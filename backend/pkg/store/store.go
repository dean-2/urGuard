// Package store persists the authority's key lifecycle in durable bbolt transactions.
package store

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/dean-2/urGuard/backend/pkg/pqc"
	bolt "go.etcd.io/bbolt"
)

const (
	meta      = "authority"
	epochs    = "epoch_keys"
	devices   = "devices"
	revoked   = "revoked_devices"
	history   = "revocations"
	wraps     = "device_wraps"
	resources = "recovery_wraps"
	lineage   = "store_revisions"
)

var buckets = []string{meta, epochs, devices, revoked, history, wraps, resources, lineage}
var (
	ErrNotFound = errors.New("store record not found")
	ErrRevoked  = errors.New("device revoked")
	ErrConflict = errors.New("store state conflict")
)

type Store struct {
	db *bolt.DB
	// OpenAuditLog reads the authority and opens its log in separate transactions.
	// A fresh-store restore can replace the authority between those operations.
	authorityMu sync.Mutex
}
type EpochState struct {
	Active, Prepared, Previous uint64
	CommittedAt, CutoffAt      time.Time
}
type Device struct {
	ID, OwnerID, KeyID string
	SigningPublic      []byte
	EncryptionPublic   pqc.HybridPublicKey
}
type Revocation struct {
	CRLEpoch                uint64
	DeviceID, KeyID, Reason string
	IssuedAt                time.Time
}

func bucket(tx *bolt.Tx, name string) *bolt.Bucket { return tx.Bucket([]byte(name)) }
func number(n uint64) []byte                       { return binary.BigEndian.AppendUint64(nil, n) }
func putJSON(b *bolt.Bucket, key []byte, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.Put(key, raw)
}
func readJSON[T any](b *bolt.Bucket, key []byte) (T, error) {
	var v T
	raw := b.Get(key)
	if raw == nil {
		return v, ErrNotFound
	}
	err := json.Unmarshal(raw, &v)
	return v, err
}
func readState(tx *bolt.Tx) (EpochState, error) {
	return readJSON[EpochState](bucket(tx, meta), []byte("state"))
}
func saveState(tx *bolt.Tx, s EpochState) error { return putJSON(bucket(tx, meta), []byte("state"), s) }

// Open initializes only an empty database and reconciles any interrupted prepare.
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	err = db.Update(func(tx *bolt.Tx) error {
		if bucket(tx, meta) != nil {
			for _, name := range buckets {
				if bucket(tx, name) == nil {
					return fmt.Errorf("missing store bucket %s", name)
				}
			}
			return recoverPrepared(tx)
		}
		if k, _ := tx.Cursor().First(); k != nil {
			return errors.New("unrecognized database")
		}
		for _, name := range buckets {
			if _, err := tx.CreateBucket([]byte(name)); err != nil {
				return err
			}
		}
		identity, err := pqc.GenerateIdentityKeyPair()
		if err != nil {
			return err
		}
		if err = bucket(tx, meta).Put([]byte("seed"), identity.PrivateBytes()); err != nil {
			return err
		}
		if err = createEpoch(tx, 1); err != nil {
			return err
		}
		return saveState(tx, EpochState{Active: 1})
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) Close() error { return s.db.Close() }

func view[T any](s *Store, fn func(*bolt.Tx) (T, error)) (T, error) {
	var out T
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		out, err = fn(tx)
		return err
	})
	return out, err
}

// The authority bucket sequence is the durable anti-rollback revision.
func changed(tx *bolt.Tx) error {
	revision, err := bucket(tx, meta).NextSequence()
	if err != nil {
		return err
	}
	var marker [16]byte
	if _, err = rand.Read(marker[:]); err != nil {
		return err
	}
	return bucket(tx, lineage).Put(number(revision), marker[:])
}
func recoverPrepared(tx *bolt.Tx) error {
	state, err := readState(tx)
	if err != nil {
		return err
	}
	if state.Prepared == 0 {
		return nil
	}
	if err = bucket(tx, epochs).Delete(number(state.Prepared)); err != nil {
		return err
	}
	state.Prepared = 0
	if err = saveState(tx, state); err != nil {
		return err
	}
	return changed(tx)
}
func (s *Store) Recover() error                  { return s.db.Update(recoverPrepared) }
func (s *Store) EpochState() (EpochState, error) { return view(s, readState) }

func createEpoch(tx *bolt.Tx, epoch uint64) error {
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	k, err := mlkem.GenerateKey768()
	if err != nil {
		return err
	}
	return bucket(tx, epochs).Put(number(epoch), slices.Concat(x.Bytes(), k.Bytes()))
}

// EpochKey restores committed key material. The caller owns and zeroizes the returned key.
func (s *Store) EpochKey(epoch uint64) (*pqc.HybridKEMKeyPair, error) {
	return view(s, func(tx *bolt.Tx) (*pqc.HybridKEMKeyPair, error) {
		state, err := readState(tx)
		if err != nil {
			return nil, err
		}
		if epoch > state.Active {
			return nil, ErrNotFound
		}
		return epochKey(tx, epoch)
	})
}
func epochKey(tx *bolt.Tx, epoch uint64) (*pqc.HybridKEMKeyPair, error) {
	raw := bucket(tx, epochs).Get(number(epoch))
	if raw == nil {
		return nil, ErrNotFound
	}
	if len(raw) != 32+mlkem.SeedSize {
		return nil, errors.New("invalid epoch private key")
	}
	return pqc.ParseHybridKEMKeyPair(raw[:32], raw[32:])
}
func (s *Store) BeginPrepareRotation(expected uint64) (EpochState, error) {
	var state EpochState
	err := s.db.Update(func(tx *bolt.Tx) error {
		var err error
		state, err = readState(tx)
		if err != nil {
			return err
		}
		if expected != state.Active || expected == math.MaxUint64 {
			return ErrConflict
		}
		if state.Prepared != 0 {
			return nil
		}
		state.Prepared = expected + 1
		if err = createEpoch(tx, state.Prepared); err != nil {
			return err
		}
		if err = saveState(tx, state); err != nil {
			return err
		}
		return changed(tx)
	})
	if err != nil {
		return EpochState{}, err
	}
	return state, nil
}
func (s *Store) CommitPreparedRotation(prepared uint64, grace time.Duration) (EpochState, error) {
	var state EpochState
	err := s.db.Update(func(tx *bolt.Tx) error {
		var err error
		state, err = readState(tx)
		if err != nil {
			return err
		}
		if grace < 0 || prepared < 2 {
			return ErrConflict
		}
		if state.Active == prepared {
			return nil
		}
		if state.Prepared != prepared {
			return ErrConflict
		}
		state.Previous, state.Active, state.Prepared = state.Active, prepared, 0
		state.CommittedAt = time.Now().UTC()
		state.CutoffAt = state.CommittedAt.Add(grace)
		if err = saveState(tx, state); err != nil {
			return err
		}
		return changed(tx)
	})
	if err != nil {
		return EpochState{}, err
	}
	return state, nil
}

func validID(id string) bool {
	return utf8.ValidString(id) && strings.TrimSpace(id) != "" && !strings.ContainsRune(id, 0)
}
func (s *Store) UpsertDevice(d Device) error {
	if !validID(d.ID) || !validID(d.OwnerID) || !validID(d.KeyID) || len(d.SigningPublic) != mldsa65.PublicKeySize {
		return errors.New("invalid device identity")
	}
	// Encapsulation also rejects low-order X25519 public keys.
	_, probe, err := pqc.EncapsulateHybrid(d.EncryptionPublic, nil)
	if err != nil {
		return err
	}
	pqc.Zeroize(probe)
	return s.db.Update(func(tx *bolt.Tx) error {
		id := []byte(d.ID)
		if bucket(tx, revoked).Get(id) != nil {
			return ErrRevoked
		}
		b := bucket(tx, devices)
		if old := b.Get(id); old != nil {
			data, err := json.Marshal(d)
			if err != nil {
				return err
			}
			if bytes.Equal(old, data) {
				return nil
			}
			return ErrConflict
		}
		err := b.ForEach(func(_, raw []byte) error {
			var other Device
			if err := json.Unmarshal(raw, &other); err != nil {
				return err
			}
			if other.KeyID == d.KeyID || bytes.Equal(other.SigningPublic, d.SigningPublic) ||
				(bytes.Equal(other.EncryptionPublic.X25519, d.EncryptionPublic.X25519) && bytes.Equal(other.EncryptionPublic.MLKEM768, d.EncryptionPublic.MLKEM768)) {
				return ErrConflict
			}
			return nil
		})
		if err != nil {
			return err
		}
		if err = putJSON(b, id, d); err != nil {
			return err
		}
		return changed(tx)
	})
}
func (s *Store) GetDevice(id string) (Device, error) {
	return view(s, func(tx *bolt.Tx) (Device, error) { return readJSON[Device](bucket(tx, devices), []byte(id)) })
}
func (s *Store) ListDevices() ([]Device, error) {
	return view(s, func(tx *bolt.Tx) ([]Device, error) {
		var out []Device
		err := bucket(tx, devices).ForEach(func(_, raw []byte) error {
			var d Device
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			out = append(out, d)
			return nil
		})
		return out, err
	})
}
func (s *Store) IsDeviceRevoked(id string) (bool, error) {
	return view(s, func(tx *bolt.Tx) (bool, error) { return bucket(tx, revoked).Get([]byte(id)) != nil, nil })
}
func (s *Store) RevokeDevice(id, reason string) (Revocation, error) {
	var r Revocation
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := bucket(tx, revoked)
		log := bucket(tx, history)
		if seq := b.Get([]byte(id)); seq != nil {
			var err error
			r, err = readJSON[Revocation](log, seq)
			return err
		}
		d, err := readJSON[Device](bucket(tx, devices), []byte(id))
		if err != nil {
			return err
		}
		seq, err := log.NextSequence()
		if err != nil {
			return err
		}
		r = Revocation{seq, id, d.KeyID, reason, time.Now().UTC()}
		if err = putJSON(log, number(seq), r); err != nil {
			return err
		}
		if err = b.Put([]byte(id), number(seq)); err != nil {
			return err
		}
		return changed(tx)
	})
	if err != nil {
		return Revocation{}, err
	}
	return r, nil
}
func (s *Store) ListRevocations(after uint64) ([]Revocation, error) {
	return view(s, func(tx *bolt.Tx) ([]Revocation, error) {
		var out []Revocation
		if after == math.MaxUint64 {
			return out, nil
		}
		c := bucket(tx, history).Cursor()
		for k, v := c.Seek(number(after + 1)); k != nil; k, v = c.Next() {
			var r Revocation
			if err := json.Unmarshal(v, &r); err != nil {
				return nil, err
			}
			out = append(out, r)
		}
		return out, nil
	})
}
