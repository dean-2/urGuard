package store

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/dean-2/urGuard/backend/pkg/pqc"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/argon2"
)

var ErrBackupCorrupted = errors.New("ERR_BACKUP_CORRUPTED")

const backupContext = "urguard/authority-backup/v1"

// Fixed-width big-endian fields are both the AEAD associated data and the
// signed header. Version 1 fixes the KDF parameters and field sizes.
type backupHeader struct {
	Format             [8]byte
	BackupID           [16]byte
	CreatedAt          int64
	KeyEpoch, Revision uint64
	Salt               [16]byte
	Nonce              [12]byte
	Manifest           [32]byte
}

var formatV1 = [8]byte{'U', 'R', 'G', 'B', 'A', 'K', 0, 1}

type entry struct{ Key, Value []byte }
type bucketImage struct {
	Sequence uint64
	Entries  []entry
}
type snapshot map[string]bucketImage

func authority(tx *bolt.Tx) (*pqc.IdentityKeyPair, error) {
	return pqc.ParseIdentityKeyPair(bucket(tx, meta).Get([]byte("seed")))
}
func (s *Store) AuthorityPublicKey() ([]byte, error) {
	return view(s, func(tx *bolt.Tx) ([]byte, error) {
		k, err := authority(tx)
		if err != nil {
			return nil, err
		}
		return k.PublicBytes(), nil
	})
}
func backupKey(passphrase []byte, salt []byte) ([]byte, error) {
	master := argon2.IDKey(passphrase, salt, 3, 64*1024, 4, 32)
	defer pqc.Zeroize(master)
	return pqc.DeriveSubkey(master, "authority-backup/v1")
}

func (s *Store) ExportBackup(passphrase []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("backup passphrase required")
	}
	h := backupHeader{Format: formatV1, CreatedAt: time.Now().UTC().UnixNano()}
	var signer *pqc.IdentityKeyPair
	plain, err := view(s, func(tx *bolt.Tx) ([]byte, error) {
		state, err := readState(tx)
		if err != nil {
			return nil, err
		}
		if state.Prepared != 0 {
			return nil, ErrConflict
		}
		signer, err = authority(tx)
		if err != nil {
			return nil, err
		}
		h.KeyEpoch, h.Revision = state.Active, bucket(tx, meta).Sequence()
		image := snapshot{}
		for _, name := range buckets {
			b := bucket(tx, name)
			im := bucketImage{Sequence: b.Sequence()}
			err = b.ForEach(func(k, v []byte) error { im.Entries = append(im.Entries, entry{k, v}); return nil })
			if err != nil {
				return nil, err
			}
			image[name] = im
		}
		// Marshal while the read transaction still owns the mapped byte slices.
		return json.Marshal(image)
	})
	if err != nil {
		return nil, err
	}
	defer pqc.Zeroize(plain)
	h.Manifest = sha256.Sum256(plain)
	for _, field := range [][]byte{h.BackupID[:], h.Salt[:], h.Nonce[:]} {
		if _, err = rand.Read(field); err != nil {
			return nil, err
		}
	}
	header, err := binary.Append(nil, binary.BigEndian, h)
	if err != nil {
		return nil, err
	}
	key, err := backupKey(passphrase, h.Salt[:])
	if err != nil {
		return nil, err
	}
	defer pqc.Zeroize(key)
	ct, err := pqc.SealAEADWithNonce(key, h.Nonce[:], plain, header)
	if err != nil {
		return nil, err
	}
	envelope := append(header, ct...)
	sig, err := signer.Sign([]byte(backupContext), envelope)
	if err != nil {
		return nil, err
	}
	return append(envelope, sig...), nil
}

func (s *Store) RestoreBackup(bundle, passphrase []byte) error {
	pub, err := s.AuthorityPublicKey()
	if err != nil {
		return err
	}
	return s.restore(bundle, passphrase, pub, false)
}

// RestoreIntoFreshStore supports disaster recovery on a new database. Supply
// the authority public key saved independently before the loss. A fresh DB has
// no independent record of the most recent revision. Perform recovery before
// opening an audit log under the new database's temporary authority.
func (s *Store) RestoreIntoFreshStore(bundle, passphrase, trustedPublic []byte) error {
	return s.restore(bundle, passphrase, trustedPublic, true)
}

func (s *Store) restore(bundle, passphrase, pub []byte, fresh bool) error {
	var h backupHeader
	size := binary.Size(h)
	if len(passphrase) == 0 || len(bundle) < size+16+mldsa65.SignatureSize {
		return ErrBackupCorrupted
	}
	signed := bundle[:len(bundle)-mldsa65.SignatureSize]
	if _, err := binary.Decode(signed[:size], binary.BigEndian, &h); err != nil || h.Format != formatV1 {
		return ErrBackupCorrupted
	}
	if !pqc.VerifySignature(pub, []byte(backupContext), signed, bundle[len(signed):]) {
		return ErrBackupCorrupted
	}
	key, err := backupKey(passphrase, h.Salt[:])
	if err != nil {
		return err
	}
	defer pqc.Zeroize(key)
	plain, err := pqc.OpenAEAD(key, h.Nonce[:], signed[size:], signed[:size])
	if err != nil {
		return ErrBackupCorrupted
	}
	defer pqc.Zeroize(plain)
	if sha256.Sum256(plain) != h.Manifest {
		return ErrBackupCorrupted
	}
	var image snapshot
	if err = json.Unmarshal(plain, &image); err != nil || len(image) != len(buckets) || image[meta].Sequence != h.Revision {
		return ErrBackupCorrupted
	}
	// Validate against live state inside the writer transaction, after the KDF.
	if fresh {
		s.authorityMu.Lock()
		defer s.authorityMu.Unlock()
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		revision := bucket(tx, meta).Sequence()
		local, err := authority(tx)
		if err != nil {
			return err
		}
		if fresh {
			// An initialized audit log, including an open, empty log, holds a
			// signer bound to the local authority. Preserve that binding.
			if revision != 0 || (bucket(tx, "audit_meta") != nil && !bytes.Equal(local.PublicBytes(), pub)) {
				return ErrConflict
			}
		} else if !bytes.Equal(local.PublicBytes(), pub) || revision > h.Revision {
			return ErrBackupCorrupted
		}
		marker := slices.Clone(bucket(tx, lineage).Get(number(revision)))
		for _, name := range buckets {
			im, ok := image[name]
			if !ok {
				return ErrBackupCorrupted
			}
			if err = tx.DeleteBucket([]byte(name)); err != nil {
				return err
			}
			b, err := tx.CreateBucket([]byte(name))
			if err != nil {
				return err
			}
			for _, row := range im.Entries {
				if err = b.Put(row.Key, row.Value); err != nil {
					return ErrBackupCorrupted
				}
			}
			if err = b.SetSequence(im.Sequence); err != nil {
				return err
			}
		}
		// Any failed invariant rolls the entire transaction back.
		restored, err := authority(tx)
		if err != nil || !bytes.Equal(restored.PublicBytes(), pub) {
			return ErrBackupCorrupted
		}
		state, err := readState(tx)
		if err != nil || state.Active == 0 || state.Active != h.KeyEpoch || state.Prepared != 0 {
			return ErrBackupCorrupted
		}
		if !fresh && revision > 0 && (len(marker) != 16 || !bytes.Equal(marker, bucket(tx, lineage).Get(number(revision)))) {
			return ErrBackupCorrupted
		}
		return nil
	})
}
