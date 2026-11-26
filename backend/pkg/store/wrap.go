package store

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"

	"github.com/dean-2/urGuard/backend/pkg/pqc"
	bolt "go.etcd.io/bbolt"
)

// SharedWrap encrypts one resource DEK for one device. An empty DeviceID
// identifies the authority's separate recovery copy under the recorded epoch.
type SharedWrap struct {
	ResourceID, DeviceID string
	Epoch                uint64
	KEM                  pqc.HybridCiphertext
	Nonce, Ciphertext    []byte
}

func wrapID(resource, device string) []byte { return []byte(resource + "\x00" + device) }
func (w SharedWrap) context() []byte {
	return append(append([]byte("urguard/dek-wrap/v1\x00"), number(w.Epoch)...), wrapID(w.ResourceID, w.DeviceID)...)
}
func (w SharedWrap) Open(k *pqc.HybridKEMKeyPair) ([]byte, error) {
	context := w.context()
	key, err := k.DecapsulateHybrid(w.KEM, context)
	if err != nil {
		return nil, err
	}
	defer pqc.Zeroize(key)
	return pqc.OpenAEAD(key, w.Nonce, w.Ciphertext, context)
}
func writeWrap(b *bolt.Bucket, id []byte, w SharedWrap, pub pqc.HybridPublicKey, dek []byte) error {
	context := w.context()
	kem, key, err := pqc.EncapsulateHybrid(pub, context)
	if err != nil {
		return err
	}
	defer pqc.Zeroize(key)
	w.KEM = kem
	w.Nonce, w.Ciphertext, err = pqc.SealAEAD(key, dek, context)
	if err != nil {
		return err
	}
	return putJSON(b, id, w)
}
func recoverDEK(tx *bolt.Tx, r SharedWrap) ([]byte, error) {
	k, err := epochKey(tx, r.Epoch)
	if err != nil {
		return nil, err
	}
	defer k.Zeroize()
	return r.Open(k)
}

// SaveSharedWrap grants a device access, creating an authority recovery wrap on
// the first grant. Subsequent grants must refer to the same resource key.
func (s *Store) SaveSharedWrap(resource, device string, dek []byte) error {
	if !validID(resource) || !validID(device) || len(dek) != 32 {
		return errors.New("invalid resource, device or DEK")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if bucket(tx, revoked).Get([]byte(device)) != nil {
			return ErrRevoked
		}
		d, err := readJSON[Device](bucket(tx, devices), []byte(device))
		if err != nil {
			return err
		}
		state, err := readState(tx)
		if err != nil {
			return err
		}
		rb := bucket(tx, resources)
		if rb.Get([]byte(resource)) == nil {
			k, err := epochKey(tx, state.Active)
			if err != nil {
				return err
			}
			defer k.Zeroize()
			err = writeWrap(rb, []byte(resource), SharedWrap{ResourceID: resource, Epoch: state.Active}, k.PublicKey(), dek)
			if err != nil {
				return err
			}
		} else {
			r, err := readJSON[SharedWrap](rb, []byte(resource))
			if err != nil {
				return err
			}
			key, err := recoverDEK(tx, r)
			if err != nil {
				return err
			}
			defer pqc.Zeroize(key)
			if subtle.ConstantTimeCompare(key, dek) != 1 {
				return ErrConflict
			}
		}
		b := bucket(tx, wraps)
		id := wrapID(resource, device)
		if b.Get(id) != nil {
			return nil
		}
		if err = writeWrap(b, id, SharedWrap{ResourceID: resource, DeviceID: device, Epoch: state.Active}, d.EncryptionPublic, dek); err != nil {
			return err
		}
		return changed(tx)
	})
}
func (s *Store) ListSharedWraps(resource string) ([]SharedWrap, error) {
	if !validID(resource) {
		return nil, errors.New("invalid resource")
	}
	return view(s, func(tx *bolt.Tx) ([]SharedWrap, error) {
		var out []SharedWrap
		prefix := wrapID(resource, "")
		c := bucket(tx, wraps).Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var w SharedWrap
			if err := json.Unmarshal(v, &w); err != nil {
				return nil, err
			}
			out = append(out, w)
		}
		return out, nil
	})
}

// RewrapResourcesForReplacement transfers grants only from a revoked device to
// an enrolled, active device of the same owner. The whole batch commits together.
func (s *Store) RewrapResourcesForReplacement(lost, replacement string) (int, error) {
	count := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		return rewrap(tx, lost, replacement, &count)
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}
func rewrap(tx *bolt.Tx, lost, replacement string, count *int) error {
	registry := bucket(tx, devices)
	old, err := readJSON[Device](registry, []byte(lost))
	if err != nil {
		return err
	}
	next, err := readJSON[Device](registry, []byte(replacement))
	if err != nil {
		return err
	}
	denied := bucket(tx, revoked)
	if denied.Get([]byte(lost)) == nil || old.OwnerID != next.OwnerID {
		return ErrConflict
	}
	if denied.Get([]byte(replacement)) != nil {
		return ErrRevoked
	}
	state, err := readState(tx)
	if err != nil {
		return err
	}
	b := bucket(tx, wraps)
	// Collect IDs before mutating this bucket, so cursor movement cannot skip grants.
	var ids []string
	err = b.ForEach(func(k, _ []byte) error {
		resource, device, ok := bytes.Cut(k, []byte{0})
		if ok && string(device) == lost {
			ids = append(ids, string(resource))
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, id := range ids {
		r, err := readJSON[SharedWrap](bucket(tx, resources), []byte(id))
		if err != nil {
			return err
		}
		dek, err := recoverDEK(tx, r)
		if err != nil {
			return err
		}
		err = writeWrap(b, wrapID(id, replacement), SharedWrap{ResourceID: id, DeviceID: replacement, Epoch: state.Active}, next.EncryptionPublic, dek)
		pqc.Zeroize(dek)
		if err != nil {
			return err
		}
		if err = b.Delete(wrapID(id, lost)); err != nil {
			return err
		}
	}
	*count = len(ids)
	if *count == 0 {
		return nil
	}
	return changed(tx)
}

func (s *Store) ReplaceDevice(lost string, replacement Device, hooks ...CommitHook) (int, error) {
	var count int
	err := s.update(hooks, func(tx *bolt.Tx) error {
		if err := upsertDevice(tx, replacement); err != nil {
			return err
		}
		var r Revocation
		if err := revokeDevice(tx, lost, "device replacement", &r); err != nil {
			return err
		}
		return rewrap(tx, lost, replacement.ID, &count)
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}
