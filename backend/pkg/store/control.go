package store

import (
	bolt "go.etcd.io/bbolt"
	"time"
)

// CommitHook lets a control-plane operation commit its audit event atomically.
type CommitHook func(*bolt.Tx) error

func (s *Store) update(hooks []CommitHook, mutate func(*bolt.Tx) error) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := mutate(tx); err != nil {
			return err
		}
		for _, hook := range hooks {
			if err := hook(tx); err != nil {
				return err
			}
		}
		return nil
	})
}

// SignControlUpdate only signs the v1 control stream domain.
func (s *Store) SignControlUpdate(body []byte) ([]byte, error) {
	return view(s, func(tx *bolt.Tx) ([]byte, error) {
		id, err := authority(tx)
		if err != nil {
			return nil, err
		}
		return id.Sign([]byte("urguard/control-update/v1"), body)
	})
}

type NodeAck struct {
	Node               string
	CRL, Epoch         uint64
	Enforced, Received time.Time
}

func (s *Store) RecordAck(a NodeAck) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("control_acks"))
		if err != nil {
			return err
		}
		if !validID(a.Node) {
			return ErrConflict
		}
		node, err := b.CreateBucketIfNotExists([]byte(a.Node))
		if err != nil {
			return err
		}
		// Each cumulative acknowledgement covers missed updates, including after restarts.
		if a.CRL > bucket(tx, history).Sequence() {
			return ErrConflict
		}
		for n := node.Sequence() + 1; n <= a.CRL; n++ {
			if err := putJSON(node, number(n), a); err != nil {
				return err
			}
		}
		if a.CRL >= node.Sequence() {
			if err = node.SetSequence(a.CRL); err != nil {
				return err
			}
			return putJSON(node, []byte("latest"), a)
		}
		return nil
	})
}
func (s *Store) AckAt(node string, seq uint64) (NodeAck, error) {
	return view(s, func(tx *bolt.Tx) (NodeAck, error) {
		b := tx.Bucket([]byte("control_acks"))
		if b == nil || b.Bucket([]byte(node)) == nil {
			return NodeAck{}, ErrNotFound
		}
		return readJSON[NodeAck](b.Bucket([]byte(node)), number(seq))
	})
}
