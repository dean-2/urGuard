package auditlog

import (
	"bytes"
	"encoding/binary"
	"errors"
	bolt "go.etcd.io/bbolt"
)

// WitnessCheckpoint authenticates a transportable head against an independent pin.
func WitnessCheckpoint(raw, public []byte, interval uint32) (uint64, string, error) {
	p, err := (&Log{public: public, interval: interval}).readCheckpoint(raw)
	if err == nil && p.Seq == 0 && p.EntryHashHex != genesis {
		err = errors.New("invalid genesis")
	}
	return p.Seq, p.EntryHashHex, err
}
func CheckWitnessLink(seq uint64, prev string, body []byte, next string) bool {
	hash, err := entryHash(seq, prev, body)
	return err == nil && hash == next
}
func (l *Log) WitnessEnabled() (bool, error) {
	var enabled bool
	err := l.db.View(func(tx *bolt.Tx) error { enabled = tx.Bucket([]byte("audit_witness_pending")) != nil; return nil })
	return enabled, err
}
func (l *Log) EnableWitness() error {
	return l.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("audit_witness_pending"))
		return err
	})
}
func (l *Log) NextPending() (seq uint64, head, body []byte, err error) {
	err = l.db.View(func(tx *bolt.Tx) error {
		q := tx.Bucket([]byte("audit_witness_pending"))
		if q == nil {
			return errors.New("witness queue missing")
		}
		k, v := q.Cursor().First()
		if k == nil {
			return nil
		}
		if len(k) != 8 {
			return errors.New("invalid pending sequence")
		}
		seq = binary.BigEndian.Uint64(k)
		r, err := readRecord(tx.Bucket([]byte(eventsBucket)).Get(k), seq)
		if err != nil {
			return err
		}
		head, body = bytes.Clone(v), r.CanonicalBody
		return nil
	})
	return
}
func (l *Log) ConfirmPending(seq uint64) error {
	return l.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("audit_witness_pending")).Delete(seqKey(seq)) })
}
