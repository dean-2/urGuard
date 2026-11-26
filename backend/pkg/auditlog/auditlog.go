// Package auditlog maintains an append-only hash chain with signed checkpoints.
package auditlog

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dean-2/urGuard/backend/pkg/pqc"
	bolt "go.etcd.io/bbolt"
)

const (
	eventsBucket     = "audit_events"
	pointsBucket     = "audit_checkpoints"
	metaBucket       = "audit_meta"
	signatureContext = "urguard/v1/audit-checkpoint"
)

// The application supplies the authenticated ActorID and Action. Untrusted
// filenames, messages, and other free-form input belong in UserText.
// Field order defines the canonical JSON representation.
type Event struct {
	Action    string    `json:"action"`
	ActorID   string    `json:"actor_id"`
	Timestamp time.Time `json:"timestamp"`
	UserText  string    `json:"user_text"`
}

type Record struct {
	Seq           uint64          `json:"seq"`
	PrevHashHex   string          `json:"prev_hash_hex"`
	CanonicalBody json.RawMessage `json:"canonical_body"`
	EntryHashHex  string          `json:"entry_hash_hex"`
}

type Verification struct {
	Valid                                        bool
	CheckedEvents, CheckedCheckpoints, BrokenSeq uint64
	Reason                                       string
}

type checkpointBody struct {
	Seq          uint64    `json:"seq"`
	EntryHashHex string    `json:"entry_hash_hex"`
	Timestamp    time.Time `json:"timestamp"`
	Interval     uint32    `json:"interval"`
}

type checkpoint struct {
	checkpointBody
	Signature []byte `json:"signature"`
}

type Log struct {
	db        *bolt.DB
	authority *pqc.IdentityKeyPair
	public    []byte
	interval  uint32
}

var genesis = hex.EncodeToString(make([]byte, sha256.Size))

func seqKey(n uint64) []byte { return binary.BigEndian.AppendUint64(nil, n) }

// Open binds a history to one signing authority and checkpoint interval.
// The caller retains ownership of the database.
func Open(db *bolt.DB, authority *pqc.IdentityKeyPair, interval uint32) (*Log, error) {
	if db == nil || authority == nil || interval == 0 {
		return nil, errors.New("audit history requires database, authority and positive interval")
	}
	log := &Log{db, authority, authority.PublicBytes(), interval}
	err := db.Update(func(tx *bolt.Tx) error {
		meta, events, points := auditBuckets(tx)
		if meta != nil || events != nil || points != nil {
			if meta == nil || events == nil || points == nil {
				return errors.New("incomplete audit history")
			}
			_, err := log.readCheckpoint(meta.Get([]byte("head")))
			return err
		}
		for _, name := range []string{eventsBucket, pointsBucket, metaBucket} {
			if _, err := tx.CreateBucket([]byte(name)); err != nil {
				return err
			}
		}
		head, err := log.signCheckpoint(0, genesis)
		if err != nil {
			return err
		}
		return tx.Bucket([]byte(metaBucket)).Put([]byte("head"), head)
	})
	if err != nil {
		return nil, err
	}
	return log, nil
}

func auditBuckets(tx *bolt.Tx) (meta, events, points *bolt.Bucket) {
	return tx.Bucket([]byte(metaBucket)), tx.Bucket([]byte(eventsBucket)), tx.Bucket([]byte(pointsBucket))
}

func canonical(e Event) ([]byte, error) {
	for _, label := range []string{e.Action, e.ActorID} {
		if !utf8.ValidString(label) || strings.TrimSpace(label) == "" || len(label) > 256 {
			return nil, errors.New("invalid audit actor or action")
		}
	}
	if !utf8.ValidString(e.UserText) || len(e.UserText) > 64*1024 {
		return nil, errors.New("invalid audit user text")
	}
	if e.Timestamp.IsZero() {
		return nil, errors.New("missing audit timestamp")
	}
	e.Timestamp = e.Timestamp.UTC()
	return json.Marshal(e)
}

func entryHash(seq uint64, prev string, body []byte) (string, error) {
	p, err := hex.DecodeString(prev)
	if err != nil || len(p) != sha256.Size {
		return "", errors.New("invalid previous hash")
	}
	h := sha256.New()
	h.Write(seqKey(seq))
	h.Write(p)
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (l *Log) signCheckpoint(seq uint64, hash string) ([]byte, error) {
	body := checkpointBody{seq, hash, time.Now().UTC(), l.interval}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	sig, err := l.authority.Sign([]byte(signatureContext), data)
	if err != nil {
		return nil, err
	}
	return json.Marshal(checkpoint{body, sig})
}

// Exact representation rejects duplicate fields, ignored fields, and alternate
// encodings of a signed or hash-chained record.
func decode(raw []byte, v any) error {
	if err := json.Unmarshal(raw, v); err != nil {
		return err
	}
	encoded, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, encoded) {
		return errors.New("noncanonical audit encoding")
	}
	return nil
}

func (l *Log) readCheckpoint(raw []byte) (checkpoint, error) {
	var p checkpoint
	if err := decode(raw, &p); err != nil {
		return p, err
	}
	data, err := json.Marshal(p.checkpointBody)
	if err != nil {
		return p, err
	}
	if p.Interval != l.interval || !pqc.VerifySignature(l.public, []byte(signatureContext), data, p.Signature) {
		return p, errors.New("invalid audit checkpoint interval or signature")
	}
	return p, nil
}

func readRecord(raw []byte, seq uint64) (Record, error) {
	var r Record
	if err := decode(raw, &r); err != nil {
		return r, err
	}
	if r.Seq != seq {
		return r, errors.New("audit sequence mismatch")
	}
	var e Event
	if err := json.Unmarshal(r.CanonicalBody, &e); err != nil {
		return r, err
	}
	body, err := canonical(e)
	if err != nil {
		return r, err
	}
	if !bytes.Equal(body, r.CanonicalBody) {
		return r, errors.New("noncanonical event body")
	}
	hash, err := entryHash(seq, r.PrevHashHex, body)
	if err != nil || hash != r.EntryHashHex {
		return r, errors.New("entry hash mismatch")
	}
	return r, nil
}

// Append atomically stores the event and signed head. At each interval the
// signed head is also retained as a permanent checkpoint.
func (l *Log) Append(e Event) (Record, error) {
	row, _, err := l.AppendWithCheckpoint(e)
	return row, err
}

// AppendWithCheckpoint also returns the signed head for this exact commit.
// Independent witness storage and acknowledgement happen after the transaction.
func (l *Log) AppendWithCheckpoint(e Event) (Record, []byte, error) {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	body, err := canonical(e)
	if err != nil {
		return Record{}, nil, err
	}
	var row Record
	var signed []byte
	err = l.db.Update(func(tx *bolt.Tx) error {
		meta, events, points := auditBuckets(tx)
		if meta == nil || events == nil || points == nil {
			return errors.New("incomplete audit history")
		}
		head, err := l.readCheckpoint(meta.Get([]byte("head")))
		if err != nil {
			return err
		}
		last, v := events.Cursor().Last()
		if head.Seq != events.Sequence() || head.Seq == math.MaxUint64 {
			return errors.New("audit sequence counter mismatch or exhausted")
		}
		if head.Seq == 0 {
			if last != nil || head.EntryHashHex != genesis {
				return errors.New("invalid audit genesis")
			}
		} else {
			if !bytes.Equal(last, seqKey(head.Seq)) {
				return errors.New("audit tail missing")
			}
			tail, err := readRecord(v, head.Seq)
			if err != nil {
				return err
			}
			if tail.EntryHashHex != head.EntryHashHex {
				return errors.New("signed head mismatch")
			}
		}
		seq, err := events.NextSequence()
		if err != nil {
			return err
		}
		hash, err := entryHash(seq, head.EntryHashHex, body)
		if err != nil {
			return err
		}
		row = Record{seq, head.EntryHashHex, body, hash}
		raw, err := json.Marshal(row)
		if err != nil {
			return err
		}
		id := seqKey(seq)
		if err := events.Put(id, raw); err != nil {
			return err
		}
		signed, err = l.signCheckpoint(seq, hash)
		if err != nil {
			return err
		}
		if seq%uint64(l.interval) == 0 {
			if points.Get(id) != nil {
				return errors.New("existing audit checkpoint")
			}
			if err := points.Put(id, signed); err != nil {
				return err
			}
		}
		return meta.Put([]byte("head"), signed)
	})
	if err != nil {
		return Record{}, nil, err
	}
	return row, signed, nil
}

// List uses an inclusive start sequence. A zero limit selects 100 records.
// A page contains at most 1000 records.
func (l *Log) List(fromSeq uint64, limit uint32) ([]Record, error) {
	if limit == 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	var rows []Record
	err := l.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(eventsBucket))
		if b == nil {
			return errors.New("missing audit events")
		}
		c := b.Cursor()
		for k, v := c.Seek(seqKey(fromSeq)); k != nil && len(rows) < int(limit); k, v = c.Next() {
			if len(k) != 8 {
				return errors.New("invalid audit sequence key")
			}
			r, err := readRecord(v, binary.BigEndian.Uint64(k))
			if err != nil {
				return err
			}
			rows = append(rows, r)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// SignedHead returns the current signed checkpoint, including at genesis. It
// can be used during initial witness enrollment or to resend a pending head.
func (l *Log) SignedHead() ([]byte, error) {
	var head []byte
	err := l.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte(metaBucket))
		if meta == nil {
			return errors.New("missing audit metadata")
		}
		raw := meta.Get([]byte("head"))
		if _, err := l.readCheckpoint(raw); err != nil {
			return err
		}
		head = bytes.Clone(raw)
		return nil
	})
	return head, err
}

// VerifyChain examines one consistent snapshot. Integrity failures populate the
// report. Errors indicate that the database could not be read.
func (l *Log) VerifyChain() (Verification, error) {
	return l.verifyChain(nil)
}

// VerifyAgainstCheckpoint checks the complete chain and its history at the
// independently retained checkpoint. Missing or invalid witness data fails closed.
func (l *Log) VerifyAgainstCheckpoint(signed []byte) (Verification, error) {
	p, err := l.readCheckpoint(signed)
	if err != nil {
		return Verification{Reason: "invalid witness checkpoint: " + err.Error()}, nil
	}
	return l.verifyChain(&p)
}

func (l *Log) verifyChain(witness *checkpoint) (Verification, error) {
	var report Verification
	fail := func(seq uint64, reason string) error { report.BrokenSeq = seq; report.Reason = reason; return nil }
	err := l.db.View(func(tx *bolt.Tx) error {
		meta, events, points := auditBuckets(tx)
		if meta == nil || events == nil || points == nil {
			return fail(1, "incomplete audit history")
		}
		prev := genesis
		if witness != nil && witness.Seq == 0 && witness.EntryHashHex != prev {
			return fail(0, "witness genesis mismatch")
		}
		ec, pc := events.Cursor(), points.Cursor()
		pk, pv := pc.First()
		for k, v := ec.First(); k != nil; k, v = ec.Next() {
			seq := report.CheckedEvents + 1
			if !bytes.Equal(k, seqKey(seq)) {
				return fail(seq, "missing or misplaced event")
			}
			row, err := readRecord(v, seq)
			if err != nil {
				return fail(seq, err.Error())
			}
			if row.PrevHashHex != prev {
				return fail(seq, "previous hash mismatch")
			}
			prev = row.EntryHashHex
			if witness != nil && seq == witness.Seq && prev != witness.EntryHashHex {
				return fail(seq, "audit history conflicts with witness checkpoint")
			}
			report.CheckedEvents++
			if pk != nil && (len(pk) != 8 || bytes.Compare(pk, k) < 0) {
				return fail(seq, "unexpected checkpoint key")
			}
			if seq%uint64(l.interval) == 0 {
				if !bytes.Equal(k, pk) {
					return fail(seq, "missing checkpoint")
				}
				p, err := l.readCheckpoint(pv)
				if err != nil {
					return fail(seq, err.Error())
				}
				if p.Seq != seq || p.EntryHashHex != prev {
					return fail(seq, "checkpoint hash or sequence mismatch")
				}
				report.CheckedCheckpoints++
				pk, pv = pc.Next()
			} else if bytes.Equal(k, pk) {
				return fail(seq, "unexpected checkpoint")
			}
		}
		last := report.CheckedEvents
		head, err := l.readCheckpoint(meta.Get([]byte("head")))
		if err != nil {
			return fail(last, "invalid signed audit head")
		}
		if last < head.Seq || last < events.Sequence() {
			return fail(last+1, "missing audit tail")
		}
		if last > head.Seq {
			return fail(head.Seq+1, "events beyond signed head")
		}
		if last > events.Sequence() {
			return fail(events.Sequence()+1, "events beyond sequence counter")
		}
		if head.EntryHashHex != prev {
			return fail(last, "signed head hash mismatch")
		}
		if witness != nil && last < witness.Seq {
			return fail(last+1, fmt.Sprintf("audit rollback: local head %d precedes witnessed event %d", last, witness.Seq))
		}
		if pk != nil {
			seq := last + 1
			if len(pk) == 8 {
				seq = binary.BigEndian.Uint64(pk)
			}
			return fail(seq, fmt.Sprintf("orphan checkpoint after event %d", last))
		}
		report.Valid = true
		return nil
	})
	return report, err
}
