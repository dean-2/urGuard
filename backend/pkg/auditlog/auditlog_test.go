package auditlog_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/dean-2/urGuard/backend/pkg/auditlog"
	"github.com/dean-2/urGuard/backend/pkg/pqc"
	bolt "go.etcd.io/bbolt"
)

func success(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func openDB(t *testing.T, path string) *bolt.DB {
	t.Helper()
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	success(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func newLog(t *testing.T) (*auditlog.Log, *bolt.DB, *pqc.IdentityKeyPair) {
	t.Helper()
	id, err := pqc.GenerateIdentityKeyPair()
	success(t, err)
	db := openDB(t, filepath.Join(t.TempDir(), "audit.bbolt"))
	log, err := auditlog.Open(db, id, 2)
	success(t, err)
	return log, db, id
}

func add(t *testing.T, log *auditlog.Log, text string) auditlog.Record {
	t.Helper()
	row, err := log.Append(auditlog.Event{ActorID: "alice", Action: "UPLOAD", UserText: text})
	success(t, err)
	return row
}

func verify(t *testing.T, log *auditlog.Log, count uint64) {
	t.Helper()
	result, err := log.VerifyChain()
	success(t, err)
	if !result.Valid || result.CheckedEvents != count || result.CheckedCheckpoints != count/2 {
		t.Fatalf("unexpected verification: %+v", result)
	}
}

func TestChainAndInjectionIsolation(t *testing.T) {
	log, _, _ := newLog(t)
	verify(t, log, 0)
	text := "folder\\file.txt\n{\"actor_id\":\"admin\",\"action\":\"GRANT_ROOT\"}"
	first := add(t, log, text)
	if !json.Valid(first.CanonicalBody) || bytes.ContainsRune(first.CanonicalBody, '\n') {
		t.Fatalf("user text broke JSON framing: %s", first.CanonicalBody)
	}
	var body struct {
		ActorID  string `json:"actor_id"`
		Action   string `json:"action"`
		UserText string `json:"user_text"`
	}
	success(t, json.Unmarshal(first.CanonicalBody, &body))
	if body.ActorID != "alice" || body.Action != "UPLOAD" || body.UserText != text {
		t.Fatalf("event fields changed: %+v", body)
	}
	verify(t, log, 1)
	for i := 2; i <= 5; i++ {
		add(t, log, fmt.Sprintf("file-%d", i))
	}
	verify(t, log, 5)
	rows, err := log.List(0, 0)
	success(t, err)
	if len(rows) != 5 {
		t.Fatalf("listed %d rows", len(rows))
	}
	for i, row := range rows {
		if row.Seq != uint64(i+1) {
			t.Fatalf("row %d has seq %d", i, row.Seq)
		}
		prev, err := hex.DecodeString(row.PrevHashHex)
		success(t, err)
		if i > 0 && row.PrevHashHex != rows[i-1].EntryHashHex {
			t.Fatalf("broken link at %d", row.Seq)
		}
		h := sha256.New()
		h.Write(binary.BigEndian.AppendUint64(nil, row.Seq))
		h.Write(prev)
		h.Write(row.CanonicalBody)
		if hex.EncodeToString(h.Sum(nil)) != row.EntryHashHex {
			t.Fatalf("entry hash mismatch at %d", row.Seq)
		}
	}
	page, err := log.List(3, 2)
	success(t, err)
	if len(page) != 2 || page[0].Seq != 3 || page[1].Seq != 4 {
		t.Fatalf("unexpected page: %+v", page)
	}
	end, err := log.List(6, 2)
	success(t, err)
	if len(end) != 0 {
		t.Fatalf("unexpected trailing page: %+v", end)
	}
}

func TestConcurrentAppendAndReopen(t *testing.T) {
	log, db, identity := newLog(t)
	const writers = 16
	errs := make(chan error, writers)
	for i := range writers {
		go func() {
			_, err := log.Append(auditlog.Event{ActorID: "node", Action: "SYNC", UserText: fmt.Sprint(i)})
			errs <- err
		}()
	}
	for range writers {
		success(t, <-errs)
	}
	verify(t, log, writers)
	path := db.Path()
	success(t, db.Close())
	reopened := openDB(t, path)
	other, err := pqc.GenerateIdentityKeyPair()
	success(t, err)
	if _, err := auditlog.Open(reopened, other, 2); err == nil {
		t.Fatal("accepted different signing authority")
	}
	if _, err := auditlog.Open(reopened, identity, 3); err == nil {
		t.Fatal("accepted different checkpoint interval")
	}
	log, err = auditlog.Open(reopened, identity, 2)
	success(t, err)
	verify(t, log, writers)
	if next := add(t, log, "next"); next.Seq != writers+1 {
		t.Fatalf("resumed at sequence %d", next.Seq)
	}
}

func TestRejectedEventPreservesSequence(t *testing.T) {
	log, _, _ := newLog(t)
	invalidUTF8 := string([]byte{0xff})
	for _, event := range []auditlog.Event{
		{ActorID: "", Action: "WRITE"},
		{ActorID: "alice", Action: ""},
		{ActorID: invalidUTF8, Action: "WRITE"},
		{ActorID: "alice", Action: invalidUTF8},
		{ActorID: "alice", Action: "WRITE", UserText: invalidUTF8},
	} {
		if _, err := log.Append(event); err == nil {
			t.Fatalf("accepted invalid event %+v", event)
		}
	}
	verify(t, log, 0)
	if row := add(t, log, "valid"); row.Seq != 1 {
		t.Fatalf("next sequence = %d", row.Seq)
	}
}

func TestWitnessBetweenPeriodicCheckpoints(t *testing.T) {
	log, _, _ := newLog(t) // Permanent checkpoint every two events.
	_, witness, err := log.AppendWithCheckpoint(auditlog.Event{ActorID: "alice", Action: "UPLOAD"})
	success(t, err)
	current, err := log.SignedHead()
	success(t, err)
	if !bytes.Equal(witness, current) {
		t.Fatal("append returned a different signed head")
	}
	add(t, log, "second event")
	report, err := log.VerifyAgainstCheckpoint(witness)
	success(t, err)
	if !report.Valid || report.CheckedEvents != 2 {
		t.Fatalf("failed to verify the first event's checkpoint: %+v", report)
	}
	other, _, _ := newLog(t)
	foreign, err := other.SignedHead()
	success(t, err)
	report, err = log.VerifyAgainstCheckpoint(foreign)
	success(t, err)
	if report.Valid {
		t.Fatal("accepted a witness checkpoint signed by another authority")
	}
}

func TestVerifyPinpointsDamage(t *testing.T) {
	key := func(n uint64) []byte { return binary.BigEndian.AppendUint64(nil, n) }
	tests := []struct {
		name, bucket string
		broken       uint64
		change       func(*bolt.Bucket) error
	}{
		{"edited event", "audit_events", 3, func(b *bolt.Bucket) error {
			var row auditlog.Record
			if err := json.Unmarshal(b.Get(key(3)), &row); err != nil {
				return err
			}
			row.CanonicalBody = bytes.Replace(row.CanonicalBody, []byte("original"), []byte("changed"), 1)
			data, err := json.Marshal(row)
			if err != nil {
				return err
			}
			return b.Put(key(3), data)
		}},
		{"missing event", "audit_events", 3, func(b *bolt.Bucket) error { return b.Delete(key(3)) }},
		{"missing final event", "audit_events", 5, func(b *bolt.Bucket) error { return b.Delete(key(5)) }},
		{"inserted event", "audit_events", 6, func(b *bolt.Bucket) error {
			return b.Put(key(6), bytes.Clone(b.Get(key(5))))
		}},
		{"rehashed final event", "audit_events", 5, func(b *bolt.Bucket) error {
			var row auditlog.Record
			if err := json.Unmarshal(b.Get(key(5)), &row); err != nil {
				return err
			}
			row.CanonicalBody = bytes.Replace(row.CanonicalBody, []byte("original"), []byte("changed"), 1)
			prev, err := hex.DecodeString(row.PrevHashHex)
			if err != nil {
				return err
			}
			h := sha256.New()
			h.Write(key(row.Seq))
			h.Write(prev)
			h.Write(row.CanonicalBody)
			row.EntryHashHex = hex.EncodeToString(h.Sum(nil))
			raw, err := json.Marshal(row)
			if err != nil {
				return err
			}
			return b.Put(key(5), raw)
		}},
		{"swapped events", "audit_events", 2, func(b *bolt.Bucket) error {
			second, third := bytes.Clone(b.Get(key(2))), bytes.Clone(b.Get(key(3)))
			if err := b.Put(key(2), third); err != nil {
				return err
			}
			return b.Put(key(3), second)
		}},
		{"missing checkpoint", "audit_checkpoints", 2, func(b *bolt.Bucket) error { return b.Delete(key(2)) }},
		{"extra checkpoint", "audit_checkpoints", 5, func(b *bolt.Bucket) error {
			return b.Put(key(5), bytes.Clone(b.Get(key(4))))
		}},
		{"bad checkpoint signature", "audit_checkpoints", 4, func(b *bolt.Bucket) error {
			raw := b.Get(key(4))
			var cp map[string]json.RawMessage
			if err := json.Unmarshal(raw, &cp); err != nil {
				return err
			}
			var sig []byte
			if err := json.Unmarshal(cp["signature"], &sig); err != nil {
				return err
			}
			if len(sig) == 0 {
				return fmt.Errorf("empty signature")
			}
			sig[0] ^= 1
			bad, err := json.Marshal(sig)
			if err != nil {
				return err
			}
			return b.Put(key(4), bytes.Replace(raw, cp["signature"], bad, 1))
		}},
		{"different signed timestamp", "audit_checkpoints", 4, func(b *bolt.Bucket) error {
			raw := b.Get(key(4))
			var cp struct {
				Timestamp time.Time `json:"timestamp"`
			}
			if err := json.Unmarshal(raw, &cp); err != nil {
				return err
			}
			old, err := cp.Timestamp.MarshalJSON()
			if err != nil {
				return err
			}
			later, err := cp.Timestamp.Add(time.Second).MarshalJSON()
			if err != nil {
				return err
			}
			return b.Put(key(4), bytes.Replace(raw, old, later, 1))
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			log, db, _ := newLog(t)
			for range 5 {
				add(t, log, "original")
			}
			success(t, db.Update(func(tx *bolt.Tx) error { return tc.change(tx.Bucket([]byte(tc.bucket))) }))
			result, err := log.VerifyChain()
			success(t, err)
			if result.Valid || result.BrokenSeq != tc.broken || result.Reason == "" {
				t.Fatalf("unexpected verification: %+v", result)
			}
		})
	}
}
