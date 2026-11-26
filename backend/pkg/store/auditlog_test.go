package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dean-2/urGuard/backend/pkg/auditlog"
	bolt "go.etcd.io/bbolt"
)

func TestWitnessedStartupAfterDatabaseRollback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authority.db")
	s := openTest(t, path)
	log, err := s.OpenAuditLog(25)
	check(t, err)
	genesis, err := log.SignedHead()
	check(t, err)
	_, err = s.OpenWitnessedAuditLog(25, genesis)
	check(t, err)
	oldPath := filepath.Join(dir, "at-40.db")
	witnessPath := filepath.Join(dir, "relay-head")
	event := auditlog.Event{ActorID: "node", Action: "UPLOAD"}
	for i := 1; i <= 60; i++ {
		_, signed, err := log.AppendWithCheckpoint(event)
		check(t, err)
		switch i {
		case 40:
			check(t, s.db.View(func(tx *bolt.Tx) error { return tx.CopyFile(oldPath, 0600) }))
		case 50:
			check(t, os.WriteFile(witnessPath, signed, 0600))
		}
	}
	witness, err := os.ReadFile(witnessPath)
	check(t, err)
	_, err = s.OpenWitnessedAuditLog(25, witness) // 60 includes the original 50.
	check(t, err)
	tampered := bytes.Clone(witness)
	tampered[len(tampered)-1] ^= 1
	for _, invalid := range [][]byte{nil, tampered} {
		if writable, err := s.OpenWitnessedAuditLog(25, invalid); err == nil || writable != nil {
			t.Fatal("accepted invalid witness")
		}
	}
	check(t, s.Close())
	old := openTest(t, oldPath)
	if writable, err := old.OpenWitnessedAuditLog(25, witness); err == nil || writable != nil {
		t.Fatal("offered writable handle after rollback")
	}
	// Simulate a fork that also has valid signatures from the same authority.
	fork, err := old.OpenAuditLog(25)
	check(t, err)
	report, err := fork.VerifyAgainstCheckpoint(witness)
	check(t, err)
	if report.Valid || report.BrokenSeq != 41 {
		t.Fatalf("rollback report: %+v", report)
	}
	event.Action = "DOWNLOAD"
	for i := 41; i <= 60; i++ {
		_, err = fork.Append(event)
		check(t, err)
		if i >= 50 {
			report, err = fork.VerifyAgainstCheckpoint(witness)
			check(t, err)
			if report.Valid || report.BrokenSeq != 50 {
				t.Fatalf("fork at length %d: %+v", i, report)
			}
		}
	}
}

func TestAuditAuthoritySurvivesKeystoreRestore(t *testing.T) {
	dir := t.TempDir()
	s := openTest(t, filepath.Join(dir, "authority.db"))
	passphrase := []byte("store integration test")
	beforeEvents, err := s.ExportBackup(passphrase)
	check(t, err)

	log, err := s.OpenAuditLog(1)
	check(t, err)
	// Even an unused log already holds the authority's signer. A recovery
	// against an unrelated authority would invalidate that link.
	other := openTest(t, filepath.Join(dir, "other.db"))
	foreignBackup, err := other.ExportBackup(passphrase)
	check(t, err)
	foreignPublic, err := other.AuthorityPublicKey()
	check(t, err)
	if err := s.RestoreIntoFreshStore(foreignBackup, passphrase, foreignPublic); !errors.Is(err, ErrConflict) {
		t.Fatalf("restore over an initialized log returned %v", err)
	}

	_, err = log.Append(auditlog.Event{ActorID: "operator", Action: "KEY_ROTATION", Timestamp: time.Now().UTC()})
	check(t, err)
	check(t, s.RestoreBackup(beforeEvents, passphrase))
	reopened, err := s.OpenAuditLog(1)
	check(t, err)
	report, err := reopened.VerifyChain()
	check(t, err)
	if !report.Valid || report.CheckedEvents != 1 || report.CheckedCheckpoints != 1 {
		t.Fatalf("verification after keystore restore: %+v", report)
	}
}
