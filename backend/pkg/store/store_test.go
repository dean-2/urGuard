package store

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/dean-2/urGuard/backend/pkg/pqc"
)

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func openTest(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(path)
	check(t, err)
	t.Cleanup(func() { s.Close() })
	return s
}
func enroll(t *testing.T, s *Store, id, owner string) (Device, *pqc.HybridKEMKeyPair) {
	t.Helper()
	sig, err := pqc.GenerateIdentityKeyPair()
	check(t, err)
	kem, err := pqc.GenerateHybridKEMKeyPair()
	check(t, err)
	t.Cleanup(kem.Zeroize)
	d := Device{id, owner, id + "-key", sig.PublicBytes(), kem.PublicKey()}
	check(t, s.UpsertDevice(d))
	return d, kem
}

func TestRecovery(t *testing.T) {
	// The child exits without closing bbolt immediately after a durable prepare.
	if path := os.Getenv("URGUARD_TEST_CRASH_DB"); path != "" {
		s, err := Open(path)
		check(t, err)
		_, err = s.BeginPrepareRotation(2)
		check(t, err)
		os.Exit(42)
	}
	path := filepath.Join(t.TempDir(), "authority.db")
	s, err := Open(path)
	check(t, err)
	state, err := s.EpochState()
	check(t, err)
	if state.Active != 1 || state.Prepared != 0 {
		t.Fatal(state)
	}
	public, err := s.AuthorityPublicKey()
	check(t, err)
	k, err := s.EpochKey(1)
	check(t, err)
	ct, want, err := pqc.EncapsulateHybrid(k.PublicKey(), nil)
	check(t, err)
	k.Zeroize()
	d, _ := enroll(t, s, "lost", "alice")
	r, err := s.RevokeDevice(d.ID, "lost")
	check(t, err)
	_, err = s.BeginPrepareRotation(1)
	check(t, err)
	_, err = s.BeginPrepareRotation(1)
	check(t, err)
	if _, err = s.EpochKey(2); !errors.Is(err, ErrNotFound) {
		t.Fatal("prepared key exposed")
	}
	committed, err := s.CommitPreparedRotation(2, 30*time.Second)
	check(t, err)
	if committed.CutoffAt.Sub(committed.CommittedAt) != 30*time.Second {
		t.Fatal(committed)
	}
	retry, err := s.CommitPreparedRotation(2, 30*time.Second)
	check(t, err)
	if retry != committed {
		t.Fatal("commit retry changed cutoff")
	}
	check(t, s.Close())
	cmd := exec.Command(os.Args[0], "-test.run=^TestRecovery$")
	cmd.Env = append(os.Environ(), "URGUARD_TEST_CRASH_DB="+path)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 42 {
		t.Fatalf("child exit: %v %s", err, out)
	}
	s = openTest(t, path)
	state, err = s.EpochState()
	check(t, err)
	if state != committed {
		t.Fatal("committed state changed", state)
	}
	if _, err = s.CommitPreparedRotation(3, 0); !errors.Is(err, ErrConflict) {
		t.Fatal("stale commit accepted")
	}
	k, err = s.EpochKey(1)
	check(t, err)
	defer k.Zeroize()
	got, err := k.DecapsulateHybrid(ct, nil)
	check(t, err)
	if !bytes.Equal(want, got) {
		t.Fatal("historical epoch key changed")
	}
	pub, err := s.AuthorityPublicKey()
	check(t, err)
	if !bytes.Equal(pub, public) {
		t.Fatal("authority changed")
	}
	log, err := s.ListRevocations(0)
	check(t, err)
	if len(log) != 1 || log[0] != r {
		t.Fatal(log)
	}
}

func TestReplacementAndRevocations(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "store.db"))
	old, _ := enroll(t, s, "old", "alice")
	next, replacement := enroll(t, s, "new", "alice")
	bob, collaborator := enroll(t, s, "bob", "bob")
	key := make([]byte, 32)
	rand.Read(key)
	check(t, s.SaveSharedWrap("file", old.ID, key))
	check(t, s.SaveSharedWrap("file", bob.ID, key))
	check(t, s.SaveSharedWrap("another", old.ID, key))
	wrong := slices.Clone(key)
	wrong[0] ^= 1
	if err := s.SaveSharedWrap("file", next.ID, wrong); !errors.Is(err, ErrConflict) {
		t.Fatal("conflicting DEK accepted")
	}
	before, err := s.ListSharedWraps("file")
	check(t, err)
	results := make(chan Revocation, 4)
	errs := make(chan error, 4)
	for range 4 {
		go func() {
			r, err := s.RevokeDevice(old.ID, "lost")
			results <- r
			errs <- err
		}()
	}
	for range 4 {
		r := <-results
		check(t, <-errs)
		if r.CRLEpoch != 1 {
			t.Fatal(r)
		}
	}
	if err := s.UpsertDevice(old); !errors.Is(err, ErrRevoked) {
		t.Fatal("reactivated device")
	}
	if _, err := s.RewrapResourcesForReplacement(old.ID, bob.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("cross-owner replacement")
	}
	_, err = s.BeginPrepareRotation(1)
	check(t, err)
	_, err = s.CommitPreparedRotation(2, 0)
	check(t, err)
	n, err := s.RewrapResourcesForReplacement(old.ID, next.ID)
	check(t, err)
	if n != 2 {
		t.Fatal(n)
	}
	n, err = s.RewrapResourcesForReplacement(old.ID, next.ID)
	check(t, err)
	if n != 0 {
		t.Fatal("retry changed wraps")
	}
	after, err := s.ListSharedWraps("file")
	check(t, err)
	if len(after) != 2 || after[0].DeviceID != bob.ID || after[1].DeviceID != next.ID || !reflect.DeepEqual(before[0], after[0]) {
		t.Fatal("unexpected grants")
	}
	for i, k := range []*pqc.HybridKEMKeyPair{collaborator, replacement} {
		got, err := after[i].Open(k)
		check(t, err)
		if !bytes.Equal(got, key) {
			t.Fatal("wrong DEK")
		}
	}
	r, err := s.RevokeDevice(next.ID, "retired")
	check(t, err)
	if r.CRLEpoch != 2 {
		t.Fatal(r)
	}
	log, err := s.ListRevocations(1)
	check(t, err)
	if len(log) != 1 || log[0] != r {
		t.Fatal(log)
	}
}

func TestBackupIntegrity(t *testing.T) {
	dir := t.TempDir()
	s := openTest(t, filepath.Join(dir, "live.db"))
	d, _ := enroll(t, s, "old", "owner")
	pass := []byte("unit test passphrase")
	initial, err := s.ExportBackup(pass)
	check(t, err)
	pub, err := s.AuthorityPublicKey()
	check(t, err)
	replica := openTest(t, filepath.Join(dir, "replica.db"))
	if err = replica.RestoreBackup(initial, pass); !errors.Is(err, ErrBackupCorrupted) {
		t.Fatal("foreign authority accepted")
	}
	check(t, replica.RestoreIntoFreshStore(initial, pass, pub))
	r, err := s.RevokeDevice(d.ID, "lost")
	check(t, err)
	latest, err := s.ExportBackup(pass)
	check(t, err)
	check(t, replica.RestoreBackup(latest, pass))
	// Check live identity and revocation records after every failed restore.
	matches := func() {
		t.Helper()
		log, err := replica.ListRevocations(0)
		check(t, err)
		if len(log) != 1 || log[0] != r {
			t.Fatal("revocation lost")
		}
		device, err := replica.GetDevice(d.ID)
		check(t, err)
		if !reflect.DeepEqual(device, d) {
			t.Fatal("device changed")
		}
		got, err := replica.AuthorityPublicKey()
		check(t, err)
		if !bytes.Equal(got, pub) {
			t.Fatal("authority changed")
		}
	}
	matches()
	reject := func(data, pw []byte) {
		t.Helper()
		if err := replica.RestoreBackup(data, pw); !errors.Is(err, ErrBackupCorrupted) {
			t.Fatalf("unexpected restore result: %v", err)
		}
		matches()
	}
	reject(initial, pass)
	reject(latest, nil)
	reject(latest, []byte("wrong"))
	reject(latest[:16], pass)
	headerSize := binary.Size(backupHeader{})
	for _, index := range []int{0, headerSize - 1, headerSize, len(latest) - 1} {
		bad := slices.Clone(latest)
		bad[index] ^= 1
		reject(bad, pass)
	}
	// An otherwise authentic bundle with damaged ciphertext must fail AEAD.
	bad := slices.Clone(latest)
	bad[headerSize] ^= 1
	id, err := view(s, authority)
	check(t, err)
	signed := bad[:len(bad)-mldsa65.SignatureSize]
	sig, err := id.Sign([]byte(backupContext), signed)
	check(t, err)
	copy(bad[len(signed):], sig)
	reject(bad, pass)
	check(t, replica.RestoreBackup(latest, pass))
	fork := openTest(t, filepath.Join(dir, "fork.db"))
	check(t, fork.RestoreIntoFreshStore(initial, pass, pub))
	enroll(t, fork, "other", "owner")
	enroll(t, fork, "third", "owner")
	diverged, err := fork.ExportBackup(pass)
	check(t, err)
	reject(diverged, pass)
}
