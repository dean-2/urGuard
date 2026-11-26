package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	v "github.com/dean-2/urGuard/backend/gen/urguard/v1"
	rpc "github.com/dean-2/urGuard/backend/gen/urguard/v1/urguardv1connect"
	"github.com/dean-2/urGuard/backend/internal/config"
	"github.com/dean-2/urGuard/backend/internal/node"
	"github.com/dean-2/urGuard/backend/internal/transport"
	"github.com/dean-2/urGuard/backend/pkg/auditlog"
	"github.com/dean-2/urGuard/backend/pkg/pqc"
	"github.com/dean-2/urGuard/backend/pkg/store"
)

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func testConfig(t *testing.T) config.Config {
	t.Helper()
	dir := t.TempDir()
	c := config.Config{NodeID: "n1", NodeDBPath: filepath.Join(dir, "node.db"), WitnessDBPath: filepath.Join(dir, "witness.db"), ControlPlaneDBPath: filepath.Join(dir, "cp.db"), CRLHeartbeat: 10 * time.Second, MaxClockSkew: time.Minute, CheckpointInterval: 2, RequiredNodes: []string{"n1", "n2"}, RotationGrace: time.Minute, Tokens: map[string]string{}}
	for _, p := range []string{"node:n1", "node:n2", "admin", "controlplane"} {
		var token [32]byte
		rand.Read(token[:])
		c.Tokens[p] = hex.EncodeToString(token[:])
	}
	return c
}
func client(t *testing.T, c config.Config, id string) *transport.HTTP {
	t.Helper()
	h, err := transport.New(c, id)
	check(t, err)
	return h
}
func serve(t *testing.T, c config.Config, handler http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(client(t, c, "controlplane").Authenticate(handler))
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}
func control(t *testing.T, c config.Config, s *Service, id string) rpc.CryptoControlServiceClient {
	t.Helper()
	m := http.NewServeMux()
	s.Mount(m)
	srv := serve(t, c, m)
	return rpc.NewCryptoControlServiceClient(client(t, c, id).Client, srv.URL, connect.WithGRPC())
}
func relay(t *testing.T, c config.Config, pub []byte) *node.Service {
	t.Helper()
	n, err := node.Open(c, pub)
	check(t, err)
	t.Cleanup(func() { n.Close() })
	return n
}
func TestDurableWitnessRetryRollbackAndFork(t *testing.T) {
	c := testConfig(t)
	c.CRLHeartbeat = 30 * time.Millisecond
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	st, err := store.Open(c.ControlPlaneDBPath)
	check(t, err)
	pub, err := st.AuthorityPublicKey()
	check(t, err)
	n := relay(t, c, pub)
	var offline atomic.Bool
	witness := func(n *node.Service) rpc.AuditWitnessServiceClient {
		mux := http.NewServeMux()
		n.Mount(mux)
		srv := serve(t, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if offline.Load() {
				http.Error(w, "offline", 503)
				return
			}
			mux.ServeHTTP(w, r)
		}))
		return rpc.NewAuditWitnessServiceClient(client(t, c, "controlplane").Client, srv.URL, connect.WithGRPC())
	}
	w := witness(n)
	_, err = New(ctx, c, st, w, nil)
	check(t, err)
	check(t, st.Close())
	base, err := os.ReadFile(c.ControlPlaneDBPath)
	check(t, err)
	st, err = store.Open(c.ControlPlaneDBPath)
	check(t, err)
	defer st.Close()
	s, err := New(ctx, c, st, w, nil)
	check(t, err)
	admin := control(t, c, s, "admin")
	offline.Store(true)
	_, err = admin.PrepareRotation(ctx, connect.NewRequest(&v.PrepareRotationRequest{ExpectedActiveEpoch: 1}))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("unwitnessed prepare: %v", err)
	}
	_, err = admin.CommitRotation(ctx, connect.NewRequest(&v.CommitRotationRequest{PreparedEpoch: 2}))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("unwitnessed commit: %v", err)
	}
	// Restart the actual witness and drain two pending events from the durable queue.
	check(t, n.Close())
	offline.Store(false)
	w = witness(relay(t, c, pub))
	s, err = New(ctx, c, st, w, nil)
	check(t, err)
	head, err := w.GetWitnessHead(ctx, connect.NewRequest(&v.GetWitnessHeadRequest{}))
	check(t, err)
	seq, _, err := auditlog.WitnessCheckpoint(head.Msg.SignedHead, pub, c.CheckpointInterval)
	check(t, err)
	if seq != 2 {
		t.Fatalf("witness seq %d", seq)
	}
	local, err := s.log.SignedHead()
	check(t, err)
	if !bytes.Equal(local, head.Msg.SignedHead) {
		t.Fatal("witness and local head differ")
	}
	// A live control plane also retries without a restart or a new RPC.
	admin = control(t, c, s, "admin")
	offline.Store(true)
	_, err = admin.PrepareRotation(ctx, connect.NewRequest(&v.PrepareRotationRequest{ExpectedActiveEpoch: 2}))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("unwitnessed retry: %v", err)
	}
	offline.Store(false)
	worker, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); s.RetryPending(worker) }()
	defer func() { stop(); <-done }()
	for {
		current, err := w.GetWitnessHead(ctx, connect.NewRequest(&v.GetWitnessHeadRequest{}))
		check(t, err)
		n, _, err := auditlog.WitnessCheckpoint(current.Msg.SignedHead, pub, c.CheckpointInterval)
		check(t, err)
		if n == 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Recreate the genesis DB, then make a distinct signed fork of equal length.
	path := filepath.Join(t.TempDir(), "rollback.db")
	check(t, os.WriteFile(path, base, 0600))
	old, err := store.Open(path)
	check(t, err)
	defer old.Close()
	if _, err = New(ctx, c, old, w, nil); err == nil {
		t.Fatal("started with rolled-back history")
	}
	l, err := old.OpenAuditLog(c.CheckpointInterval)
	check(t, err)
	for range 3 {
		_, err = l.Append(auditlog.Event{ActorID: "operator", Action: "OTHER"})
		check(t, err)
	}
	if _, err = New(ctx, c, old, w, nil); err == nil {
		t.Fatal("started with forked history")
	}
}
func TestStreamEnforcementAndRequiredAcknowledgements(t *testing.T) {
	c := testConfig(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	st, err := store.Open(c.ControlPlaneDBPath)
	check(t, err)
	defer st.Close()
	pub, err := st.AuthorityPublicKey()
	check(t, err)
	s, err := New(ctx, c, st, nil, nil)
	check(t, err)
	admin := control(t, c, s, "admin")
	sign, err := pqc.GenerateIdentityKeyPair()
	check(t, err)
	kem, err := pqc.GenerateHybridKEMKeyPair()
	check(t, err)
	defer kem.Zeroize()
	pk := kem.PublicKey()
	d := &v.DeviceIdentity{OwnerId: "alice", DeviceId: "phone", KeyId: "phone-key", Mldsa65PublicKey: sign.PublicBytes(), X25519PublicKey: pk.X25519, Mlkem768PublicKey: pk.MLKEM768}
	data, err := wire.Marshal(d)
	check(t, err)
	proof, err := sign.Sign([]byte("urguard/enroll/v1"), data)
	check(t, err)
	if _, err = admin.EnrollDevice(ctx, connect.NewRequest(&v.EnrollDeviceRequest{Device: d})); err == nil {
		t.Fatal("missing enrollment proof accepted")
	}
	_, err = admin.EnrollDevice(ctx, connect.NewRequest(&v.EnrollDeviceRequest{Device: d, EnrollmentProof: proof}))
	check(t, err)
	// Hold a real stream open across the mutation. The heartbeat is ten seconds.
	cp1 := control(t, c, s, "node:n1")
	stream, err := cp1.StreamControlUpdates(ctx, connect.NewRequest(&v.StreamControlUpdatesRequest{NodeId: "n1"}))
	check(t, err)
	defer stream.Close()
	if !stream.Receive() || len(stream.Msg().Devices) != 1 {
		t.Fatal("missing initial device snapshot", stream.Err())
	}
	rev, err := admin.RevokeDevice(ctx, connect.NewRequest(&v.RevokeDeviceRequest{DeviceId: d.DeviceId}))
	check(t, err)
	started := time.Now()
	if !stream.Receive() || stream.Msg().CrlEpoch != 1 || time.Since(started) >= c.CRLHeartbeat {
		t.Fatal("revocation was not pushed", stream.Err())
	}
	req := connect.NewRequest(&v.GetRevocationStatusRequest{CrlEpoch: rev.Msg.Revocation.CrlEpoch})
	status, err := admin.GetRevocationStatus(ctx, req)
	check(t, err)
	if status.Msg.RevocationPropagationMs != nil {
		t.Fatal("premature propagation metric")
	}
	// Each node persists the snapshot and acknowledges using its own credential.
	workers, stop := context.WithCancel(ctx)
	var done []chan struct{}
	defer func() {
		stop()
		for _, ch := range done {
			<-ch
		}
	}()
	for _, id := range c.RequiredNodes {
		nc := c
		nc.NodeID = id
		dir := t.TempDir()
		nc.NodeDBPath = filepath.Join(dir, "node")
		nc.WitnessDBPath = filepath.Join(dir, "witness")
		n := relay(t, nc, pub)
		cp := control(t, c, s, "node:"+id)
		ch := make(chan struct{})
		done = append(done, ch)
		go func() { defer close(ch); _ = n.Sync(workers, cp) }()
		for {
			status, err = admin.GetRevocationStatus(ctx, req)
			check(t, err)
			ready := false
			for _, ack := range status.Msg.Nodes {
				if ack.NodeId == id && ack.AcknowledgedAt != nil {
					ready = true
				}
			}
			if ready {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if id == "n1" && status.Msg.RevocationPropagationMs != nil {
			t.Fatal("final node has not acknowledged")
		}
	}
	last := status.Msg.Nodes[1].AcknowledgedAt.AsTime()
	want := uint64(last.Sub(rev.Msg.Revocation.IssuedAt.AsTime()).Milliseconds())
	if status.Msg.RevocationPropagationMs == nil || status.Msg.GetRevocationPropagationMs() != want {
		t.Fatalf("metric %v, want %d", status.Msg, want)
	}
}

func TestRecoveryProofBackupAndAudit(t *testing.T) {
	c := testConfig(t)
	var secret [32]byte
	rand.Read(secret[:])
	c.BackupPassphrase = hex.EncodeToString(secret[:])
	ctx := t.Context()
	st, err := store.Open(c.ControlPlaneDBPath)
	check(t, err)
	defer st.Close()
	s, err := New(ctx, c, st, nil, nil)
	check(t, err)
	admin := control(t, c, s, "admin")
	mux := http.NewServeMux()
	s.Mount(mux)
	server := serve(t, c, mux)
	telemetry := rpc.NewTelemetryServiceClient(client(t, c, "admin").Client, server.URL, connect.WithGRPC())
	makeDevice := func(id string) (*v.DeviceIdentity, *pqc.IdentityKeyPair) {
		signer, err := pqc.GenerateIdentityKeyPair()
		check(t, err)
		kem, err := pqc.GenerateHybridKEMKeyPair()
		check(t, err)
		pub := kem.PublicKey()
		kem.Zeroize()
		return &v.DeviceIdentity{DeviceId: id, OwnerId: "alice", KeyId: id + "-key", Mldsa65PublicKey: signer.PublicBytes(), X25519PublicKey: pub.X25519, Mlkem768PublicKey: pub.MLKEM768}, signer
	}
	enroll := func(d *v.DeviceIdentity, k *pqc.IdentityKeyPair) {
		body, err := wire.Marshal(d)
		check(t, err)
		sig, err := k.Sign([]byte("urguard/enroll/v1"), body)
		check(t, err)
		_, err = admin.EnrollDevice(ctx, connect.NewRequest(&v.EnrollDeviceRequest{Device: d, EnrollmentProof: sig}))
		check(t, err)
	}
	lost, k := makeDevice("lost")
	enroll(lost, k)
	recovery, rk := makeDevice("recovery")
	enroll(recovery, rk)
	next, _ := makeDevice("new")
	var dek [32]byte
	rand.Read(dek[:])
	check(t, st.SaveSharedWrap("resource", "lost", dek[:]))
	r := &v.ReenrollDeviceRequest{LostDeviceId: "lost", RecoveryDeviceId: "recovery", Replacement: next}
	body, err := wire.Marshal(r)
	check(t, err)
	r.RecoveryProof, err = k.Sign([]byte("urguard/recover/v1"), body)
	check(t, err)
	if _, err = admin.ReenrollDevice(ctx, connect.NewRequest(r)); err == nil {
		t.Fatal("lost device authorized its own replacement")
	}
	revoked, err := st.IsDeviceRevoked("lost")
	check(t, err)
	if revoked {
		t.Fatal("invalid proof changed live state")
	}
	r.RecoveryProof, err = rk.Sign([]byte("urguard/recover/v1"), body)
	check(t, err)
	result, err := admin.ReenrollDevice(ctx, connect.NewRequest(r))
	check(t, err)
	if result.Msg.ResourcesRewrapped != 1 {
		t.Fatal(result.Msg)
	}
	backup, err := admin.ExportBackup(ctx, connect.NewRequest(&v.ExportBackupRequest{}))
	check(t, err)
	_, err = admin.RestoreBackup(ctx, connect.NewRequest(&v.RestoreBackupRequest{Bundle: backup.Msg.Bundle}))
	check(t, err)
	backup.Msg.Bundle[0] ^= 1
	if _, err = admin.RestoreBackup(ctx, connect.NewRequest(&v.RestoreBackupRequest{Bundle: backup.Msg.Bundle})); err == nil {
		t.Fatal("corrupt restore accepted")
	}
	events, err := telemetry.ListAuditEvents(ctx, connect.NewRequest(&v.ListAuditEventsRequest{}))
	check(t, err)
	if len(events.Msg.Events) == 0 || events.Msg.Events[len(events.Msg.Events)-1].Action != "BACKUP_INTEGRITY_FAILURE" {
		t.Fatal("missing backup failure event")
	}
	report, err := telemetry.VerifyAuditChain(ctx, connect.NewRequest(&v.VerifyAuditChainRequest{}))
	check(t, err)
	if !report.Msg.Valid {
		t.Fatal(report.Msg)
	}
	_, err = telemetry.ListAlerts(ctx, connect.NewRequest(&v.ListAlertsRequest{}))
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatal(err)
	}
}
