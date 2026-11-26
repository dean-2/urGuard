package tests

import (
	"bytes"
	"connectrpc.com/connect"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	v "github.com/dean-2/urGuard/backend/gen/urguard/v1"
	rpc "github.com/dean-2/urGuard/backend/gen/urguard/v1/urguardv1connect"
	"github.com/dean-2/urGuard/backend/internal/config"
	"github.com/dean-2/urGuard/backend/internal/controlplane"
	"github.com/dean-2/urGuard/backend/internal/node"
	"github.com/dean-2/urGuard/backend/internal/transport"
	"github.com/dean-2/urGuard/backend/pkg/auditlog"
	"github.com/dean-2/urGuard/backend/pkg/pqc"
	"github.com/dean-2/urGuard/backend/pkg/protocol"
	"github.com/dean-2/urGuard/backend/pkg/store"
	"google.golang.org/protobuf/proto"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func check(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func reject(t *testing.T, e, want error) {
	t.Helper()
	if e == nil || !strings.Contains(e.Error(), want.Error()) {
		t.Fatalf("expected %v, got %v", want, e)
	}
}
func until(t *testing.T, ok func() bool) {
	t.Helper()
	end := time.Now().Add(8 * time.Second)
	for !ok() {
		if time.Now().After(end) {
			t.Fatal("condition timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func secret() string { var b [32]byte; rand.Read(b[:]); return hex.EncodeToString(b[:]) }
func settings(t *testing.T) config.Config {
	dir := t.TempDir()
	c := config.Config{ControlPlaneDBPath: filepath.Join(dir, "cp.db"), CheckpointInterval: 2, CRLHeartbeat: 100 * time.Millisecond, MaxClockSkew: time.Minute, RotationGrace: 3 * time.Second, RequiredNodes: []string{"node-1", "node-2", "node-3"}, BackupPassphrase: secret(), Tokens: map[string]string{}}
	for _, id := range []string{"admin", "controlplane", "node:node-1", "node:node-2", "node:node-3", "device:alice-old", "device:bob"} {
		c.Tokens[id] = secret()
	}
	return c
}
func httpFor(t *testing.T, c config.Config, id string) *transport.HTTP {
	t.Helper()
	h, e := transport.New(c, id)
	check(t, e)
	return h
}
func serve(t *testing.T, c config.Config, mount func(*http.ServeMux)) string {
	m := http.NewServeMux()
	mount(m)
	s := httptest.NewUnstartedServer(httpFor(t, c, "controlplane").Authenticate(m))
	s.Config.Protocols = new(http.Protocols)
	s.Config.Protocols.SetUnencryptedHTTP2(true)
	s.Start()
	t.Cleanup(s.Close)
	return s.URL
}

type identity struct {
	d   *v.DeviceIdentity
	sig *pqc.IdentityKeyPair
	kem *pqc.HybridKEMKeyPair
}

func makeID(t *testing.T, id, owner string) identity {
	k, e := pqc.GenerateIdentityKeyPair()
	check(t, e)
	kem, e := pqc.GenerateHybridKEMKeyPair()
	check(t, e)
	t.Cleanup(kem.Zeroize)
	pub := kem.PublicKey()
	return identity{&v.DeviceIdentity{OwnerId: owner, DeviceId: id, KeyId: id + "-key", Mldsa65PublicKey: k.PublicBytes(), X25519PublicKey: pub.X25519, Mlkem768PublicKey: pub.MLKEM768}, k, kem}
}
func (i identity) peer() protocol.Peer {
	return protocol.Peer{ID: i.d.OwnerId, DeviceID: i.d.DeviceId, SigningPublic: i.sig.PublicBytes()}
}
func sign(t *testing.T, k *pqc.IdentityKeyPair, domain string, m proto.Message) []byte {
	body, e := (proto.MarshalOptions{Deterministic: true}).Marshal(m)
	check(t, e)
	sig, e := k.Sign([]byte(domain), body)
	check(t, e)
	return sig
}
func enroll(t *testing.T, cp rpc.CryptoControlServiceClient, i identity) {
	t.Helper()
	_, e := cp.EnrollDevice(t.Context(), connect.NewRequest(&v.EnrollDeviceRequest{Device: i.d, EnrollmentProof: sign(t, i.sig, "urguard/enroll/v1", i.d)}))
	check(t, e)
}

type flight struct {
	alice, bob rpc.MessagingServiceClient
	h          *v.SessionHandshake
	send, recv *protocol.Session
	ticket     []byte
	chunks     []*v.EncryptedChunk
	final      *v.FinalizeTransferRequest
	env        *v.EncryptedEnvelope
}

func parts(t *testing.T, s *protocol.Session, id string) ([]*v.EncryptedChunk, *v.FinalizeTransferRequest) {
	data := []string{"zero", "one", "two", "three"}
	var sums [][32]byte
	for _, p := range data {
		sums = append(sums, sha256.Sum256([]byte(p)))
	}
	root := protocol.RootManifest(sums)
	var chunks []*v.EncryptedChunk
	for i, p := range data {
		c, e := s.SealChunk(id, uint32(i), 4, root, []byte(p))
		check(t, e)
		chunks = append(chunks, c)
	}
	r, e := s.SignFinalizeTransfer(id, 4, root)
	check(t, e)
	return chunks, r
}
func inbox(t *testing.T, c rpc.MessagingServiceClient) []*v.InboxItem {
	r, e := c.GetInbox(t.Context(), connect.NewRequest(&v.GetInboxRequest{RecipientDeviceId: "bob"}))
	check(t, e)
	return r.Msg.Items
}
func TestThreeRelayLifecycle(t *testing.T) {
	c := settings(t)
	ctx := t.Context()
	st, e := store.Open(c.ControlPlaneDBPath)
	check(t, e)
	t.Cleanup(func() { st.Close() })
	pub, e := st.AuthorityPublicKey()
	check(t, e)
	var nodes []*node.Service
	var urls []string
	for _, id := range c.RequiredNodes {
		nc := c
		nc.NodeID = id
		dir := t.TempDir()
		nc.NodeDBPath = filepath.Join(dir, "node.db")
		nc.WitnessDBPath = filepath.Join(dir, "witness.db")
		n, e := node.Open(nc, pub)
		check(t, e)
		t.Cleanup(func() { n.Close() })
		nodes = append(nodes, n)
		urls = append(urls, serve(t, c, n.Mount))
	}
	c.WitnessURL = urls[0]
	w := rpc.NewAuditWitnessServiceClient(httpFor(t, c, "controlplane").Client, urls[0], connect.WithGRPC())
	s, e := controlplane.New(ctx, c, st, w, nil)
	check(t, e)
	url := serve(t, c, s.Mount)
	admin := httpFor(t, c, "admin").Client
	cp := rpc.NewCryptoControlServiceClient(admin, url, connect.WithGRPC())
	tele := rpc.NewTelemetryServiceClient(admin, url, connect.WithGRPC())
	alice, bob, recovery, next := makeID(t, "alice-old", "alice"), makeID(t, "bob", "bob"), makeID(t, "alice-recovery", "alice"), makeID(t, "alice-new", "alice")
	payload := "file\n{\"actor_id\":\"admin\",\"action\":\"GRANT_ROOT\"}"
	for _, i := range []identity{alice, bob, recovery, makeID(t, payload, "owner")} {
		enroll(t, cp, i)
	}
	var dek [32]byte
	rand.Read(dek[:])
	for _, id := range []string{"bob", "alice-old"} {
		check(t, st.SaveSharedWrap("file", id, dek[:]))
	}
	before, e := st.ListSharedWraps("file")
	check(t, e)
	var bobWrap store.SharedWrap
	for _, r := range before {
		if r.DeviceID == "bob" {
			bobWrap = r
		}
	}
	workers, stop := context.WithCancel(ctx)
	var done []chan struct{}
	defer func() {
		stop()
		for _, ch := range done {
			<-ch
		}
	}()
	var flights []flight
	for idx, n := range nodes {
		nc := rpc.NewCryptoControlServiceClient(httpFor(t, c, "node:"+c.RequiredNodes[idx]).Client, url, connect.WithGRPC())
		ch := make(chan struct{})
		done = append(done, ch)
		go func() { defer close(ch); _ = n.Sync(workers, nc) }()
		a := rpc.NewMessagingServiceClient(httpFor(t, c, "device:alice-old").Client, urls[idx], connect.WithGRPC())
		b := rpc.NewMessagingServiceClient(httpFor(t, c, "device:bob").Client, urls[idx], connect.WithGRPC())
		o, p, e := protocol.CreateSessionOffer(bob.peer(), bob.sig, time.Now().Add(time.Minute))
		check(t, e)
		defer p.Close()
		until(t, func() bool {
			_, e := b.PublishSessionOffer(ctx, connect.NewRequest(&v.PublishSessionOfferRequest{Offer: o}))
			return e == nil
		})
		fetched, e := a.GetSessionOffer(ctx, connect.NewRequest(&v.GetSessionOfferRequest{RecipientDeviceId: "bob"}))
		check(t, e)
		h, send, e := protocol.CreateSessionHandshake(fetched.Msg.Offer, alice.peer(), bob.peer(), alice.sig, 1)
		check(t, e)
		opened, e := a.OpenSession(ctx, connect.NewRequest(&v.OpenSessionRequest{Handshake: h}))
		check(t, e)
		items := inbox(t, b)
		recv, e := p.AcceptHandshake(items[0].GetHandshake(), alice.peer())
		check(t, e)
		f := flight{alice: a, bob: b, h: h, send: send, recv: recv, ticket: opened.Msg.ResumptionTicket}
		f.env, e = send.SealEnvelope([]byte("secret"))
		check(t, e)
		bad := proto.CloneOf(f.env)
		bad.Header.RecipientId = "other"
		_, e = a.SendEnvelope(ctx, connect.NewRequest(&v.SendEnvelopeRequest{Envelope: bad}))
		reject(t, e, protocol.ErrRecipientMismatch)
		_, e = a.SendEnvelope(ctx, connect.NewRequest(&v.SendEnvelopeRequest{Envelope: f.env}))
		check(t, e)
		_, e = a.SendEnvelope(ctx, connect.NewRequest(&v.SendEnvelopeRequest{Envelope: f.env}))
		reject(t, e, protocol.ErrReplayDetected)
		capture := inbox(t, b)[1].GetEnvelope()
		plain, e := recv.OpenEnvelope(capture)
		check(t, e)
		if string(plain) != "secret" {
			t.Fatal("incorrect envelope")
		}
		f.env = capture
		cr := connect.NewRequest(&v.RequestResumeChallengeRequest{SessionId: h.SessionId, ResumptionTicket: f.ticket})
		challenge, e := a.RequestResumeChallenge(ctx, cr)
		check(t, e)
		rr, e := protocol.SignResumeSession(h.SessionId, f.ticket, challenge.Msg.ChallengeNonce, alice.sig)
		check(t, e)
		_, e = b.ResumeSession(ctx, connect.NewRequest(rr))
		reject(t, e, protocol.ErrSessionIdentityMismatch)
		_, e = a.ResumeSession(ctx, connect.NewRequest(rr))
		check(t, e)
		for _, id := range []string{"missing", "corrupted"} {
			chunks, final := parts(t, send, id)
			_, e = a.SendChunk(ctx, connect.NewRequest(&v.SendChunkRequest{Chunk: chunks[0]}))
			check(t, e)
			if id == "corrupted" {
				chunks[1].Envelope.Ciphertext[0] ^= 1
				_, e = a.SendChunk(ctx, connect.NewRequest(&v.SendChunkRequest{Chunk: chunks[1]}))
				reject(t, e, protocol.ErrDeliveryFailed)
			}
			r, e := a.FinalizeTransfer(ctx, connect.NewRequest(final))
			check(t, e)
			if r.Msg.Status != v.DeliveryStatus_DELIVERY_STATUS_FAILED || len(inbox(t, b)) != 2 {
				t.Fatal("failed transfer exposed items")
			}
		}
		f.chunks, f.final = parts(t, send, "good")
		_, e = a.SendChunk(ctx, connect.NewRequest(&v.SendChunkRequest{Chunk: f.chunks[2]}))
		check(t, e)
		flights = append(flights, f)
	}
	_, e = cp.PrepareRotation(ctx, connect.NewRequest(&v.PrepareRotationRequest{ExpectedActiveEpoch: 1}))
	check(t, e)
	commit, e := cp.CommitRotation(ctx, connect.NewRequest(&v.CommitRotationRequest{PreparedEpoch: 2}))
	check(t, e)
	for _, f := range flights {
		// Probe using an already-consumed offer while the signed update propagates.
		until(t, func() bool {
			_, e := f.alice.OpenSession(ctx, connect.NewRequest(&v.OpenSessionRequest{Handshake: f.h}))
			return e != nil && strings.Contains(e.Error(), node.ErrEpoch.Error())
		})
		fresh, p, e := protocol.CreateSessionOffer(bob.peer(), bob.sig, time.Now().Add(time.Minute))
		check(t, e)
		defer p.Close()
		_, e = f.bob.PublishSessionOffer(ctx, connect.NewRequest(&v.PublishSessionOfferRequest{Offer: fresh}))
		check(t, e)
		old, tmp, e := protocol.CreateSessionHandshake(fresh, alice.peer(), bob.peer(), alice.sig, 1)
		check(t, e)
		tmp.Close()
		_, e = f.alice.OpenSession(ctx, connect.NewRequest(&v.OpenSessionRequest{Handshake: old}))
		reject(t, e, node.ErrEpoch)
		for _, idx := range []int{0, 3, 1} {
			_, e = f.alice.SendChunk(ctx, connect.NewRequest(&v.SendChunkRequest{Chunk: f.chunks[idx]}))
			check(t, e)
		}
		status, e := f.alice.FinalizeTransfer(ctx, connect.NewRequest(f.final))
		check(t, e)
		if status.Msg.Status != v.DeliveryStatus_DELIVERY_STATUS_DELIVERED {
			t.Fatal(status.Msg)
		}
		asm, e := protocol.NewChunkAssembler(f.recv, "good", time.Now().Add(time.Minute))
		check(t, e)
		var data []byte
		for _, item := range inbox(t, f.bob) {
			if chunk := item.GetChunk(); chunk != nil {
				check(t, asm.Add(chunk))
			}
			if r := item.GetFinalized(); r != nil {
				_, data, e = asm.FinalizeTransfer(r)
				check(t, e)
			}
		}
		if string(data) != "zeroonetwothree" {
			t.Fatal("incomplete transfer")
		}
		asm.Close()
		f.send.Close()
		f.recv.Close()
		for _, id := range []identity{alice, bob} {
			assertExposure(t, id, f.env)
		}
	}
	time.Sleep(time.Until(commit.Msg.State.CutoffAt.AsTime()))
	for _, f := range flights {
		_, e = f.alice.SendEnvelope(ctx, connect.NewRequest(&v.SendEnvelopeRequest{Envelope: f.env}))
		reject(t, e, node.ErrEpoch)
		_, e = f.alice.SendChunk(ctx, connect.NewRequest(&v.SendChunkRequest{Chunk: f.chunks[0]}))
		reject(t, e, node.ErrEpoch)
	}
	_, e = cp.RevokeDevice(ctx, connect.NewRequest(&v.RevokeDeviceRequest{DeviceId: "alice-old", Reason: payload}))
	check(t, e)
	until(t, func() bool {
		r, e := cp.GetRevocationStatus(ctx, connect.NewRequest(&v.GetRevocationStatusRequest{CrlEpoch: 1}))
		check(t, e)
		if r.Msg.RevocationPropagationMs == nil {
			return false
		}
		if len(r.Msg.Nodes) != 3 {
			t.Fatal(r.Msg)
		}
		t.Logf("revocation_propagation_ms=%d", r.Msg.GetRevocationPropagationMs())
		return true
	})
	for _, f := range flights {
		_, e = f.alice.SendEnvelope(ctx, connect.NewRequest(&v.SendEnvelopeRequest{Envelope: f.env}))
		reject(t, e, node.ErrRevoked)
	}
	r := &v.ReenrollDeviceRequest{LostDeviceId: "alice-old", RecoveryDeviceId: "alice-recovery", Replacement: next.d}
	r.RecoveryProof = sign(t, recovery.sig, "urguard/recover/v1", r)
	replaced, e := cp.ReenrollDevice(ctx, connect.NewRequest(r))
	check(t, e)
	if replaced.Msg.ResourcesRewrapped != 1 {
		t.Fatal(replaced.Msg)
	}
	wraps, e := st.ListSharedWraps("file")
	check(t, e)
	if len(wraps) != 2 {
		t.Fatal(wraps)
	}
	seen := map[string]bool{}
	for _, wrap := range wraps {
		k := next.kem
		switch wrap.DeviceID {
		case "bob":
			k = bob.kem
			if !reflect.DeepEqual(wrap, bobWrap) {
				t.Fatal("collaborator wrap changed")
			}
		case "alice-new":
		default:
			t.Fatal(wrap.DeviceID)
		}
		seen[wrap.DeviceID] = true
		plain, e := wrap.Open(k)
		check(t, e)
		if !bytes.Equal(plain, dek[:]) {
			t.Fatal("DEK mismatch")
		}
	}
	if len(seen) != 2 {
		t.Fatal(seen)
	}
	backup, e := cp.ExportBackup(ctx, connect.NewRequest(&v.ExportBackupRequest{}))
	check(t, e)
	// v1 fixed-width header: 76 bytes before SHA-256 manifest, then ciphertext at 108.
	for _, offset := range []int{76, 108} {
		bad := bytes.Clone(backup.Msg.Bundle)
		bad[offset] ^= 1
		_, e = cp.RestoreBackup(ctx, connect.NewRequest(&v.RestoreBackupRequest{Bundle: bad}))
		reject(t, e, store.ErrBackupCorrupted)
	}
	state, e := cp.GetEpochState(ctx, connect.NewRequest(&v.GetEpochStateRequest{}))
	check(t, e)
	after, e := st.ListSharedWraps("file")
	check(t, e)
	revoked, e := st.IsDeviceRevoked("alice-old")
	check(t, e)
	if state.Msg.State.ActiveEpoch != 2 || !reflect.DeepEqual(after, wraps) || !revoked {
		t.Fatal("restore changed live state")
	}
	events, e := tele.ListAuditEvents(ctx, connect.NewRequest(&v.ListAuditEventsRequest{}))
	check(t, e)
	failures, injected := 0, 0
	for _, event := range events.Msg.Events {
		if event.Action == "GRANT_ROOT" {
			t.Fatal("forged event")
		}
		if event.Action == "BACKUP_INTEGRITY_FAILURE" {
			failures++
		}
		if event.UserText == payload {
			var body auditlog.Event
			check(t, json.Unmarshal(event.CanonicalBody, &body))
			if body.UserText != payload || body.Action != "DEVICE_ENROLLED" || bytes.ContainsRune(event.CanonicalBody, '\n') {
				t.Fatal("invalid framing")
			}
			injected++
		}
	}
	report, e := tele.VerifyAuditChain(ctx, connect.NewRequest(&v.VerifyAuditChainRequest{}))
	check(t, e)
	head, e := w.GetWitnessHead(ctx, connect.NewRequest(&v.GetWitnessHeadRequest{}))
	check(t, e)
	seq, hash, e := auditlog.WitnessCheckpoint(head.Msg.SignedHead, pub, c.CheckpointInterval)
	check(t, e)
	last := events.Msg.Events[len(events.Msg.Events)-1]
	if failures != 2 || injected != 1 || !report.Msg.Valid || seq != last.Seq || hash != hex.EncodeToString(last.EntryHash) {
		t.Fatal("audit or witness mismatch")
	}
}

// Reconstruct the actual envelope AAD for a captured packet; test both leaked
// signing seeds against the protocol KDF after the two endpoints have closed.
func assertExposure(t *testing.T, id identity, e *v.EncryptedEnvelope) {
	n := func(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }
	frame := func(fields ...[]byte) []byte {
		var b []byte
		for _, f := range fields {
			b = append(b, n(uint64(len(f)))...)
			b = append(b, f...)
		}
		return b
	}
	h := e.Header
	aad := frame([]byte(h.SenderId), []byte(h.SenderDeviceId), []byte(h.RecipientId), []byte(h.RecipientDeviceId), []byte(h.SessionId), n(h.KeyEpoch), n(h.MsgSeq), frame(n(uint64(h.Timestamp.Seconds)), n(uint64(h.Timestamp.Nanos))), nil)
	seed := id.sig.PrivateBytes()
	defer pqc.Zeroize(seed)
	k, err := pqc.DeriveSubkey(seed, "session/v1")
	check(t, err)
	defer pqc.Zeroize(k)
	mk, err := pqc.DeriveSubkey(k, "urguard/v1/envelope"+string(n(h.MsgSeq)))
	check(t, err)
	defer pqc.Zeroize(mk)
	if _, err = pqc.OpenAEAD(mk, h.Nonce, e.Ciphertext, aad); err == nil {
		t.Fatal(fmt.Sprintf("identity %s decrypted historical capture", id.d.DeviceId))
	}
}
