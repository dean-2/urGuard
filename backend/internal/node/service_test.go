package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	v "github.com/dean-2/urGuard/backend/gen/urguard/v1"
	rpc "github.com/dean-2/urGuard/backend/gen/urguard/v1/urguardv1connect"
	"github.com/dean-2/urGuard/backend/internal/config"
	"github.com/dean-2/urGuard/backend/internal/transport"
	"github.com/dean-2/urGuard/backend/pkg/pqc"
	"github.com/dean-2/urGuard/backend/pkg/protocol"
	"google.golang.org/protobuf/proto"
	ts "google.golang.org/protobuf/types/known/timestamppb"
)

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func reject(t *testing.T, err, want error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want.Error()) {
		t.Fatalf("got %v; want %v", err, want)
	}
}
func TestMessagingRotationRevocation(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{NodeDBPath: filepath.Join(dir, "node.db"), WitnessDBPath: filepath.Join(dir, "witness.db"), CheckpointInterval: 2, CRLHeartbeat: time.Minute, MaxClockSkew: time.Minute, Tokens: map[string]string{}}
	for _, id := range []string{"device:alice", "device:bob"} {
		var tok [32]byte
		rand.Read(tok[:])
		cfg.Tokens[id] = hex.EncodeToString(tok[:])
	}
	authority, err := pqc.GenerateIdentityKeyPair()
	check(t, err)
	n, err := Open(cfg, authority.PublicBytes())
	check(t, err)
	defer n.Close()
	mux := http.NewServeMux()
	n.Mount(mux)
	a, err := transport.New(cfg, "device:alice")
	check(t, err)
	srv := httptest.NewUnstartedServer(a.Authenticate(mux))
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	defer srv.Close()
	b, err := transport.New(cfg, "device:bob")
	check(t, err)
	aliceRPC := rpc.NewMessagingServiceClient(a.Client, srv.URL, connect.WithGRPC())
	bobRPC := rpc.NewMessagingServiceClient(b.Client, srv.URL, connect.WithGRPC())
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	aliceKey, err := pqc.GenerateIdentityKeyPair()
	check(t, err)
	bobKey, err := pqc.GenerateIdentityKeyPair()
	check(t, err)
	alice := protocol.Peer{ID: "owner-a", DeviceID: "alice", SigningPublic: aliceKey.PublicBytes()}
	bob := protocol.Peer{ID: "owner-b", DeviceID: "bob", SigningPublic: bobKey.PublicBytes()}
	snapshot := &v.StreamControlUpdatesResponse{State: &v.EpochState{ActiveEpoch: 1}}
	for _, p := range []protocol.Peer{alice, bob} {
		snapshot.Devices = append(snapshot.Devices, &v.DeviceIdentity{DeviceId: p.DeviceID, OwnerId: p.ID, Mldsa65PublicKey: p.SigningPublic})
	}
	apply := func() {
		u := proto.CloneOf(snapshot)
		u.IssuedAt = ts.Now()
		body, err := (proto.MarshalOptions{Deterministic: true}).Marshal(u)
		check(t, err)
		u.AuthoritySignature, err = authority.Sign([]byte("urguard/control-update/v1"), body)
		check(t, err)
		check(t, n.apply(u))
	}
	apply()
	if err := n.apply(snapshot); err == nil {
		t.Fatal("accepted unsigned control update")
	}
	offer, pending, err := protocol.CreateSessionOffer(bob, bobKey, time.Now().Add(time.Hour))
	check(t, err)
	defer pending.Close()
	_, err = bobRPC.PublishSessionOffer(ctx, connect.NewRequest(&v.PublishSessionOfferRequest{Offer: offer}))
	check(t, err)
	got, err := aliceRPC.GetSessionOffer(ctx, connect.NewRequest(&v.GetSessionOfferRequest{RecipientDeviceId: "bob"}))
	check(t, err)
	h, send, err := protocol.CreateSessionHandshake(got.Msg.Offer, alice, bob, aliceKey, 1)
	check(t, err)
	defer send.Close()
	opened, err := aliceRPC.OpenSession(ctx, connect.NewRequest(&v.OpenSessionRequest{Handshake: h}))
	check(t, err)
	recv, err := pending.AcceptHandshake(h, alice)
	check(t, err)
	defer recv.Close()
	ticket := opened.Msg.ResumptionTicket
	challengeReq := connect.NewRequest(&v.RequestResumeChallengeRequest{SessionId: h.SessionId, ResumptionTicket: ticket})
	_, err = bobRPC.RequestResumeChallenge(ctx, challengeReq)
	reject(t, err, protocol.ErrSessionIdentityMismatch)
	challenge, err := aliceRPC.RequestResumeChallenge(ctx, challengeReq)
	check(t, err)
	resume, err := protocol.SignResumeSession(h.SessionId, ticket, challenge.Msg.ChallengeNonce, aliceKey)
	check(t, err)
	_, err = aliceRPC.ResumeSession(ctx, connect.NewRequest(resume))
	check(t, err)
	_, err = aliceRPC.ResumeSession(ctx, connect.NewRequest(resume))
	reject(t, err, protocol.ErrReplayDetected)
	// Send the last chunk first, rotate, and finish the transfer during grace.
	parts := [][]byte{[]byte("part one"), []byte("part two")}
	root := protocol.RootManifest([][32]byte{sha256.Sum256(parts[0]), sha256.Sum256(parts[1])})
	chunk := func(i int) {
		c, err := send.SealChunk("t", uint32(i), 2, root, parts[i])
		check(t, err)
		_, err = aliceRPC.SendChunk(ctx, connect.NewRequest(&v.SendChunkRequest{Chunk: c}))
		check(t, err)
	}
	chunk(1)
	snapshot.State = &v.EpochState{ActiveEpoch: 2, PreviousEpoch: 1, CutoffAt: ts.New(time.Now().Add(time.Minute))}
	apply()
	_, err = aliceRPC.OpenSession(ctx, connect.NewRequest(&v.OpenSessionRequest{Handshake: h}))
	reject(t, err, ErrEpoch)
	chunk(0)
	final, err := send.SignFinalizeTransfer("t", 2, root)
	check(t, err)
	status, err := aliceRPC.FinalizeTransfer(ctx, connect.NewRequest(final))
	check(t, err)
	if status.Msg.Status != v.DeliveryStatus_DELIVERY_STATUS_DELIVERED {
		t.Fatal(status.Msg.Status)
	}
	inbox, err := bobRPC.GetInbox(ctx, connect.NewRequest(&v.GetInboxRequest{RecipientDeviceId: "bob"}))
	check(t, err)
	assembler, err := protocol.NewChunkAssembler(recv, "t", time.Now().Add(time.Hour))
	check(t, err)
	defer assembler.Close()
	var content []byte
	for _, item := range inbox.Msg.Items {
		if c := item.GetChunk(); c != nil {
			check(t, assembler.Add(c))
		}
		if f := item.GetFinalized(); f != nil {
			_, content, err = assembler.FinalizeTransfer(f)
			check(t, err)
		}
	}
	if !bytes.Equal(content, bytes.Join(parts, nil)) {
		t.Fatal("recipient could not reconstruct transfer")
	}
	env, err := send.SealEnvelope([]byte("hello"))
	check(t, err)
	bad := proto.CloneOf(env)
	bad.Header.RecipientDeviceId = "alice"
	_, err = aliceRPC.SendEnvelope(ctx, connect.NewRequest(&v.SendEnvelopeRequest{Envelope: bad}))
	reject(t, err, protocol.ErrRecipientMismatch)
	req := connect.NewRequest(&v.SendEnvelopeRequest{Envelope: env})
	_, err = aliceRPC.SendEnvelope(ctx, req)
	check(t, err)
	_, err = aliceRPC.SendEnvelope(ctx, req)
	reject(t, err, protocol.ErrReplayDetected)
	snapshot.State.CutoffAt = ts.New(time.Now())
	apply()
	_, err = aliceRPC.SendEnvelope(ctx, req)
	reject(t, err, ErrEpoch)
	snapshot.Revocations = []*v.Revocation{{CrlEpoch: 1, RevokedDeviceId: "bob", IssuedAt: ts.Now()}}
	snapshot.CrlEpoch = 1
	apply()
	_, err = aliceRPC.SendEnvelope(ctx, req)
	reject(t, err, ErrRevoked)
	_, err = bobRPC.GetInbox(ctx, connect.NewRequest(&v.GetInboxRequest{RecipientDeviceId: "bob"}))
	reject(t, err, ErrRevoked)
}
