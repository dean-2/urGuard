package protocol

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/dean-2/urGuard/backend/gen/urguard/v1"
	"github.com/dean-2/urGuard/backend/pkg/pqc"
	"google.golang.org/protobuf/proto"
)

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func wantErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got %v; want %v", err, want)
	}
}
func peer(t *testing.T, id string) (Peer, *pqc.IdentityKeyPair) {
	t.Helper()
	k, err := pqc.GenerateIdentityKeyPair()
	check(t, err)
	return Peer{id, id + "-device", k.PublicBytes()}, k
}

type fixture struct {
	alice, bob Peer
	a, b       *pqc.IdentityKeyPair
	h          *v1.SessionHandshake
	offer      *PendingOffer
	send, recv *Session
}

func setup(t *testing.T) *fixture {
	t.Helper()
	f := new(fixture)
	f.alice, f.a = peer(t, "alice")
	f.bob, f.b = peer(t, "bob")
	o, p, err := CreateSessionOffer(f.bob, f.b, time.Now().Add(time.Hour))
	check(t, err)
	f.offer = p
	t.Cleanup(p.Close)
	f.h, f.send, err = CreateSessionHandshake(o, f.alice, f.bob, f.a, 7)
	check(t, err)
	t.Cleanup(f.send.Close)
	f.recv, err = p.AcceptHandshake(f.h, f.alice)
	check(t, err)
	t.Cleanup(f.recv.Close)
	return f
}
func TestOfferAndHandshake(t *testing.T) {
	alice, a := peer(t, "alice")
	bob, b := peer(t, "bob")
	o, p, err := CreateSessionOffer(bob, b, time.Now().Add(time.Hour))
	check(t, err)
	defer p.Close()
	for _, change := range []func(*v1.SessionOffer){
		func(o *v1.SessionOffer) { o.RecipientDeviceId += "x" }, func(o *v1.SessionOffer) { o.OfferId += "x" },
		func(o *v1.SessionOffer) { o.EphemeralMlkem768PublicKey[0] ^= 1 }, func(o *v1.SessionOffer) { o.ExpiresAt.Seconds++ },
	} {
		bad := proto.CloneOf(o)
		change(bad)
		if VerifySessionOffer(bad, bob) == nil {
			t.Fatal("accepted altered offer")
		}
	}
	h, send, err := CreateSessionHandshake(o, alice, bob, a, 2)
	check(t, err)
	defer send.Close()
	for _, change := range []func(*v1.SessionHandshake){
		func(h *v1.SessionHandshake) { h.SessionId += "x" }, func(h *v1.SessionHandshake) { h.SenderId += "x" },
		func(h *v1.SessionHandshake) { h.SenderDeviceId += "x" }, func(h *v1.SessionHandshake) { h.KeyEpoch++ },
		func(h *v1.SessionHandshake) { h.Offer.OfferId += "x" }, func(h *v1.SessionHandshake) { h.Offer.RecipientId += "x" },
		func(h *v1.SessionHandshake) { h.Offer.RecipientDeviceId += "x" },
	} {
		bad := proto.CloneOf(h)
		change(bad)
		if bytes.Equal(transcript(h), transcript(bad)) {
			t.Fatal("unbound transcript field")
		}
		if _, err := p.AcceptHandshake(bad, alice); err == nil {
			t.Fatal("accepted modified handshake")
		}
	}
	// Exactly one consumer wins, even when both receive a valid handshake.
	ephemeral := p.key
	var wins, replays atomic.Int32
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			s, err := p.AcceptHandshake(h, alice)
			switch {
			case err == nil:
				wins.Add(1)
				s.Close()
			case errors.Is(err, ErrReplayDetected):
				replays.Add(1)
			default:
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 || replays.Load() != 1 {
		t.Fatal("offer was not single use")
	}
	ct := pqc.HybridCiphertext{EphemeralX25519: h.EphemeralX25519PublicKey, MLKEM768: h.Mlkem768Ciphertext}
	if _, err := ephemeral.DecapsulateHybrid(ct, transcript(h)); err == nil {
		t.Fatal("consumed offer still has a usable private key")
	}
}
func TestEnvelopeBindingAndSlidingReplay(t *testing.T) {
	f := setup(t)
	msg := []byte("authenticated message")
	env, err := f.send.SealEnvelope(msg)
	check(t, err)
	for _, change := range []func(*v1.EncryptedEnvelope){
		func(e *v1.EncryptedEnvelope) { e.Header.RecipientId += "x" }, func(e *v1.EncryptedEnvelope) { e.Header.RecipientDeviceId += "x" },
		func(e *v1.EncryptedEnvelope) { e.Header.SenderId += "x" }, func(e *v1.EncryptedEnvelope) { e.Header.SenderDeviceId += "x" },
		func(e *v1.EncryptedEnvelope) { e.Header.Timestamp.Nanos ^= 1 }, func(e *v1.EncryptedEnvelope) { e.Header.MsgSeq += 1000 },
		func(e *v1.EncryptedEnvelope) { e.Header.SessionId += "x" }, func(e *v1.EncryptedEnvelope) { e.Header.KeyEpoch++ },
		func(e *v1.EncryptedEnvelope) { e.Header.Nonce[0] ^= 1 }, func(e *v1.EncryptedEnvelope) { e.Ciphertext[0] ^= 1 },
	} {
		bad := proto.CloneOf(env)
		change(bad)
		_, err := f.recv.OpenEnvelope(bad)
		wantErr(t, err, ErrRecipientMismatch)
	}
	zero := proto.CloneOf(env)
	zero.Header.MsgSeq = 0
	_, err = f.recv.OpenEnvelope(zero)
	wantErr(t, err, ErrReplayDetected)
	got, err := f.recv.OpenEnvelope(env)
	check(t, err)
	if !bytes.Equal(got, msg) {
		t.Fatal("incorrect plaintext")
	}
	_, err = f.recv.OpenEnvelope(env)
	wantErr(t, err, ErrReplayDetected)
	stale, err := f.send.SealEnvelope(msg)
	check(t, err)
	var latest *v1.EncryptedEnvelope
	for range 64 {
		latest, err = f.send.SealEnvelope(msg)
		check(t, err)
	}
	_, err = f.recv.OpenEnvelope(latest)
	check(t, err)
	_, err = f.recv.OpenEnvelope(stale)
	wantErr(t, err, ErrReplayDetected)
}
func TestClosedSessionAndExposedIdentities(t *testing.T) {
	f := setup(t)
	capture, err := f.send.SealEnvelope([]byte("private"))
	check(t, err)
	// Retain buffer references to verify in-place wiping, not just dropping pointers.
	sendKey, recvKey := f.send.key, f.recv.key
	f.send.Close()
	f.recv.Close()
	if !bytes.Equal(sendKey, make([]byte, 32)) || !bytes.Equal(recvKey, make([]byte, 32)) || f.offer.key != nil {
		t.Fatal("ephemeral key material retained")
	}
	_, err = f.recv.OpenEnvelope(capture)
	wantErr(t, err, ErrClosed)
	_, err = f.offer.AcceptHandshake(f.h, f.alice)
	wantErr(t, err, ErrReplayDetected)
	// Signing seeds can still reproduce the corresponding identities after
	// closure. Neither seed yields the captured message's AEAD key.
	for _, identity := range []*pqc.IdentityKeyPair{f.a, f.b} {
		leaked := identity.PrivateBytes()
		restored, err := pqc.ParseIdentityKeyPair(leaked)
		check(t, err)
		if !bytes.Equal(restored.PublicBytes(), identity.PublicBytes()) {
			t.Fatal("invalid exposure fixture")
		}
		session, err := pqc.DeriveSubkey(leaked, "session/v1")
		check(t, err)
		k, err := pqc.DeriveSubkey(session, envelopeDomain+string(number(capture.Header.MsgSeq)))
		check(t, err)
		if _, err := pqc.OpenAEAD(k, capture.Header.Nonce, capture.Ciphertext, aad(capture.Header, nil)); err == nil {
			t.Fatal("identity seed decrypted past message")
		}
	}
}
func TestChunkDelivery(t *testing.T) {
	for _, mode := range []string{"reordered", "missing", "ciphertext", "wrong index", "wrong transfer", "wrong total", "changed hash", "changed root", "signed wrong root", "final signature", "truncated finalize"} {
		t.Run(mode, func(t *testing.T) {
			f := setup(t)
			parts := [][]byte{[]byte("ab"), []byte("cd"), []byte("ef"), []byte("gh")}
			var hashes [][32]byte
			for _, p := range parts {
				hashes = append(hashes, sha256.Sum256(p))
			}
			root := RootManifest(hashes)
			if mode == "signed wrong root" {
				root[0] ^= 1
			}
			chunks := make([]*v1.EncryptedChunk, len(parts))
			for i, p := range parts {
				c, err := f.send.SealChunk("file", uint32(i), 4, root, p)
				check(t, err)
				chunks[i] = c
			}
			req, err := f.send.SignFinalizeTransfer("file", 4, root)
			check(t, err)
			asm, err := NewChunkAssembler(f.recv, "file", time.Now().Add(time.Minute))
			check(t, err)
			defer asm.Close()
			switch mode {
			case "ciphertext":
				chunks[1].Envelope.Ciphertext[0] ^= 1
			case "wrong index":
				chunks[1].ChunkIndex = 0
			case "wrong transfer":
				chunks[1].TransferId += "x"
			case "wrong total":
				chunks[1].TotalChunks++
			case "changed hash":
				chunks[1].ChunkHash[0] ^= 1
			case "changed root":
				chunks[1].RootManifestHash[0] ^= 1
			case "final signature":
				req.SenderSignature[0] ^= 1
			case "truncated finalize":
				req.TotalChunks--
			}
			for _, i := range []int{2, 0, 3, 1} {
				if i == 1 && mode == "missing" {
					continue
				}
				err = asm.Add(chunks[i])
				if err != nil {
					wantErr(t, err, ErrDeliveryFailed)
					break
				}
			}
			status, plain, err := asm.FinalizeTransfer(req)
			if mode == "reordered" {
				check(t, err)
				if status.Status != v1.DeliveryStatus_DELIVERY_STATUS_DELIVERED || string(plain) != "abcdefgh" {
					t.Fatal("incorrect delivery")
				}
			} else {
				wantErr(t, err, ErrDeliveryFailed)
				if status.Status != v1.DeliveryStatus_DELIVERY_STATUS_FAILED || plain != nil {
					t.Fatal("exposed partial transfer")
				}
			}
			if asm.parts != nil {
				t.Fatal("assembler retained chunks")
			}
			_, out, err := asm.FinalizeTransfer(req)
			wantErr(t, err, ErrDeliveryFailed)
			if out != nil {
				t.Fatal("duplicate delivery")
			}
		})
	}
}
func TestPeerBoundResumption(t *testing.T) {
	f := setup(t)
	key := make([]byte, 32)
	rand.Read(key)
	r, err := NewResumption(key)
	check(t, err)
	now := time.Now().UTC()
	r.now = func() time.Time { return now }
	ticket, err := r.IssueResumptionTicket(f.h.SessionId, f.alice, 7, now.Add(time.Hour))
	check(t, err)
	request := &v1.RequestResumeChallengeRequest{SessionId: f.h.SessionId, ResumptionTicket: ticket}
	challenge, err := r.IssueResumeChallenge(request, f.alice)
	check(t, err)
	resume, err := SignResumeSession(request.SessionId, ticket, challenge.ChallengeNonce, f.a)
	check(t, err)
	_, err = r.IssueResumeChallenge(request, f.bob)
	wantErr(t, err, ErrSessionIdentityMismatch)
	for _, p := range []Peer{f.bob, {f.alice.ID, "other-device", f.alice.SigningPublic}, {f.alice.ID, f.alice.DeviceID, f.bob.SigningPublic}} {
		_, err = r.VerifyResumeSession(resume, p)
		wantErr(t, err, ErrSessionIdentityMismatch)
	}
	impersonation, err := SignResumeSession(request.SessionId, ticket, challenge.ChallengeNonce, f.b)
	check(t, err)
	_, err = r.VerifyResumeSession(impersonation, f.alice)
	wantErr(t, err, ErrSessionIdentityMismatch)
	altered := proto.CloneOf(resume)
	altered.ResumptionTicket[0] ^= 1
	_, err = r.VerifyResumeSession(altered, f.alice)
	wantErr(t, err, ErrSessionIdentityMismatch)
	alternate, err := r.IssueResumptionTicket(f.h.SessionId, f.alice, 7, now.Add(time.Hour))
	check(t, err)
	swapped, err := SignResumeSession(request.SessionId, alternate, challenge.ChallengeNonce, f.a)
	check(t, err)
	_, err = r.VerifyResumeSession(swapped, f.alice)
	wantErr(t, err, ErrSessionIdentityMismatch)
	claims, err := r.VerifyResumeSession(resume, f.alice)
	check(t, err)
	if claims.KeyEpoch != 7 || claims.SessionID != f.h.SessionId || claims.Fingerprint != sha256.Sum256(f.alice.SigningPublic) {
		t.Fatal("unexpected claims")
	}
	_, err = r.VerifyResumeSession(resume, f.alice)
	wantErr(t, err, ErrReplayDetected)
	challenge, err = r.IssueResumeChallenge(request, f.alice)
	check(t, err)
	resume, err = SignResumeSession(request.SessionId, ticket, challenge.ChallengeNonce, f.a)
	check(t, err)
	now = challenge.ExpiresAt.AsTime()
	_, err = r.VerifyResumeSession(resume, f.alice)
	wantErr(t, err, ErrReplayDetected)
	now = claims.ExpiresAt
	_, err = r.IssueResumeChallenge(request, f.alice)
	wantErr(t, err, ErrSessionIdentityMismatch)
}
