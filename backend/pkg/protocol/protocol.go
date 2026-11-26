// Package protocol implements the endpoint operations behind the v1 messaging schema.
// Peer identities and verification keys must come from authenticated enrollment.
package protocol

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	v1 "github.com/dean-2/urGuard/backend/gen/urguard/v1"
	"github.com/dean-2/urGuard/backend/pkg/pqc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	ErrRecipientMismatch       = errors.New("ERR_RECIPIENT_MISMATCH")
	ErrReplayDetected          = errors.New("ERR_REPLAY_DETECTED")
	ErrDeliveryFailed          = errors.New("DELIVERY_FAILED")
	ErrSessionIdentityMismatch = errors.New("ERR_SESSION_IDENTITY_MISMATCH")
	ErrClosed                  = errors.New("session closed")
	errHandshake               = errors.New("invalid session handshake or offer")
)

const (
	offerDomain     = "urguard/v1/session-offer"
	handshakeDomain = "urguard/v1/session-handshake"
	envelopeDomain  = "urguard/v1/envelope"
	chunkDomain     = "urguard/v1/chunk"
	finalizeDomain  = "urguard/v1/finalize"
	resumeDomain    = "urguard/v1/resume"
	ticketDomain    = "urguard/v1/resumption-ticket"
)

type Peer struct {
	ID, DeviceID  string
	SigningPublic []byte
}

func validID(s string) bool { return s != "" && len(s) <= 1024 && utf8.ValidString(s) }
func (p Peer) valid() bool {
	return validID(p.ID) && validID(p.DeviceID) && len(p.SigningPublic) == mldsa65.PublicKeySize
}
func (p Peer) owns(k *pqc.IdentityKeyPair) bool {
	return k != nil && p.valid() && bytes.Equal(k.PublicBytes(), p.SigningPublic)
}
func number(n uint64) []byte { return binary.BigEndian.AppendUint64(nil, n) }

// frame encodes ordered fields with unsigned big-endian byte lengths.
func frame(fields ...[]byte) []byte {
	var out []byte
	for _, field := range fields {
		out = binary.BigEndian.AppendUint64(out, uint64(len(field)))
		out = append(out, field...)
	}
	return out
}
func stamp(t *timestamppb.Timestamp) []byte {
	return frame(number(uint64(t.GetSeconds())), number(uint64(t.GetNanos())))
}
func randomID() string {
	var id [16]byte
	rand.Read(id[:])
	return hex.EncodeToString(id[:])
}
func offerBody(o *v1.SessionOffer) []byte {
	return frame([]byte(o.OfferId), []byte(o.RecipientId), []byte(o.RecipientDeviceId), o.EphemeralX25519PublicKey, o.EphemeralMlkem768PublicKey, stamp(o.ExpiresAt))
}

type PendingOffer struct {
	mu    sync.Mutex
	offer *v1.SessionOffer
	key   *pqc.HybridKEMKeyPair
}

// Close releases an unused offer on cancellation or expiration.
func (p *PendingOffer) Close() { p.mu.Lock(); defer p.mu.Unlock(); p.destroy() }
func (p *PendingOffer) destroy() {
	if p.key != nil {
		p.key.Zeroize()
		p.key = nil
	}
}
func CreateSessionOffer(recipient Peer, signer *pqc.IdentityKeyPair, expires time.Time) (*v1.SessionOffer, *PendingOffer, error) {
	exp := timestamppb.New(expires)
	if !recipient.owns(signer) || exp.CheckValid() != nil || !expires.After(time.Now()) {
		return nil, nil, errHandshake
	}
	k, err := pqc.GenerateHybridKEMKeyPair()
	if err != nil {
		return nil, nil, err
	}
	pub := k.PublicKey()
	o := &v1.SessionOffer{OfferId: randomID(), RecipientId: recipient.ID, RecipientDeviceId: recipient.DeviceID, ExpiresAt: exp, EphemeralX25519PublicKey: pub.X25519, EphemeralMlkem768PublicKey: pub.MLKEM768}
	o.RecipientSignature, err = signer.Sign([]byte(offerDomain), offerBody(o))
	if err != nil {
		k.Zeroize()
		return nil, nil, err
	}
	return o, &PendingOffer{offer: proto.CloneOf(o), key: k}, nil
}
func VerifySessionOffer(o *v1.SessionOffer, recipient Peer) error {
	if !recipient.valid() || !validID(o.GetOfferId()) || o.GetRecipientId() != recipient.ID || o.GetRecipientDeviceId() != recipient.DeviceID || o.GetExpiresAt().CheckValid() != nil || !o.ExpiresAt.AsTime().After(time.Now()) ||
		!pqc.VerifySignature(recipient.SigningPublic, []byte(offerDomain), offerBody(o), o.RecipientSignature) {
		return errHandshake
	}
	return nil
}
func transcript(h *v1.SessionHandshake) []byte {
	o := h.Offer
	return frame([]byte(h.SessionId), []byte(o.OfferId), []byte(h.SenderId), []byte(h.SenderDeviceId), []byte(o.RecipientId), []byte(o.RecipientDeviceId), number(h.KeyEpoch))
}
func handshakeBody(h *v1.SessionHandshake) []byte {
	return frame(transcript(h), offerBody(h.Offer), h.Offer.RecipientSignature, h.EphemeralX25519PublicKey, h.Mlkem768Ciphertext)
}

// Session is one direction of communication, with one replay window scoped to
// its immutable session ID and sender. Keep one receiving Session per handshake.
type Session struct {
	mu                  sync.Mutex
	id                  string
	sender, recipient   Peer
	epoch               uint64
	key                 []byte
	signer              *pqc.IdentityKeyPair // sender endpoint only
	sent, highest, seen uint64
}

func newSession(h *v1.SessionHandshake, sender Peer, signer *pqc.IdentityKeyPair, shared []byte) (*Session, error) {
	defer pqc.Zeroize(shared)
	key, err := pqc.DeriveSubkey(shared, "session/v1")
	if err != nil {
		return nil, err
	}
	sender.SigningPublic = bytes.Clone(sender.SigningPublic)
	return &Session{id: h.SessionId, sender: sender, recipient: Peer{ID: h.Offer.RecipientId, DeviceID: h.Offer.RecipientDeviceId}, epoch: h.KeyEpoch, key: key, signer: signer}, nil
}
func CreateSessionHandshake(o *v1.SessionOffer, sender, recipient Peer, signer *pqc.IdentityKeyPair, epoch uint64) (*v1.SessionHandshake, *Session, error) {
	if !sender.owns(signer) || epoch == 0 {
		return nil, nil, errHandshake
	}
	if err := VerifySessionOffer(o, recipient); err != nil {
		return nil, nil, err
	}
	h := &v1.SessionHandshake{SessionId: randomID(), SenderId: sender.ID, SenderDeviceId: sender.DeviceID, Offer: proto.CloneOf(o), KeyEpoch: epoch}
	ct, shared, err := pqc.EncapsulateHybrid(pqc.HybridPublicKey{X25519: o.EphemeralX25519PublicKey, MLKEM768: o.EphemeralMlkem768PublicKey}, transcript(h))
	if err != nil {
		return nil, nil, err
	}
	h.EphemeralX25519PublicKey, h.Mlkem768Ciphertext = ct.EphemeralX25519, ct.MLKEM768
	h.SenderSignature, err = signer.Sign([]byte(handshakeDomain), handshakeBody(h))
	if err != nil {
		pqc.Zeroize(shared)
		return nil, nil, err
	}
	s, err := newSession(h, sender, signer, shared)
	return h, s, err
}
func (p *PendingOffer) AcceptHandshake(h *v1.SessionHandshake, sender Peer) (*Session, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.key == nil {
		return nil, ErrReplayDetected
	}
	if !p.offer.ExpiresAt.AsTime().After(time.Now()) {
		p.destroy()
		return nil, errHandshake
	}
	if !sender.valid() || !validID(h.GetSessionId()) || h.GetKeyEpoch() == 0 || sender.ID != h.SenderId || sender.DeviceID != h.SenderDeviceId || !proto.Equal(h.Offer, p.offer) ||
		!pqc.VerifySignature(sender.SigningPublic, []byte(handshakeDomain), handshakeBody(h), h.SenderSignature) {
		return nil, errHandshake
	}
	shared, err := p.key.DecapsulateHybrid(pqc.HybridCiphertext{EphemeralX25519: h.EphemeralX25519PublicKey, MLKEM768: h.Mlkem768Ciphertext}, transcript(h))
	if err != nil {
		return nil, err
	}
	p.destroy()
	return newSession(h, sender, nil, shared)
}
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	pqc.Zeroize(s.key)
	s.key = nil
	s.signer = nil
}

func aad(h *v1.EnvelopeHeader, metadata []byte) []byte {
	return frame([]byte(h.SenderId), []byte(h.SenderDeviceId), []byte(h.RecipientId), []byte(h.RecipientDeviceId), []byte(h.SessionId), number(h.KeyEpoch), number(h.MsgSeq), stamp(h.Timestamp), metadata)
}
func (s *Session) SealEnvelope(plaintext []byte) (*v1.EncryptedEnvelope, error) {
	return s.seal(plaintext, envelopeDomain, nil)
}
func (s *Session) seal(plain []byte, domain string, meta []byte) (*v1.EncryptedEnvelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == nil {
		return nil, ErrClosed
	}
	if s.signer == nil || s.sent == math.MaxUint64 {
		return nil, errors.New("session cannot send")
	}
	seq := s.sent + 1
	h := &v1.EnvelopeHeader{SenderId: s.sender.ID, SenderDeviceId: s.sender.DeviceID, RecipientId: s.recipient.ID, RecipientDeviceId: s.recipient.DeviceID, KeyEpoch: s.epoch, SessionId: s.id, MsgSeq: seq, Timestamp: timestamppb.Now()}
	a := aad(h, meta)
	key, err := pqc.DeriveSubkey(s.key, domain+string(number(seq)))
	if err != nil {
		return nil, err
	}
	defer pqc.Zeroize(key)
	nonce, ct, err := pqc.SealAEAD(key, plain, a)
	if err != nil {
		return nil, err
	}
	h.Nonce = nonce
	sig, err := s.signer.Sign([]byte(domain), frame(a, nonce, ct))
	if err != nil {
		return nil, err
	}
	s.sent = seq
	return &v1.EncryptedEnvelope{Header: h, Ciphertext: ct, SenderSignature: sig}, nil
}
func (s *Session) OpenEnvelope(e *v1.EncryptedEnvelope) ([]byte, error) {
	return s.open(e, envelopeDomain, nil)
}
func (s *Session) open(e *v1.EncryptedEnvelope, domain string, meta []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == nil {
		return nil, ErrClosed
	}
	h := e.GetHeader()
	if s.signer != nil || h == nil ||
		h.RecipientId != s.recipient.ID || h.RecipientDeviceId != s.recipient.DeviceID ||
		h.SenderId != s.sender.ID || h.SenderDeviceId != s.sender.DeviceID ||
		h.KeyEpoch != s.epoch || h.SessionId != s.id || h.Timestamp.CheckValid() != nil ||
		len(h.ProtoReflect().GetUnknown()) != 0 || len(h.Timestamp.ProtoReflect().GetUnknown()) != 0 {
		return nil, ErrRecipientMismatch
	}
	n := h.MsgSeq
	if n == 0 {
		return nil, ErrReplayDetected
	}
	a := aad(h, meta)
	if !pqc.VerifySignature(s.sender.SigningPublic, []byte(domain), frame(a, h.Nonce, e.Ciphertext), e.SenderSignature) {
		return nil, ErrRecipientMismatch
	}
	if n <= s.highest && (s.highest-n >= 64 || s.seen&(uint64(1)<<(s.highest-n)) != 0) {
		return nil, ErrReplayDetected
	}
	key, err := pqc.DeriveSubkey(s.key, domain+string(number(n)))
	if err != nil {
		return nil, err
	}
	defer pqc.Zeroize(key)
	plain, err := pqc.OpenAEAD(key, h.Nonce, e.Ciphertext, a)
	if err != nil {
		return nil, ErrRecipientMismatch
	}
	if n > s.highest {
		s.seen <<= n - s.highest
		s.highest = n
	}
	s.seen |= uint64(1) << (s.highest - n)
	return plain, nil
}

const (
	MaxChunks     = 64 // one replay window of contiguous messages
	MaxChunkBytes = 1 << 20
)

func chunkMeta(c *v1.EncryptedChunk) []byte {
	return frame([]byte(c.TransferId), number(uint64(c.ChunkIndex)), number(uint64(c.TotalChunks)), c.ChunkHash, c.RootManifestHash)
}

// RootManifest hashes the concatenation of the ordered, fixed-width SHA-256 digests.
func RootManifest(hashes [][sha256.Size]byte) []byte {
	h := sha256.New()
	for _, digest := range hashes {
		h.Write(digest[:])
	}
	return h.Sum(nil)
}
func (s *Session) SealChunk(id string, index, total uint32, root, plain []byte) (*v1.EncryptedChunk, error) {
	if !validID(id) || total > MaxChunks || index >= total || len(root) != sha256.Size || len(plain) > MaxChunkBytes {
		return nil, ErrDeliveryFailed
	}
	sum := sha256.Sum256(plain)
	c := &v1.EncryptedChunk{TransferId: id, ChunkIndex: index, TotalChunks: total, ChunkHash: sum[:], RootManifestHash: bytes.Clone(root)}
	e, err := s.seal(plain, chunkDomain, chunkMeta(c))
	if err != nil {
		return nil, err
	}
	c.Envelope = e
	return c, nil
}
func finalizeBody(r *v1.FinalizeTransferRequest) []byte {
	return frame([]byte(r.TransferId), []byte(r.SessionId), number(uint64(r.TotalChunks)), r.RootManifestHash)
}
func (s *Session) SignFinalizeTransfer(id string, total uint32, root []byte) (*v1.FinalizeTransferRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.signer == nil || s.key == nil || !validID(id) || total == 0 || total > MaxChunks || len(root) != sha256.Size {
		return nil, ErrDeliveryFailed
	}
	r := &v1.FinalizeTransferRequest{TransferId: id, SessionId: s.id, TotalChunks: total, RootManifestHash: bytes.Clone(root)}
	sig, err := s.signer.Sign([]byte(finalizeDomain), finalizeBody(r))
	if err != nil {
		return nil, err
	}
	r.SenderSignature = sig
	return r, nil
}

type chunkPart struct {
	plain []byte
	hash  [sha256.Size]byte
}
type ChunkAssembler struct {
	mu       sync.Mutex
	session  *Session
	id       string
	deadline time.Time
	root     []byte
	total    uint32
	parts    map[uint32]chunkPart
}

func NewChunkAssembler(session *Session, id string, deadline time.Time) (*ChunkAssembler, error) {
	if session == nil || !validID(id) || !deadline.After(time.Now()) {
		return nil, ErrDeliveryFailed
	}
	return &ChunkAssembler{session: session, id: id, deadline: deadline, parts: make(map[uint32]chunkPart)}, nil
}
func (a *ChunkAssembler) discard() {
	for _, p := range a.parts {
		pqc.Zeroize(p.plain)
	}
	a.parts = nil
}

// Close discards all buffered plaintext when the receiver cancels or times out.
func (a *ChunkAssembler) Close() { a.mu.Lock(); defer a.mu.Unlock(); a.discard() }
func (a *ChunkAssembler) Add(c *v1.EncryptedChunk) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.parts == nil || !time.Now().Before(a.deadline) || c.GetTransferId() != a.id || c.ChunkIndex >= c.TotalChunks || c.TotalChunks > MaxChunks || len(c.ChunkHash) != sha256.Size || len(c.RootManifestHash) != sha256.Size || len(c.Envelope.GetCiphertext()) > MaxChunkBytes+16 {
		a.discard()
		return ErrDeliveryFailed
	}
	_, duplicate := a.parts[c.ChunkIndex]
	if duplicate || (a.total != 0 && (a.total != c.TotalChunks || !bytes.Equal(a.root, c.RootManifestHash))) {
		a.discard()
		return ErrDeliveryFailed
	}
	plain, err := a.session.open(c.Envelope, chunkDomain, chunkMeta(c))
	if err != nil {
		a.discard()
		return errors.Join(ErrDeliveryFailed, err)
	}
	digest := sha256.Sum256(plain)
	if !bytes.Equal(digest[:], c.ChunkHash) {
		pqc.Zeroize(plain)
		a.discard()
		return ErrDeliveryFailed
	}
	if a.total == 0 {
		a.total = c.TotalChunks
		a.root = bytes.Clone(c.RootManifestHash)
	}
	a.parts[c.ChunkIndex] = chunkPart{plain, digest}
	return nil
}
func (a *ChunkAssembler) FinalizeTransfer(r *v1.FinalizeTransferRequest) (*v1.FinalizeTransferResponse, []byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	defer a.discard()
	s := a.session
	s.mu.Lock()
	defer s.mu.Unlock()
	failed := &v1.FinalizeTransferResponse{Status: v1.DeliveryStatus_DELIVERY_STATUS_FAILED}
	if a.parts == nil || s.key == nil || !time.Now().Before(a.deadline) || r.GetTransferId() != a.id || r.SessionId != s.id || a.total == 0 || r.TotalChunks != a.total || len(a.parts) != int(a.total) || !bytes.Equal(a.root, r.RootManifestHash) ||
		!pqc.VerifySignature(s.sender.SigningPublic, []byte(finalizeDomain), finalizeBody(r), r.SenderSignature) {
		return failed, nil, ErrDeliveryFailed
	}
	hashes := make([][sha256.Size]byte, a.total)
	size := 0
	for i := range hashes {
		p, ok := a.parts[uint32(i)]
		if !ok {
			return failed, nil, ErrDeliveryFailed
		}
		hashes[i] = sha256.Sum256(p.plain)
		if hashes[i] != p.hash {
			return failed, nil, ErrDeliveryFailed
		}
		size += len(p.plain)
	}
	if !bytes.Equal(RootManifest(hashes), a.root) {
		return failed, nil, ErrDeliveryFailed
	}
	out := make([]byte, 0, size)
	for i := range hashes {
		out = append(out, a.parts[uint32(i)].plain...)
	}
	return &v1.FinalizeTransferResponse{Status: v1.DeliveryStatus_DELIVERY_STATUS_DELIVERED}, out, nil
}

type TicketClaims struct {
	SessionID   string            `json:"session_id"`
	PeerID      string            `json:"peer_id"`
	DeviceID    string            `json:"peer_device_id"`
	Fingerprint [sha256.Size]byte `json:"peer_mldsa_pub_sha256"`
	KeyEpoch    uint64            `json:"key_epoch"`
	IssuedAt    time.Time         `json:"issued_at"`
	ExpiresAt   time.Time         `json:"expires_at"`
}
type resumeChallenge struct {
	ticket  [sha256.Size]byte
	expires time.Time
}
type Resumption struct {
	key     []byte
	mu      sync.Mutex
	pending map[[32]byte]resumeChallenge
	now     func() time.Time
}

func NewResumption(ticketKey []byte) (*Resumption, error) {
	if len(ticketKey) != 32 {
		return nil, errors.New("ticket key must be 32 bytes")
	}
	return &Resumption{key: bytes.Clone(ticketKey), pending: make(map[[32]byte]resumeChallenge), now: time.Now}, nil
}
func (r *Resumption) IssueResumptionTicket(sessionID string, peer Peer, epoch uint64, expires time.Time) ([]byte, error) {
	now := r.now().UTC()
	if !validID(sessionID) || !peer.valid() || epoch == 0 || !expires.After(now) {
		return nil, ErrSessionIdentityMismatch
	}
	claims := TicketClaims{sessionID, peer.ID, peer.DeviceID, sha256.Sum256(peer.SigningPublic), epoch, now, expires.UTC()}
	body, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	nonce, ct, err := pqc.SealAEAD(r.key, body, []byte(ticketDomain))
	if err != nil {
		return nil, err
	}
	return append(nonce, ct...), nil
}

// peer is the authenticated caller, independent of all request fields.
func (r *Resumption) claims(ticket []byte, sessionID string, peer Peer) (TicketClaims, error) {
	var c TicketClaims
	if !peer.valid() || len(ticket) < 12+16 || len(ticket) > 32768 {
		return c, ErrSessionIdentityMismatch
	}
	plain, err := pqc.OpenAEAD(r.key, ticket[:12], ticket[12:], []byte(ticketDomain))
	if err != nil {
		return c, ErrSessionIdentityMismatch
	}
	now := r.now()
	if json.Unmarshal(plain, &c) != nil || c.SessionID != sessionID || c.PeerID != peer.ID || c.DeviceID != peer.DeviceID || c.Fingerprint != sha256.Sum256(peer.SigningPublic) || c.KeyEpoch == 0 || c.IssuedAt.After(now) || !now.Before(c.ExpiresAt) {
		return TicketClaims{}, ErrSessionIdentityMismatch
	}
	return c, nil
}
func (r *Resumption) IssueResumeChallenge(req *v1.RequestResumeChallengeRequest, peer Peer) (*v1.RequestResumeChallengeResponse, error) {
	claims, err := r.claims(req.GetResumptionTicket(), req.GetSessionId(), peer)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	for n, c := range r.pending {
		if !now.Before(c.expires) {
			delete(r.pending, n)
		}
	}
	if len(r.pending) >= 4096 {
		return nil, errors.New("resume challenge capacity reached")
	}
	expires := now.Add(time.Minute)
	if claims.ExpiresAt.Before(expires) {
		expires = claims.ExpiresAt
	}
	var n [32]byte
	rand.Read(n[:])
	r.pending[n] = resumeChallenge{sha256.Sum256(req.ResumptionTicket), expires}
	return &v1.RequestResumeChallengeResponse{ChallengeNonce: n[:], ExpiresAt: timestamppb.New(expires)}, nil
}
func resumeBody(n []byte, id string, digest [32]byte) []byte { return frame(n, []byte(id), digest[:]) }
func SignResumeSession(id string, ticket, nonce []byte, signer *pqc.IdentityKeyPair) (*v1.ResumeSessionRequest, error) {
	if signer == nil || len(nonce) != 32 || !validID(id) {
		return nil, ErrSessionIdentityMismatch
	}
	sig, err := signer.Sign([]byte(resumeDomain), resumeBody(nonce, id, sha256.Sum256(ticket)))
	if err != nil {
		return nil, err
	}
	return &v1.ResumeSessionRequest{SessionId: id, ResumptionTicket: bytes.Clone(ticket), ChallengeNonce: bytes.Clone(nonce), PeerSignature: sig}, nil
}

// VerifyResumeSession authenticates resumption of a retained session. Tickets
// carry no encryption secret and cannot recreate the keys of a closed session.
func (r *Resumption) VerifyResumeSession(req *v1.ResumeSessionRequest, peer Peer) (TicketClaims, error) {
	c, err := r.claims(req.GetResumptionTicket(), req.GetSessionId(), peer)
	if err != nil {
		return TicketClaims{}, err
	}
	if len(req.ChallengeNonce) != 32 {
		return TicketClaims{}, ErrReplayDetected
	}
	digest := sha256.Sum256(req.ResumptionTicket)
	if !pqc.VerifySignature(peer.SigningPublic, []byte(resumeDomain), resumeBody(req.ChallengeNonce, req.SessionId, digest), req.PeerSignature) {
		return TicketClaims{}, ErrSessionIdentityMismatch
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := [32]byte(req.ChallengeNonce)
	pending, ok := r.pending[n]
	if !ok || !r.now().Before(pending.expires) {
		delete(r.pending, n)
		return TicketClaims{}, ErrReplayDetected
	}
	if digest != pending.ticket {
		return TicketClaims{}, ErrSessionIdentityMismatch
	}
	delete(r.pending, n)
	return c, nil
}
