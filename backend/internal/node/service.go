package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	v "github.com/dean-2/urGuard/backend/gen/urguard/v1"
	rpc "github.com/dean-2/urGuard/backend/gen/urguard/v1/urguardv1connect"
	"github.com/dean-2/urGuard/backend/internal/config"
	"github.com/dean-2/urGuard/backend/internal/transport"
	"github.com/dean-2/urGuard/backend/pkg/auditlog"
	"github.com/dean-2/urGuard/backend/pkg/pqc"
	"github.com/dean-2/urGuard/backend/pkg/protocol"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
	ts "google.golang.org/protobuf/types/known/timestamppb"
)

var (
	ErrEpoch    = errors.New("ERR_KEY_EPOCH_EXPIRED")
	ErrRevoked  = errors.New("ERR_DEVICE_REVOKED")
	ErrUnsynced = errors.New("control snapshot unavailable")
)

type Service struct {
	cfg         config.Config
	pin         []byte
	db, witness *bolt.DB
	resume      *protocol.Resumption
	mu          sync.RWMutex
	update      *v.StreamControlUpdatesResponse
	peers       map[string]protocol.Peer
	revoked     map[string]bool
	liveUntil   time.Time
}

func Open(c config.Config, pin []byte) (*Service, error) {
	if len(pin) != mldsa65.PublicKeySize {
		return nil, errors.New("invalid authority pin")
	}
	a, _ := filepath.Abs(c.NodeDBPath)
	b, _ := filepath.Abs(c.WitnessDBPath)
	if a == b {
		return nil, errors.New("witness requires separate database")
	}
	db, err := bolt.Open(a, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	w, err := bolt.Open(b, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		db.Close()
		return nil, err
	}
	s := &Service{cfg: c, pin: bytes.Clone(pin), db: db, witness: w}
	err = w.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("audit_witness"))
		if err != nil {
			return err
		}
		p := b.Get([]byte("pinned_authority_pub"))
		if p != nil && !bytes.Equal(p, pin) {
			return errors.New("witness authority pin changed")
		}
		return b.Put([]byte("pinned_authority_pub"), pin)
	})
	if err != nil {
		s.Close()
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{"control", "offers", "consumed", "sessions", "inboxes", "transfers", "replay"} {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return err
			}
		}
		b := tx.Bucket([]byte("control"))
		k := b.Get([]byte("ticket"))
		if k == nil {
			k = make([]byte, 32)
			rand.Read(k)
			if err := b.Put([]byte("ticket"), k); err != nil {
				return err
			}
		}
		r, err := protocol.NewResumption(k)
		if err != nil {
			return err
		}
		s.resume = r
		if raw := b.Get([]byte("snapshot")); raw != nil {
			u := new(v.StreamControlUpdatesResponse)
			if err = proto.Unmarshal(raw, u); err != nil {
				return err
			}
			if err = s.verify(u); err != nil {
				return err
			}
			s.index(u)
		}
		return nil
	})
	if err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}
func (s *Service) Close() error { return errors.Join(s.db.Close(), s.witness.Close()) }
func (s *Service) Mount(m *http.ServeMux) {
	m.Handle(rpc.NewMessagingServiceHandler(s))
	m.Handle(rpc.NewAuditWitnessServiceHandler(s))
}
func denied() error {
	return connect.NewError(connect.CodePermissionDenied, protocol.ErrSessionIdentityMismatch)
}
func (s *Service) GetWitnessHead(ctx context.Context, _ *connect.Request[v.GetWitnessHeadRequest]) (*connect.Response[v.GetWitnessHeadResponse], error) {
	if transport.Principal(ctx) != "controlplane" {
		return nil, denied()
	}
	var head []byte
	err := s.witness.View(func(tx *bolt.Tx) error {
		head = bytes.Clone(tx.Bucket([]byte("audit_witness")).Get([]byte("latest_signed_head")))
		return nil
	})
	return connect.NewResponse(&v.GetWitnessHeadResponse{SignedHead: head}), err
}
func (s *Service) AcceptWitnessHead(ctx context.Context, r *connect.Request[v.AcceptWitnessHeadRequest]) (*connect.Response[v.AcceptWitnessHeadResponse], error) {
	if transport.Principal(ctx) != "controlplane" {
		return nil, denied()
	}
	m := r.Msg
	n, hash, err := auditlog.WitnessCheckpoint(m.SignedHead, s.pin, s.cfg.CheckpointInterval)
	if err != nil {
		return nil, err
	}
	err = s.witness.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("audit_witness"))
		last := b.Get([]byte("latest_signed_head"))
		if last == nil {
			if n != 0 || len(m.CanonicalEvent) != 0 {
				return errors.New("witness requires genesis")
			}
		} else {
			seq := b.Get([]byte("accepted_seq"))
			if len(seq) != 8 {
				return errors.New("invalid witness sequence")
			}
			old := binary.BigEndian.Uint64(seq)
			prev := string(b.Get([]byte("accepted_hash_hex")))
			if n == old && hash == prev && bytes.Equal(last, m.SignedHead) {
				return nil
			}
			if n <= old || n-old != 1 || !auditlog.CheckWitnessLink(n, prev, m.CanonicalEvent, hash) {
				return errors.New("witness continuity conflict")
			}
		}
		if err := b.Put([]byte("accepted_seq"), binary.BigEndian.AppendUint64(nil, n)); err != nil {
			return err
		}
		if err := b.Put([]byte("accepted_hash_hex"), []byte(hash)); err != nil {
			return err
		}
		return b.Put([]byte("latest_signed_head"), m.SignedHead)
	})
	return connect.NewResponse(&v.AcceptWitnessHeadResponse{}), err
}
func (s *Service) verify(u *v.StreamControlUpdatesResponse) error {
	unsigned := proto.CloneOf(u)
	unsigned.AuthoritySignature = nil
	body, err := (proto.MarshalOptions{Deterministic: true}).Marshal(unsigned)
	if err != nil || !pqc.VerifySignature(s.pin, []byte("urguard/control-update/v1"), body, u.AuthoritySignature) {
		return errors.New("invalid control signature")
	}
	if u.State.GetActiveEpoch() == 0 || u.IssuedAt.CheckValid() != nil || uint64(len(u.Revocations)) != u.CrlEpoch {
		return errors.New("invalid snapshot")
	}
	for i, r := range u.Revocations {
		if r.GetCrlEpoch() != uint64(i)+1 {
			return errors.New("noncontiguous revocations")
		}
	}
	return nil
}
func (s *Service) index(u *v.StreamControlUpdatesResponse) {
	s.update = u
	s.peers = map[string]protocol.Peer{}
	s.revoked = map[string]bool{}
	for _, d := range u.Devices {
		s.peers[d.DeviceId] = protocol.Peer{ID: d.OwnerId, DeviceID: d.DeviceId, SigningPublic: d.Mldsa65PublicKey}
	}
	for _, r := range u.Revocations {
		s.revoked[r.RevokedDeviceId] = true
	}
}
func (s *Service) apply(u *v.StreamControlUpdatesResponse) error {
	if err := s.verify(u); err != nil {
		return err
	}
	now := time.Now()
	if age := now.Sub(u.IssuedAt.AsTime()); age > s.cfg.MaxClockSkew+3*s.cfg.CRLHeartbeat || age < -s.cfg.MaxClockSkew {
		return errors.New("stale control snapshot")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if old := s.update; old != nil {
		if u.CrlEpoch < old.CrlEpoch || u.State.ActiveEpoch < old.State.ActiveEpoch || !u.IssuedAt.AsTime().After(old.IssuedAt.AsTime()) {
			return errors.New("control rollback")
		}
		for i, r := range old.Revocations {
			if !proto.Equal(r, u.Revocations[i]) {
				return errors.New("conflicting revocation")
			}
		}
	}
	raw, err := proto.Marshal(u)
	if err != nil {
		return err
	}
	if err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("control"))
		if err := b.Put([]byte("snapshot"), raw); err != nil {
			return err
		}
		// Save the enforcement timestamp alongside the snapshot. An interrupted
		// ACK is resent before processing another update, including after restart.
		return put(b, []byte("pending_ack"), &v.AckControlUpdateRequest{NodeId: s.cfg.NodeID, CrlEpoch: u.CrlEpoch, KeyEpoch: u.State.ActiveEpoch, EnforcedAt: ts.Now()})
	}); err != nil {
		return err
	}
	s.index(u)
	s.liveUntil = now.Add(3 * s.cfg.CRLHeartbeat)
	return nil
}

func (s *Service) ackPending(ctx context.Context, cp rpc.CryptoControlServiceClient) error {
	var pending []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		pending = bytes.Clone(tx.Bucket([]byte("control")).Get([]byte("pending_ack")))
		return nil
	})
	if err != nil || len(pending) == 0 {
		return err
	}
	var req v.AckControlUpdateRequest
	if err = proto.Unmarshal(pending, &req); err != nil {
		return err
	}
	attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err = cp.AckControlUpdate(attempt, connect.NewRequest(&req)); err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("control"))
		if bytes.Equal(b.Get([]byte("pending_ack")), pending) {
			return b.Delete([]byte("pending_ack"))
		}
		return nil
	})
}
func (s *Service) Sync(ctx context.Context, cp rpc.CryptoControlServiceClient) error {
	if err := s.ackPending(ctx, cp); err != nil {
		return err
	}
	s.mu.RLock()
	req := &v.StreamControlUpdatesRequest{NodeId: s.cfg.NodeID}
	if u := s.update; u != nil {
		req.LastCrlEpoch = u.CrlEpoch
		req.LastKeyEpoch = u.State.ActiveEpoch
	}
	s.mu.RUnlock()
	stream, err := cp.StreamControlUpdates(ctx, connect.NewRequest(req))
	if err != nil {
		return err
	}
	defer stream.Close()
	defer func() { s.mu.Lock(); s.liveUntil = time.Time{}; s.mu.Unlock() }()
	for stream.Receive() {
		u := stream.Msg()
		if err = s.apply(u); err != nil {
			return err
		}
		if err = s.ackPending(ctx, cp); err != nil {
			return err
		}
	}
	return stream.Err()
}
