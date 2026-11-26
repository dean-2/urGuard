package controlplane

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	v "github.com/dean-2/urGuard/backend/gen/urguard/v1"
	rpc "github.com/dean-2/urGuard/backend/gen/urguard/v1/urguardv1connect"
	"github.com/dean-2/urGuard/backend/internal/config"
	"github.com/dean-2/urGuard/backend/internal/transport"
	"github.com/dean-2/urGuard/backend/pkg/auditlog"
	"github.com/dean-2/urGuard/backend/pkg/pqc"
	"github.com/dean-2/urGuard/backend/pkg/store"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
	ts "google.golang.org/protobuf/types/known/timestamppb"
)

type Service struct {
	AccessDetector
	cfg     config.Config
	store   *store.Store
	log     *auditlog.Log
	witness rpc.AuditWitnessServiceClient
	mu      sync.Mutex
	notify  chan struct{}
	auditMu sync.Mutex
}

// New takes an already-open store; the caller owns its lifetime.
func New(ctx context.Context, c config.Config, st *store.Store, w rpc.AuditWitnessServiceClient, det AccessDetector) (*Service, error) {
	if det == nil {
		det = rpc.UnimplementedTelemetryServiceHandler{}
	}
	s := &Service{cfg: c, store: st, witness: w, notify: make(chan struct{}), AccessDetector: det}
	l, err := st.OpenAuditLog(c.CheckpointInterval)
	if err != nil {
		return nil, err
	}
	s.log = l
	enabled, err := l.WitnessEnabled()
	if err != nil {
		return nil, err
	}
	if w == nil {
		if enabled || c.WitnessURL != "" {
			return nil, errors.New("enrolled witness required")
		}
		return s, nil
	}
	latest, err := w.GetWitnessHead(ctx, connect.NewRequest(&v.GetWitnessHeadRequest{}))
	if err != nil {
		return nil, err
	}
	local, err := l.SignedHead()
	if err != nil {
		return nil, err
	}
	remote := latest.Msg.SignedHead
	if len(remote) == 0 {
		pub, err := st.AuthorityPublicKey()
		if err != nil {
			return nil, err
		}
		seq, _, err := auditlog.WitnessCheckpoint(local, pub, c.CheckpointInterval)
		if err != nil || seq != 0 || enabled {
			return nil, errors.New("missing enrolled witness history")
		}
		if _, err = w.AcceptWitnessHead(ctx, connect.NewRequest(&v.AcceptWitnessHeadRequest{SignedHead: local})); err != nil {
			return nil, err
		}
		remote = local
	}
	s.log, err = st.OpenWitnessedAuditLog(c.CheckpointInterval, remote)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(local, remote) && !enabled {
		return nil, errors.New("missing witness outbox")
	}
	if err = l.EnableWitness(); err != nil {
		return nil, err
	}
	if err = s.flush(ctx); err != nil {
		return nil, err
	}
	latest, err = w.GetWitnessHead(ctx, connect.NewRequest(&v.GetWitnessHeadRequest{}))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(local, latest.Msg.SignedHead) {
		return nil, errors.New("witness did not reach local head")
	}
	return s, nil
}
func (s *Service) flush(ctx context.Context) error {
	if s.witness == nil {
		return nil
	}
	for {
		seq, head, body, err := s.log.NextPending()
		if err != nil || seq == 0 {
			return err
		}
		_, err = s.witness.AcceptWitnessHead(ctx, connect.NewRequest(&v.AcceptWitnessHeadRequest{SignedHead: head, CanonicalEvent: body}))
		if err != nil {
			return err
		}
		if err = s.log.ConfirmPending(seq); err != nil {
			return err
		}
	}
}
func (s *Service) RetryPending(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.CRLHeartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.auditMu.Lock()
			attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
			_ = s.flush(attempt)
			cancel()
			s.auditMu.Unlock()
		}
	}
}
func (s *Service) auditHook(ctx context.Context, action, detail string) store.CommitHook {
	event := auditlog.Event{ActorID: transport.Principal(ctx), Action: action, UserText: detail}
	return func(tx *bolt.Tx) error { _, _, err := s.log.AppendInTx(tx, event); return err }
}

func (s *Service) audit(ctx context.Context, action, detail string) error {
	_, _, err := s.log.AppendWithCheckpoint(auditlog.Event{ActorID: transport.Principal(ctx), Action: action, UserText: detail})
	if err != nil {
		return err
	}
	return s.confirm(ctx)
}
func (s *Service) confirm(ctx context.Context) error {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.flush(attempt); err != nil {
		return connect.NewError(connect.CodeUnavailable, err)
	}
	return nil
}
func (s *Service) Mount(m *http.ServeMux) {
	m.Handle(rpc.NewCryptoControlServiceHandler(s))
	m.Handle(rpc.NewTelemetryServiceHandler(s))
}
func forbidden() error {
	return connect.NewError(connect.CodePermissionDenied, errors.New("principal not authorized"))
}
func (s *Service) signal() { close(s.notify); s.notify = make(chan struct{}) }
func phase(x store.EpochState) *v.EpochState {
	out := &v.EpochState{ActiveEpoch: x.Active, PreparedEpoch: x.Prepared, PreviousEpoch: x.Previous, Phase: v.RotationPhase_ROTATION_PHASE_IDLE}
	if !x.CommittedAt.IsZero() {
		out.CommittedAt = ts.New(x.CommittedAt)
		out.CutoffAt = ts.New(x.CutoffAt)
		out.Phase = v.RotationPhase_ROTATION_PHASE_COMMITTED
		if !time.Now().Before(x.CutoffAt) {
			out.Phase = v.RotationPhase_ROTATION_PHASE_CUTOFF_ENFORCED
		}
	}
	if x.Prepared != 0 {
		out.Phase = v.RotationPhase_ROTATION_PHASE_PREPARING
	}
	return out
}
func (s *Service) PrepareRotation(ctx context.Context, r *connect.Request[v.PrepareRotationRequest]) (*connect.Response[v.PrepareRotationResponse], error) {
	if transport.Principal(ctx) != "admin" {
		return nil, forbidden()
	}
	s.mu.Lock()
	x, err := s.store.BeginPrepareRotation(r.Msg.ExpectedActiveEpoch, s.auditHook(ctx, "ROTATION_PREPARED", ""))
	if err == nil {
		s.signal()
	}
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v.PrepareRotationResponse{State: phase(x)}), s.confirm(ctx)
}
func (s *Service) CommitRotation(ctx context.Context, r *connect.Request[v.CommitRotationRequest]) (*connect.Response[v.CommitRotationResponse], error) {
	if transport.Principal(ctx) != "admin" {
		return nil, forbidden()
	}
	s.mu.Lock()
	x, err := s.store.CommitPreparedRotation(r.Msg.PreparedEpoch, s.cfg.RotationGrace, s.auditHook(ctx, "ROTATION_COMMITTED", ""))
	if err == nil {
		s.signal()
	}
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v.CommitRotationResponse{State: phase(x)}), s.confirm(ctx)
}
func (s *Service) GetEpochState(ctx context.Context, r *connect.Request[v.GetEpochStateRequest]) (*connect.Response[v.GetEpochStateResponse], error) {
	x, err := s.store.EpochState()
	return connect.NewResponse(&v.GetEpochStateResponse{State: phase(x)}), err
}

var wire = proto.MarshalOptions{Deterministic: true}

func device(d *v.DeviceIdentity) store.Device {
	return store.Device{ID: d.DeviceId, OwnerID: d.OwnerId, KeyID: d.KeyId, SigningPublic: d.Mldsa65PublicKey, EncryptionPublic: pqc.HybridPublicKey{X25519: d.X25519PublicKey, MLKEM768: d.Mlkem768PublicKey}}
}
func (s *Service) EnrollDevice(ctx context.Context, r *connect.Request[v.EnrollDeviceRequest]) (*connect.Response[v.EnrollDeviceResponse], error) {
	if transport.Principal(ctx) != "admin" {
		return nil, forbidden()
	}
	d := r.Msg.Device
	body, err := wire.Marshal(d)
	if d == nil || err != nil || !pqc.VerifySignature(d.Mldsa65PublicKey, []byte("urguard/enroll/v1"), body, r.Msg.EnrollmentProof) {
		return nil, forbidden()
	}
	s.mu.Lock()
	err = s.store.UpsertDevice(device(d), s.auditHook(ctx, "DEVICE_ENROLLED", d.DeviceId))
	if err == nil {
		s.signal()
	}
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v.EnrollDeviceResponse{Device: d}), s.confirm(ctx)
}
func (s *Service) ReenrollDevice(ctx context.Context, r *connect.Request[v.ReenrollDeviceRequest]) (*connect.Response[v.ReenrollDeviceResponse], error) {
	if transport.Principal(ctx) != "admin" {
		return nil, forbidden()
	}
	m := r.Msg
	d := m.Replacement
	if d == nil || m.LostDeviceId == m.RecoveryDeviceId || d.DeviceId == m.LostDeviceId || d.DeviceId == m.RecoveryDeviceId {
		return nil, forbidden()
	}
	count, err := func() (int, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		old, err := s.store.GetDevice(m.LostDeviceId)
		if err != nil {
			return 0, err
		}
		recovery, err := s.store.GetDevice(m.RecoveryDeviceId)
		if err != nil {
			return 0, err
		}
		revoked, err := s.store.IsDeviceRevoked(recovery.ID)
		if err != nil {
			return 0, err
		}
		unsigned := proto.CloneOf(m)
		unsigned.RecoveryProof = nil
		body, err := wire.Marshal(unsigned)
		if err != nil || revoked || old.OwnerID != recovery.OwnerID || old.OwnerID != d.OwnerId || !pqc.VerifySignature(recovery.SigningPublic, []byte("urguard/recover/v1"), body, m.RecoveryProof) {
			return 0, forbidden()
		}
		n, err := s.store.ReplaceDevice(old.ID, device(d), s.auditHook(ctx, "DEVICE_REENROLLED", d.DeviceId))
		if err == nil {
			s.signal()
		}
		return n, err
	}()
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v.ReenrollDeviceResponse{Device: d, ResourcesRewrapped: uint64(count)}), s.confirm(ctx)
}
func rev(r store.Revocation) *v.Revocation {
	return &v.Revocation{CrlEpoch: r.CRLEpoch, RevokedDeviceId: r.DeviceID, RevokedKeyId: r.KeyID, IssuedAt: ts.New(r.IssuedAt)}
}
func (s *Service) RevokeDevice(ctx context.Context, r *connect.Request[v.RevokeDeviceRequest]) (*connect.Response[v.RevokeDeviceResponse], error) {
	if transport.Principal(ctx) != "admin" {
		return nil, forbidden()
	}
	s.mu.Lock()
	x, err := s.store.RevokeDevice(r.Msg.DeviceId, r.Msg.Reason, s.auditHook(ctx, "DEVICE_REVOKED", r.Msg.DeviceId))
	if err == nil {
		s.signal()
	}
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v.RevokeDeviceResponse{Revocation: rev(x)}), s.confirm(ctx)
}
func (s *Service) GetRevocationStatus(ctx context.Context, r *connect.Request[v.GetRevocationStatusRequest]) (*connect.Response[v.GetRevocationStatusResponse], error) {
	n := r.Msg.CrlEpoch
	if n == 0 {
		return nil, store.ErrNotFound
	}
	rs, err := s.store.ListRevocations(n - 1)
	if err != nil {
		return nil, err
	}
	if len(rs) == 0 {
		return nil, store.ErrNotFound
	}
	out := &v.GetRevocationStatusResponse{Revocation: rev(rs[0])}
	last := rs[0].IssuedAt
	complete := true
	for _, id := range s.cfg.RequiredNodes {
		a, err := s.store.AckAt(id, n)
		node := &v.NodeEnforcement{NodeId: id}
		if errors.Is(err, store.ErrNotFound) {
			complete = false
		} else if err != nil {
			return nil, err
		} else {
			node.EnforcedAt = ts.New(a.Enforced)
			node.AcknowledgedAt = ts.New(a.Received)
			if a.Received.After(last) {
				last = a.Received
			}
		}
		out.Nodes = append(out.Nodes, node)
	}
	if complete {
		ms := uint64(last.Sub(rs[0].IssuedAt).Milliseconds())
		out.RevocationPropagationMs = &ms
	}
	return connect.NewResponse(out), nil
}
func (s *Service) snapshot() (*v.StreamControlUpdatesResponse, error) {
	state, err := s.store.EpochState()
	if err != nil {
		return nil, err
	}
	u := &v.StreamControlUpdatesResponse{State: phase(state), IssuedAt: ts.Now()}
	rs, err := s.store.ListRevocations(0)
	if err != nil {
		return nil, err
	}
	for _, r := range rs {
		u.Revocations = append(u.Revocations, rev(r))
		u.CrlEpoch = r.CRLEpoch
	}
	ds, err := s.store.ListDevices()
	if err != nil {
		return nil, err
	}
	for _, d := range ds {
		u.Devices = append(u.Devices, &v.DeviceIdentity{DeviceId: d.ID, OwnerId: d.OwnerID, KeyId: d.KeyID, Mldsa65PublicKey: d.SigningPublic, X25519PublicKey: d.EncryptionPublic.X25519, Mlkem768PublicKey: d.EncryptionPublic.MLKEM768})
	}
	data, err := wire.Marshal(u)
	if err != nil {
		return nil, err
	}
	u.AuthoritySignature, err = s.store.SignControlUpdate(data)
	return u, err
}
func (s *Service) StreamControlUpdates(ctx context.Context, r *connect.Request[v.StreamControlUpdatesRequest], stream *connect.ServerStream[v.StreamControlUpdatesResponse]) error {
	if transport.Principal(ctx) != "node:"+r.Msg.NodeId {
		return forbidden()
	}
	ticker := time.NewTicker(s.cfg.CRLHeartbeat)
	defer ticker.Stop()
	for {
		s.mu.Lock()
		notify := s.notify
		u, err := s.snapshot()
		s.mu.Unlock()
		if err != nil {
			return err
		}
		if err = stream.Send(u); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-notify:
		case <-ticker.C:
		}
	}
}
func (s *Service) AckControlUpdate(ctx context.Context, r *connect.Request[v.AckControlUpdateRequest]) (*connect.Response[v.AckControlUpdateResponse], error) {
	m := r.Msg
	if transport.Principal(ctx) != "node:"+m.NodeId || m.EnforcedAt.CheckValid() != nil {
		return nil, forbidden()
	}
	x, err := s.store.EpochState()
	if err != nil {
		return nil, err
	}
	if m.KeyEpoch == 0 || m.KeyEpoch > x.Active {
		return nil, store.ErrConflict
	}
	err = s.store.RecordAck(store.NodeAck{Node: m.NodeId, Epoch: m.KeyEpoch, CRL: m.CrlEpoch, Enforced: m.EnforcedAt.AsTime(), Received: time.Now().UTC()})
	return connect.NewResponse(&v.AckControlUpdateResponse{}), err
}
func (s *Service) ExportBackup(ctx context.Context, _ *connect.Request[v.ExportBackupRequest]) (*connect.Response[v.ExportBackupResponse], error) {
	if transport.Principal(ctx) != "admin" {
		return nil, forbidden()
	}
	if s.cfg.BackupPassphrase == "" {
		return nil, errors.New("URGUARD_BACKUP_PASSPHRASE required")
	}
	data, err := s.store.ExportBackup([]byte(s.cfg.BackupPassphrase))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v.ExportBackupResponse{Bundle: data}), s.audit(ctx, "BACKUP_EXPORTED", "")
}
func (s *Service) RestoreBackup(ctx context.Context, r *connect.Request[v.RestoreBackupRequest]) (*connect.Response[v.RestoreBackupResponse], error) {
	if transport.Principal(ctx) != "admin" {
		return nil, forbidden()
	}
	if s.cfg.BackupPassphrase == "" {
		return nil, errors.New("URGUARD_BACKUP_PASSPHRASE required")
	}
	s.mu.Lock()
	err := s.store.RestoreBackup(r.Msg.Bundle, []byte(s.cfg.BackupPassphrase), s.auditHook(ctx, "BACKUP_RESTORED", ""))
	if err != nil {
		s.mu.Unlock()
		if errors.Is(err, store.ErrBackupCorrupted) || errors.Is(err, store.ErrConflict) {
			err = errors.Join(err, s.audit(ctx, "BACKUP_INTEGRITY_FAILURE", ""))
		}
		return nil, err
	}
	s.signal()
	u, err := s.snapshot()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v.RestoreBackupResponse{State: u.State, CrlEpoch: u.CrlEpoch}), s.confirm(ctx)
}
