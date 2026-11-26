package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	v "github.com/dean-2/urGuard/backend/gen/urguard/v1"
	"github.com/dean-2/urGuard/backend/internal/transport"
	"github.com/dean-2/urGuard/backend/pkg/protocol"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

func get(b *bolt.Bucket, id []byte, m proto.Message) error {
	raw := b.Get(id)
	if raw == nil {
		return connect.NewError(connect.CodeNotFound, errors.New("record not found"))
	}
	return proto.Unmarshal(raw, m)
}
func put(b *bolt.Bucket, id []byte, m proto.Message) error {
	raw, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	return b.Put(id, raw)
}
func (s *Service) peer(id string) (protocol.Peer, error) {
	if s.revoked[id] {
		return protocol.Peer{}, ErrRevoked
	}
	p, ok := s.peers[id]
	if !ok {
		return p, denied()
	}
	return p, nil
}
func (s *Service) run(ctx context.Context, fn func(*bolt.Tx, protocol.Peer) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.update == nil || !time.Now().Before(s.liveUntil) {
		return ErrUnsynced
	}
	id, ok := strings.CutPrefix(transport.Principal(ctx), "device:")
	if !ok {
		return denied()
	}
	caller, err := s.peer(id)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error { return fn(tx, caller) })
}
func (s *Service) epoch(epoch uint64, inflight bool) error {
	state := s.update.State
	if epoch == state.ActiveEpoch || inflight && epoch != 0 && epoch == state.PreviousEpoch && state.CutoffAt != nil && time.Now().Before(state.CutoffAt.AsTime()) {
		return nil
	}
	return ErrEpoch
}
func (s *Service) session(tx *bolt.Tx, id string, p protocol.Peer) (*v.SessionHandshake, error) {
	h := new(v.SessionHandshake)
	if err := get(tx.Bucket([]byte("sessions")), []byte(id), h); err != nil {
		return nil, err
	}
	if _, err := s.peer(h.SenderDeviceId); err != nil {
		return nil, err
	}
	if _, err := s.peer(h.Offer.RecipientDeviceId); err != nil {
		return nil, err
	}
	if h.SenderDeviceId != p.DeviceID || h.SenderId != p.ID {
		return nil, denied()
	}
	return h, s.epoch(h.KeyEpoch, true)
}
func (s *Service) PublishSessionOffer(ctx context.Context, r *connect.Request[v.PublishSessionOfferRequest]) (*connect.Response[v.PublishSessionOfferResponse], error) {
	err := s.run(ctx, func(tx *bolt.Tx, p protocol.Peer) error {
		o := r.Msg.Offer
		if err := protocol.VerifySessionOffer(o, p); err != nil {
			return err
		}
		if tx.Bucket([]byte("consumed")).Get([]byte(o.OfferId)) != nil {
			return protocol.ErrReplayDetected
		}
		return put(tx.Bucket([]byte("offers")), []byte(p.DeviceID), o)
	})
	return connect.NewResponse(&v.PublishSessionOfferResponse{}), err
}
func (s *Service) GetSessionOffer(ctx context.Context, r *connect.Request[v.GetSessionOfferRequest]) (*connect.Response[v.GetSessionOfferResponse], error) {
	o := new(v.SessionOffer)
	err := s.run(ctx, func(tx *bolt.Tx, _ protocol.Peer) error {
		p, err := s.peer(r.Msg.RecipientDeviceId)
		if err != nil {
			return err
		}
		if err = get(tx.Bucket([]byte("offers")), []byte(p.DeviceID), o); err != nil {
			return err
		}
		return protocol.VerifySessionOffer(o, p)
	})
	return connect.NewResponse(&v.GetSessionOfferResponse{Offer: o}), err
}
func enqueue(tx *bolt.Tx, id string, item *v.InboxItem) error {
	inbox, err := tx.Bucket([]byte("inboxes")).CreateBucketIfNotExists([]byte(id))
	if err != nil {
		return err
	}
	n, err := inbox.NextSequence()
	if err != nil {
		return err
	}
	item.MessageId = strconv.FormatUint(n, 10)
	return put(inbox, binary.BigEndian.AppendUint64(nil, n), item)
}
func (s *Service) OpenSession(ctx context.Context, r *connect.Request[v.OpenSessionRequest]) (*connect.Response[v.OpenSessionResponse], error) {
	out := new(v.OpenSessionResponse)
	h := r.Msg.Handshake
	err := s.run(ctx, func(tx *bolt.Tx, p protocol.Peer) error {
		if h.GetOffer() == nil {
			return denied()
		}
		peer, err := s.peer(h.Offer.RecipientDeviceId)
		if err != nil {
			return err
		}
		if err = s.epoch(h.KeyEpoch, false); err != nil {
			return err
		}
		if err = protocol.VerifyRelayHandshake(h, p, peer); err != nil {
			return err
		}
		sessions := tx.Bucket([]byte("sessions"))
		used := tx.Bucket([]byte("consumed"))
		id := []byte(h.Offer.OfferId)
		if sessions.Get([]byte(h.SessionId)) != nil || used.Get(id) != nil {
			return protocol.ErrReplayDetected
		}
		offers := tx.Bucket([]byte("offers"))
		published := new(v.SessionOffer)
		if err = get(offers, []byte(peer.DeviceID), published); err != nil || !proto.Equal(h.Offer, published) {
			return denied()
		}
		if err = put(sessions, []byte(h.SessionId), h); err != nil {
			return err
		}
		if err = used.Put(id, []byte{1}); err != nil {
			return err
		}
		if err = offers.Delete([]byte(peer.DeviceID)); err != nil {
			return err
		}
		out.SessionId = h.SessionId
		out.ResumptionTicket, err = s.resume.IssueResumptionTicket(h.SessionId, p, h.KeyEpoch, time.Now().Add(time.Hour))
		if err != nil {
			return err
		}
		return enqueue(tx, peer.DeviceID, &v.InboxItem{Payload: &v.InboxItem_Handshake{Handshake: h}})
	})
	return connect.NewResponse(out), err
}
func (s *Service) RequestResumeChallenge(ctx context.Context, r *connect.Request[v.RequestResumeChallengeRequest]) (*connect.Response[v.RequestResumeChallengeResponse], error) {
	var out *v.RequestResumeChallengeResponse
	err := s.run(ctx, func(tx *bolt.Tx, p protocol.Peer) error {
		if _, err := s.session(tx, r.Msg.SessionId, p); err != nil {
			return err
		}
		var err error
		out, err = s.resume.IssueResumeChallenge(r.Msg, p)
		return err
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(out), nil
}
func (s *Service) ResumeSession(ctx context.Context, r *connect.Request[v.ResumeSessionRequest]) (*connect.Response[v.ResumeSessionResponse], error) {
	out := new(v.ResumeSessionResponse)
	err := s.run(ctx, func(tx *bolt.Tx, p protocol.Peer) error {
		h, err := s.session(tx, r.Msg.SessionId, p)
		if err != nil {
			return err
		}
		c, err := s.resume.VerifyResumeSession(r.Msg, p)
		if err != nil {
			return err
		}
		if c.KeyEpoch != h.KeyEpoch {
			return denied()
		}
		out.ResumptionTicket, err = s.resume.IssueResumptionTicket(h.SessionId, p, h.KeyEpoch, time.Now().Add(time.Hour))
		return err
	})
	return connect.NewResponse(out), err
}

// One durable sliding window per one-way session. Update and delivery share the transaction.
func replay(tx *bolt.Tx, id string, n uint64) error {
	b := tx.Bucket([]byte("replay"))
	var high, mask uint64
	if raw := b.Get([]byte(id)); raw != nil {
		if len(raw) != 16 {
			return errors.New("invalid replay window")
		}
		high = binary.BigEndian.Uint64(raw)
		mask = binary.BigEndian.Uint64(raw[8:])
	}
	if n == 0 || n <= high && (high-n >= 64 || mask&(uint64(1)<<(high-n)) != 0) {
		return protocol.ErrReplayDetected
	}
	if n > high {
		mask <<= n - high
		high = n
	}
	mask |= uint64(1) << (high - n)
	return b.Put([]byte(id), binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(nil, high), mask))
}
func (s *Service) SendEnvelope(ctx context.Context, r *connect.Request[v.SendEnvelopeRequest]) (*connect.Response[v.SendEnvelopeResponse], error) {
	item := &v.InboxItem{Payload: &v.InboxItem_Envelope{Envelope: r.Msg.Envelope}}
	err := s.run(ctx, func(tx *bolt.Tx, p protocol.Peer) error {
		e := r.Msg.Envelope
		x := e.GetHeader()
		h, err := s.session(tx, x.GetSessionId(), p)
		if err != nil {
			return err
		}
		if err = protocol.VerifyRelayEnvelope(e, nil, h, p); err != nil {
			return err
		}
		if err = replay(tx, h.SessionId, x.MsgSeq); err != nil {
			return err
		}
		return enqueue(tx, h.Offer.RecipientDeviceId, item)
	})
	return connect.NewResponse(&v.SendEnvelopeResponse{MessageId: item.MessageId}), err
}
func transferKey(session, id string) []byte {
	return append(append(binary.BigEndian.AppendUint64(nil, uint64(len(session))), session...), id...)
}
func (s *Service) SendChunk(ctx context.Context, r *connect.Request[v.SendChunkRequest]) (*connect.Response[v.SendChunkResponse], error) {
	var rejected error
	err := s.run(ctx, func(tx *bolt.Tx, p protocol.Peer) error {
		c := r.Msg.Chunk
		x := c.GetEnvelope().GetHeader()
		h, err := s.session(tx, x.GetSessionId(), p)
		if err != nil {
			return err
		}
		groups := tx.Bucket([]byte("transfers"))
		id := transferKey(h.SessionId, c.GetTransferId())
		if len(id) > bolt.MaxKeySize {
			return protocol.ErrDeliveryFailed
		}
		if groups.Get(id) != nil {
			return protocol.ErrDeliveryFailed
		}
		g, err := groups.CreateBucketIfNotExists(id)
		if err != nil {
			return err
		}
		fail := func(e error) error {
			rejected = errors.Join(protocol.ErrDeliveryFailed, e)
			if err := groups.DeleteBucket(id); err != nil {
				return err
			}
			return groups.Put(id, []byte{1})
		}
		if err = protocol.VerifyRelayEnvelope(c.Envelope, c, h, p); err != nil {
			return fail(err)
		}
		if err = replay(tx, h.SessionId, x.MsgSeq); err != nil {
			return fail(err)
		}
		if g.Get([]byte("root")) == nil {
			if err = g.Put([]byte("root"), c.RootManifestHash); err != nil {
				return err
			}
			if err = g.SetSequence(uint64(c.TotalChunks)); err != nil {
				return err
			}
		}
		k := binary.BigEndian.AppendUint32(nil, c.ChunkIndex)
		if !bytes.Equal(g.Get([]byte("root")), c.RootManifestHash) || g.Sequence() != uint64(c.TotalChunks) || g.Get(k) != nil {
			return fail(protocol.ErrDeliveryFailed)
		}
		return put(g, k, c)
	})
	return connect.NewResponse(&v.SendChunkResponse{}), errors.Join(err, rejected)
}
func (s *Service) FinalizeTransfer(ctx context.Context, r *connect.Request[v.FinalizeTransferRequest]) (*connect.Response[v.FinalizeTransferResponse], error) {
	m := r.Msg
	out := &v.FinalizeTransferResponse{Status: v.DeliveryStatus_DELIVERY_STATUS_FAILED}
	err := s.run(ctx, func(tx *bolt.Tx, p protocol.Peer) error {
		h, err := s.session(tx, m.SessionId, p)
		if err != nil {
			return err
		}
		groups := tx.Bucket([]byte("transfers"))
		id := transferKey(h.SessionId, m.TransferId)
		g := groups.Bucket(id)
		if g == nil {
			return nil
		}
		discard := func() error {
			if err := groups.DeleteBucket(id); err != nil {
				return err
			}
			return groups.Put(id, []byte{1})
		}
		if !protocol.VerifyRelayFinalize(m, p) || g.Sequence() != uint64(m.TotalChunks) || !bytes.Equal(g.Get([]byte("root")), m.RootManifestHash) {
			return discard()
		}
		hashes := make([][32]byte, m.TotalChunks)
		parts := make([]*v.EncryptedChunk, m.TotalChunks)
		for i := range parts {
			c := new(v.EncryptedChunk)
			if get(g, binary.BigEndian.AppendUint32(nil, uint32(i)), c) != nil || c.ChunkIndex != uint32(i) || c.TransferId != m.TransferId || c.TotalChunks != m.TotalChunks || !bytes.Equal(c.RootManifestHash, m.RootManifestHash) || protocol.VerifyRelayEnvelope(c.Envelope, c, h, p) != nil {
				return discard()
			}
			hashes[i] = [sha256.Size]byte(c.ChunkHash)
			parts[i] = c
		}
		if !bytes.Equal(protocol.RootManifest(hashes), m.RootManifestHash) {
			return discard()
		}
		for _, c := range parts {
			if err := enqueue(tx, h.Offer.RecipientDeviceId, &v.InboxItem{Payload: &v.InboxItem_Chunk{Chunk: c}}); err != nil {
				return err
			}
		}
		if err := enqueue(tx, h.Offer.RecipientDeviceId, &v.InboxItem{Payload: &v.InboxItem_Finalized{Finalized: m}}); err != nil {
			return err
		}
		out.Status = v.DeliveryStatus_DELIVERY_STATUS_DELIVERED
		return discard()
	})
	return connect.NewResponse(out), err
}
func (s *Service) GetInbox(ctx context.Context, r *connect.Request[v.GetInboxRequest]) (*connect.Response[v.GetInboxResponse], error) {
	out := new(v.GetInboxResponse)
	err := s.run(ctx, func(tx *bolt.Tx, p protocol.Peer) error {
		if _, err := s.peer(r.Msg.RecipientDeviceId); err != nil {
			return err
		}
		if r.Msg.RecipientDeviceId != p.DeviceID {
			return denied()
		}
		page := r.Msg.PageSize
		if page == 0 || page > 100 {
			page = 100
		}
		start := uint64(1)
		var err error
		if r.Msg.PageToken != "" {
			start, err = strconv.ParseUint(r.Msg.PageToken, 10, 64)
			if err != nil {
				return err
			}
		}
		inbox := tx.Bucket([]byte("inboxes")).Bucket([]byte(p.DeviceID))
		if inbox == nil {
			return nil
		}
		c := inbox.Cursor()
		for k, data := c.Seek(binary.BigEndian.AppendUint64(nil, start)); k != nil; k, data = c.Next() {
			item := new(v.InboxItem)
			if err := proto.Unmarshal(data, item); err != nil {
				return err
			}
			var id string
			switch x := item.Payload.(type) {
			case *v.InboxItem_Handshake:
				id = x.Handshake.SessionId
			case *v.InboxItem_Envelope:
				id = x.Envelope.GetHeader().GetSessionId()
			case *v.InboxItem_Chunk:
				id = x.Chunk.GetEnvelope().GetHeader().GetSessionId()
			case *v.InboxItem_Finalized:
				id = x.Finalized.SessionId
			default:
				return errors.New("unknown inbox payload")
			}
			h := new(v.SessionHandshake)
			if err := get(tx.Bucket([]byte("sessions")), []byte(id), h); err != nil {
				return err
			}
			if s.revoked[h.SenderDeviceId] || s.epoch(h.KeyEpoch, true) != nil {
				continue
			}
			if len(out.Items) >= int(page) {
				out.NextPageToken = strconv.FormatUint(binary.BigEndian.Uint64(k), 10)
				break
			}
			out.Items = append(out.Items, item)
		}
		return nil
	})
	return connect.NewResponse(out), err
}
