package controlplane

import (
	"context"
	"encoding/hex"
	"encoding/json"

	"connectrpc.com/connect"
	v "github.com/dean-2/urGuard/backend/gen/urguard/v1"
	"github.com/dean-2/urGuard/backend/internal/transport"
	"github.com/dean-2/urGuard/backend/pkg/auditlog"
	ts "google.golang.org/protobuf/types/known/timestamppb"
)

type AccessDetector interface {
	IngestAccessEvents(context.Context, *connect.Request[v.IngestAccessEventsRequest]) (*connect.Response[v.IngestAccessEventsResponse], error)
	ListAlerts(context.Context, *connect.Request[v.ListAlertsRequest]) (*connect.Response[v.ListAlertsResponse], error)
	StreamAlerts(context.Context, *connect.Request[v.StreamAlertsRequest], *connect.ServerStream[v.StreamAlertsResponse]) error
	GetDetectionMetrics(context.Context, *connect.Request[v.GetDetectionMetricsRequest]) (*connect.Response[v.GetDetectionMetricsResponse], error)
	GetAccessGraph(context.Context, *connect.Request[v.GetAccessGraphRequest]) (*connect.Response[v.GetAccessGraphResponse], error)
}

func (s *Service) ListAuditEvents(ctx context.Context, r *connect.Request[v.ListAuditEventsRequest]) (*connect.Response[v.ListAuditEventsResponse], error) {
	if transport.Principal(ctx) != "admin" {
		return nil, forbidden()
	}
	rows, err := s.log.List(r.Msg.FromSeq, r.Msg.Limit)
	if err != nil {
		return nil, err
	}
	out := &v.ListAuditEventsResponse{}
	for _, row := range rows {
		var e auditlog.Event
		if err = json.Unmarshal(row.CanonicalBody, &e); err != nil {
			return nil, err
		}
		prev, _ := hex.DecodeString(row.PrevHashHex)
		hash, _ := hex.DecodeString(row.EntryHashHex)
		out.Events = append(out.Events, &v.AuditEvent{Seq: row.Seq, PrevHash: prev, EntryHash: hash, CanonicalBody: row.CanonicalBody, Timestamp: ts.New(e.Timestamp), ActorId: e.ActorID, Action: e.Action, UserText: e.UserText})
		out.NextSeq = row.Seq + 1
	}
	return connect.NewResponse(out), nil
}
func (s *Service) VerifyAuditChain(ctx context.Context, _ *connect.Request[v.VerifyAuditChainRequest]) (*connect.Response[v.VerifyAuditChainResponse], error) {
	if transport.Principal(ctx) != "admin" {
		return nil, forbidden()
	}
	var report auditlog.Verification
	var err error
	if s.witness != nil {
		head, e := s.witness.GetWitnessHead(ctx, connect.NewRequest(&v.GetWitnessHeadRequest{}))
		if e != nil {
			return nil, e
		}
		report, err = s.log.VerifyAgainstCheckpoint(head.Msg.SignedHead)
	} else {
		report, err = s.log.VerifyChain()
	}
	if err != nil {
		return nil, err
	}
	out := &v.VerifyAuditChainResponse{Valid: report.Valid, Reason: report.Reason, CheckedEvents: report.CheckedEvents, CheckedCheckpoints: report.CheckedCheckpoints}
	if !report.Valid {
		out.BrokenSeq = &report.BrokenSeq
	}
	return connect.NewResponse(out), nil
}
