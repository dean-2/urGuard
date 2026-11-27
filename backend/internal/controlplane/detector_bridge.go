package controlplane

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/dean-2/urGuard/backend/detector"
	v "github.com/dean-2/urGuard/backend/gen/urguard/v1"
	"github.com/dean-2/urGuard/backend/internal/transport"
	ts "google.golang.org/protobuf/types/known/timestamppb"
)

type auditObserver interface {
	ObserveAuditEvent(seq uint64, actorID, action, detail string, at time.Time)
}

// DetectorBridge adapts detector.TelemetryService to controlplane.AccessDetector.
type DetectorBridge struct {
	svc    *detector.TelemetryService
	labels map[string]detector.GroundTruthLabel

	mu        sync.Mutex
	seenAlert map[string]bool
	subs      map[chan *v.Alert]struct{}
}

// NewDetectorBridge constructs an explainable detector bridge and optionally
// seeds baseline approvals, events, and labels from dataDir if present.
func NewDetectorBridge(maxSkew time.Duration, dataDir string) (*DetectorBridge, error) {
	if maxSkew <= 0 {
		maxSkew = 30 * time.Second
	}

	var approvals []detector.ApprovalRule
	var events []detector.NormalizedEvent
	var labels map[string]detector.GroundTruthLabel

	if dataDir != "" {
		appPath := filepath.Join(dataDir, "approvals.json")
		if _, err := os.Stat(appPath); err == nil {
			approvals, err = detector.LoadApprovalsJSON(appPath)
			if err != nil {
				return nil, fmt.Errorf("load detector approvals: %w", err)
			}
		}
		evPath := filepath.Join(dataDir, "events.csv")
		if _, err := os.Stat(evPath); err == nil {
			events, err = detector.LoadEventsCSV(evPath)
			if err != nil {
				return nil, fmt.Errorf("load detector events: %w", err)
			}
		}
		lblPath := filepath.Join(dataDir, "labels.csv")
		if _, err := os.Stat(lblPath); err == nil {
			labels, err = detector.LoadLabelsCSV(lblPath)
			if err != nil {
				return nil, fmt.Errorf("load detector labels: %w", err)
			}
		}
	}

	svc := detector.NewTelemetryService(maxSkew, approvals)
	if len(events) > 0 {
		svc.LoadPracticeScenario(events, labels)
	}

	b := &DetectorBridge{
		svc:       svc,
		labels:    labels,
		seenAlert: make(map[string]bool),
		subs:      make(map[chan *v.Alert]struct{}),
	}
	alerts, _, _, _ := svc.Snapshot()
	for _, a := range alerts {
		b.seenAlert[a.AlertID] = true
	}
	return b, nil
}

// ResolveDetectorDataDir searches standard relative and container paths for detector testdata.
func ResolveDetectorDataDir() string {
	if explicit := os.Getenv("URGUARD_DETECTOR_DATA_DIR"); explicit != "" {
		return explicit
	}
	for _, candidate := range []string{
		"./detector/testdata",
		"../backend/detector/testdata",
		"./backend/detector/testdata",
		"/app/testdata",
	} {
		if info, err := os.Stat(filepath.Join(candidate, "events.csv")); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

// ObserveAuditEvent feeds a live control-plane audit event into the explainable detector.
func (b *DetectorBridge) ObserveAuditEvent(seq uint64, actorID, action, detail string, at time.Time) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	sourceSvc, targetSvc, outcome := classifyControlPlaneAction(action)
	ae := detector.AuditEvent{
		Seq:             int64(seq),
		EventID:         fmt.Sprintf("cp-%d", seq),
		EventTimeUTC:    at.UTC(),
		ReceivedTimeUTC: time.Now().UTC(),
		ActorID:         actorID,
		SourceService:   sourceSvc,
		TargetService:   targetSvc,
		Action:          action,
		Outcome:         outcome,
		Metadata:        map[string]string{"detail": detail},
	}
	_, alerts := b.svc.IngestAuditEvents([]detector.AuditEvent{ae}, b.labels)
	b.publishNewAlerts(alerts)
}

func classifyControlPlaneAction(action string) (sourceSvc, targetSvc, outcome string) {
	sourceSvc = "admin-console"
	targetSvc = "controlplane"
	outcome = "allow"
	switch action {
	case "BACKUP_INTEGRITY_FAILURE":
		outcome = "deny"
		targetSvc = "backup-vault"
	case "ROTATION_PREPARED", "ROTATION_COMMITTED":
		targetSvc = "key-authority"
	case "DEVICE_ENROLLED", "DEVICE_REENROLLED", "DEVICE_REVOKED":
		targetSvc = "identity"
	case "BACKUP_EXPORTED", "BACKUP_RESTORED":
		targetSvc = "backup-vault"
	}
	return sourceSvc, targetSvc, outcome
}

func (b *DetectorBridge) publishNewAlerts(alerts []detector.Alert) {
	b.mu.Lock()
	var fresh []*v.Alert
	for _, a := range alerts {
		if !b.seenAlert[a.AlertID] {
			b.seenAlert[a.AlertID] = true
			fresh = append(fresh, toProtoAlert(a))
		}
	}
	subs := make([]chan *v.Alert, 0, len(b.subs))
	for ch := range b.subs {
		subs = append(subs, ch)
	}
	b.mu.Unlock()

	for _, pa := range fresh {
		for _, ch := range subs {
			select {
			case ch <- pa:
			default:
			}
		}
	}
}

func (b *DetectorBridge) IngestAccessEvents(ctx context.Context, r *connect.Request[v.IngestAccessEventsRequest]) (*connect.Response[v.IngestAccessEventsResponse], error) {
	if transport.Principal(ctx) != "admin" {
		return nil, forbidden()
	}
	in := make([]detector.AuditEvent, 0, len(r.Msg.Events))
	for idx, ev := range r.Msg.Events {
		evTime := time.Now().UTC()
		if ev.EventTimestamp != nil {
			evTime = ev.EventTimestamp.AsTime().UTC()
		}
		rxTime := evTime
		if ev.IngestTimestamp != nil {
			rxTime = ev.IngestTimestamp.AsTime().UTC()
		}
		in = append(in, detector.AuditEvent{
			Seq:             int64(idx + 1),
			EventID:         ev.EventId,
			EventTimeUTC:    evTime,
			ReceivedTimeUTC: rxTime,
			ActorID:         ev.Identity,
			SourceService:   ev.SourceService,
			TargetService:   ev.TargetService,
			Action:          ev.Action,
			RoleAfter:       ev.Role,
			Outcome:         "allow",
			ApprovalID:      ev.ChangeTicket,
		})
	}
	_, alerts := b.svc.IngestAuditEvents(in, b.labels)
	b.publishNewAlerts(alerts)
	return connect.NewResponse(&v.IngestAccessEventsResponse{Accepted: uint64(len(in))}), nil
}

func (b *DetectorBridge) ListAlerts(ctx context.Context, r *connect.Request[v.ListAlertsRequest]) (*connect.Response[v.ListAlertsResponse], error) {
	if transport.Principal(ctx) != "admin" {
		return nil, forbidden()
	}
	alerts, _, _, _ := b.svc.Snapshot()
	start := 0
	if r.Msg.PageToken != "" {
		if idx, err := strconv.Atoi(r.Msg.PageToken); err == nil && idx >= 0 {
			start = idx
		}
	}
	limit := int(r.Msg.PageSize)
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	out := &v.ListAlertsResponse{}
	if start < len(alerts) {
		end := start + limit
		if end > len(alerts) {
			end = len(alerts)
		} else {
			out.NextPageToken = strconv.Itoa(end)
		}
		for _, a := range alerts[start:end] {
			out.Alerts = append(out.Alerts, toProtoAlert(a))
		}
	}
	return connect.NewResponse(out), nil
}

func (b *DetectorBridge) StreamAlerts(ctx context.Context, r *connect.Request[v.StreamAlertsRequest], stream *connect.ServerStream[v.StreamAlertsResponse]) error {
	if transport.Principal(ctx) != "admin" {
		return forbidden()
	}
	ch := make(chan *v.Alert, 64)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.subs, ch)
		b.mu.Unlock()
	}()

	alerts, _, _, _ := b.svc.Snapshot()
	sendAfter := r.Msg.AfterAlertId == ""
	for _, a := range alerts {
		if !sendAfter {
			if a.AlertID == r.Msg.AfterAlertId {
				sendAfter = true
			}
			continue
		}
		if err := stream.Send(&v.StreamAlertsResponse{Alert: toProtoAlert(a)}); err != nil {
			return err
		}
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case alert := <-ch:
			if err := stream.Send(&v.StreamAlertsResponse{Alert: alert}); err != nil {
				return err
			}
		}
	}
}

func (b *DetectorBridge) GetDetectionMetrics(ctx context.Context, _ *connect.Request[v.GetDetectionMetricsRequest]) (*connect.Response[v.GetDetectionMetricsResponse], error) {
	if transport.Principal(ctx) != "admin" {
		return nil, forbidden()
	}
	_, m, _, _ := b.svc.Snapshot()
	return connect.NewResponse(&v.GetDetectionMetricsResponse{
		Precision:                 m.Precision,
		Recall:                    m.Recall,
		F1:                        m.F1,
		MedianTimeToAlertMs:       m.MedianTimeToAlertMs,
		FalseAlertsPer_1000Benign: m.FalseAlertsPer1kBenign,
	}), nil
}

func (b *DetectorBridge) GetAccessGraph(ctx context.Context, _ *connect.Request[v.GetAccessGraphRequest]) (*connect.Response[v.GetAccessGraphResponse], error) {
	if transport.Principal(ctx) != "admin" {
		return nil, forbidden()
	}
	_, _, edges, _ := b.svc.Snapshot()
	out := &v.GetAccessGraphResponse{}
	for _, e := range edges {
		out.Edges = append(out.Edges, &v.AccessEdge{
			Identity:      e.Actor,
			SourceService: e.SourceService,
			TargetService: e.TargetService,
			ObservedCount: uint64(e.Count),
		})
	}
	return connect.NewResponse(out), nil
}

// Snapshot exposes full detector state (including flagged graph edges and skew window)
// for the operator console API.
func (b *DetectorBridge) Snapshot() ([]detector.Alert, detector.EvalMetrics, []detector.GraphEdgeSnapshot, time.Duration) {
	return b.svc.Snapshot()
}

func toProtoAlert(a detector.Alert) *v.Alert {
	out := &v.Alert{
		AlertId:         a.AlertID,
		Identity:        a.Identity,
		Services:        append([]string(nil), a.Services...),
		EventIds:        append([]string(nil), a.EventIDs...),
		PathOrRule:      a.PathOrRule,
		Explanation:     a.Explanation,
		ConfidenceScore: a.ConfidenceScore,
		OrderUncertain:  a.OrderUncertain,
		DetectedAt:      ts.New(a.DetectedAtUTC),
	}
	for _, alt := range a.PossibleOrderings {
		out.PossibleOrderings = append(out.PossibleOrderings, &v.EventOrdering{
			EventIds: []string{alt.FirstEventID, alt.SecondEventID},
		})
	}
	return out
}
