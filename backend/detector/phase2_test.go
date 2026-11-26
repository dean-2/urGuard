package detector

import (
	"fmt"
	"testing"
	"time"
)

func TestSynthetic1kBenchmark(t *testing.T) {
	base := time.Date(2026, 2, 1, 8, 0, 0, 0, time.UTC)
	approvals := []ApprovalRule{
		{
			ApprovalID:    "chg-200",
			ApprovedBy:    "admin-1",
			Subject:       "eng-1",
			Operation:     "grant_role",
			Role:          "report-reader",
			Scope:         []string{"reports"},
			ValidFromUTC:  base,
			ValidUntilUTC: base.Add(2 * time.Hour),
		},
	}

	var events []NormalizedEvent
	labels := make(map[string]GroundTruthLabel)
	seq := int64(0)

	addEvent := func(ev NormalizedEvent, label string) {
		seq++
		ev.ReceiptSeq = seq
		ev.AdjustedTimeUTC = ev.EventTimeUTC.Add(-time.Duration(ev.SourceClockOffsetMs) * time.Millisecond)
		ev.CollectorDelayMs = ev.ReceivedTimeUTC.Sub(ev.AdjustedTimeUTC).Milliseconds()
		events = append(events, ev)
		labels[ev.EventID] = GroundTruthLabel{EventID: ev.EventID, Label: label}
	}

	// 1,000 benign events across 10 normal users (spaced 10s apart per user) + clock offsets.
	for i := 0; i < 1000; i++ {
		actor := fmt.Sprintf("user-%02d", i%10)
		ts := base.Add(time.Duration(i) * time.Second)
		offsetMs := int64(0)
		if i%25 == 0 {
			offsetMs = 1500
		}
		addEvent(NormalizedEvent{
			EventID:             fmt.Sprintf("syn-benign-%04d", i),
			EventTimeUTC:        ts.Add(time.Duration(offsetMs) * time.Millisecond),
			ReceivedTimeUTC:     ts.Add(150 * time.Millisecond),
			SourceClockOffsetMs: offsetMs,
			Actor:               actor,
			SourceService:       "portal",
			TargetService:       "catalog",
			Action:              "read",
			RoleBefore:          "viewer",
			RoleAfter:           "viewer",
			Outcome:             "allow",
			SessionID:           "sess-" + actor,
			CorrelationID:       fmt.Sprintf("flow-b-%04d", i),
		}, "routine")
	}

	// Approved role change (benign admin).
	addEvent(NormalizedEvent{
		EventID:         "syn-admin-1",
		EventTimeUTC:    base.Add(1100 * time.Second),
		ReceivedTimeUTC: base.Add(1100*time.Second + 100*time.Millisecond),
		Actor:           "eng-1",
		SourceService:   "admin-console",
		TargetService:   "identity",
		Action:          "role_change",
		RoleBefore:      "viewer",
		RoleAfter:       "report-reader",
		Outcome:         "success",
		ApprovalID:      "chg-200",
		SessionID:       "sess-eng-1",
		CorrelationID:   "flow-chg-200",
	}, "approved_change")

	// Inject attack 1: unapproved role escalation + follow-up read.
	addEvent(NormalizedEvent{
		EventID:         "syn-atk-esc-1",
		EventTimeUTC:    base.Add(1200 * time.Second),
		ReceivedTimeUTC: base.Add(1200*time.Second + 100*time.Millisecond),
		Actor:           "user-03",
		SourceService:   "admin-console",
		TargetService:   "identity",
		Action:          "role_change",
		RoleBefore:      "viewer",
		RoleAfter:       "operator",
		Outcome:         "success",
		SessionID:       "sess-user-03",
		CorrelationID:   "flow-atk-1",
	}, "unexpected_role_change")
	addEvent(NormalizedEvent{
		EventID:         "syn-atk-esc-2",
		EventTimeUTC:    base.Add(1202 * time.Second),
		ReceivedTimeUTC: base.Add(1202*time.Second + 100*time.Millisecond),
		Actor:           "user-03",
		SourceService:   "portal",
		TargetService:   "reports",
		Action:          "read",
		RoleBefore:      "operator",
		RoleAfter:       "operator",
		Outcome:         "allow",
		SessionID:       "sess-user-03",
		CorrelationID:   "flow-atk-1",
	}, "review_after_role_change")

	// Inject attack 2: 3-hop lateral movement pivot.
	pivots := [][2]string{{"reports", "billing"}, {"billing", "archive"}, {"archive", "identity"}}
	for idx, p := range pivots {
		ts := base.Add(time.Duration(1300+idx) * time.Second)
		addEvent(NormalizedEvent{
			EventID:         fmt.Sprintf("syn-atk-lm-%d", idx+1),
			EventTimeUTC:    ts,
			ReceivedTimeUTC: ts.Add(80 * time.Millisecond),
			Actor:           "svc-worker",
			SourceService:   p[0],
			TargetService:   p[1],
			Action:          "read",
			RoleBefore:      "service-reader",
			RoleAfter:       "service-reader",
			Outcome:         "deny",
			SessionID:       "sess-svc-worker",
			CorrelationID:   "flow-atk-lm",
		}, "lateral_movement_candidate")
	}

	// Inject attack 3: EWMA rate spike (50ms burst after 100 normal events for user-01).
	burstTS := base.Add(1400 * time.Second)
	addEvent(NormalizedEvent{
		EventID:         "syn-atk-rate-1",
		EventTimeUTC:    burstTS,
		ReceivedTimeUTC: burstTS.Add(50 * time.Millisecond),
		Actor:           "user-01",
		SourceService:   "portal",
		TargetService:   "catalog",
		Action:          "read",
		RoleBefore:      "viewer",
		RoleAfter:       "viewer",
		Outcome:         "allow",
		SessionID:       "sess-user-01",
		CorrelationID:   "flow-atk-rate",
	}, "routine")
	addEvent(NormalizedEvent{
		EventID:         "syn-atk-rate-2",
		EventTimeUTC:    burstTS.Add(20 * time.Millisecond),
		ReceivedTimeUTC: burstTS.Add(70 * time.Millisecond),
		Actor:           "user-01",
		SourceService:   "portal",
		TargetService:   "catalog",
		Action:          "read",
		RoleBefore:      "viewer",
		RoleAfter:       "viewer",
		Outcome:         "allow",
		SessionID:       "sess-user-01",
		CorrelationID:   "flow-atk-rate",
	}, "rate_anomaly")

	det := NewDetector(30*time.Second, approvals)
	verdicts, alerts := det.ProcessBatch(events)
	m := EvaluateAgainstLabels(verdicts, alerts, labels)

	if m.FalsePositives != 0 {
		t.Fatalf("expected 0 false positives across 1k benign events, got %d (false_alerts_per_1k=%.2f)", m.FalsePositives, m.FalseAlertsPer1kBenign)
	}
	if m.F1 < 0.99 {
		t.Fatalf("expected F1 >= 0.99 on 1k synthetic benchmark, got %.4f (TP=%d FP=%d FN=%d)", m.F1, m.TruePositives, m.FalsePositives, m.FalseNegatives)
	}
}

func TestConcurrentDisjointNodeDetection(t *testing.T) {
	base := time.Date(2026, 2, 1, 9, 0, 0, 0, time.UTC)
	events := []NormalizedEvent{
		{
			EventID:         "dj-1",
			EventTimeUTC:    base,
			ReceivedTimeUTC: base.Add(50 * time.Millisecond),
			AdjustedTimeUTC: base,
			ReceiptSeq:      1,
			Actor:           "user-kim",
			SourceService:   "portal",
			TargetService:   "catalog",
			Action:          "read",
			RoleBefore:      "viewer",
			RoleAfter:       "viewer",
			Outcome:         "allow",
			SessionID:       "sess-kim-1",
		},
		{
			EventID:         "dj-2",
			EventTimeUTC:    base.Add(2 * time.Second),
			ReceivedTimeUTC: base.Add(2*time.Second + 50*time.Millisecond),
			AdjustedTimeUTC: base.Add(2 * time.Second),
			ReceiptSeq:      2,
			Actor:           "user-kim",
			SourceService:   "enclave-b",
			TargetService:   "vault",
			Action:          "read",
			RoleBefore:      "viewer",
			RoleAfter:       "viewer",
			Outcome:         "allow",
			SessionID:       "sess-kim-2",
		},
	}

	det := NewDetector(30*time.Second, nil)
	_, alerts := det.ProcessBatch(events)
	found := false
	for _, a := range alerts {
		if a.PathOrRule == "GRAPH_CONCURRENT_DISJOINT_NODE" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected GRAPH_CONCURRENT_DISJOINT_NODE alert, got %+v", alerts)
	}
}

func TestWatermarkLateArrivalAndReordering30s(t *testing.T) {
	base := time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC)
	wb := NewWatermarkBuffer(30 * time.Second)

	// Event at t=0, then t=+40s (advances watermark to +40s, cutoff=+10s), then late arrival at t=-5s.
	_ = wb.Push(NormalizedEvent{EventID: "w-1", AdjustedTimeUTC: base, ReceiptSeq: 1})
	ready := wb.Push(NormalizedEvent{EventID: "w-2", AdjustedTimeUTC: base.Add(40 * time.Second), ReceiptSeq: 2})
	if len(ready) != 1 || ready[0].EventID != "w-1" {
		t.Fatalf("expected w-1 emitted after watermark passed +10s, got %+v", ready)
	}

	late := wb.Push(NormalizedEvent{EventID: "w-late", AdjustedTimeUTC: base.Add(-5 * time.Second), ReceiptSeq: 3})
	if len(late) != 1 || !late[0].LateArrival {
		t.Fatalf("expected w-late to be flagged LateArrival=true, got %+v", late)
	}
}
