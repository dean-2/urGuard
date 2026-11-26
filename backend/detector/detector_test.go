package detector

import (
	"path/filepath"
	"testing"
	"time"
)

func TestPracticeDatasetEvaluation(t *testing.T) {
	events, err := LoadEventsCSV(filepath.Join("testdata", "events.csv"))
	if err != nil {
		t.Fatalf("LoadEventsCSV: %v", err)
	}
	approvals, err := LoadApprovalsJSON(filepath.Join("testdata", "approvals.json"))
	if err != nil {
		t.Fatalf("LoadApprovalsJSON: %v", err)
	}
	labels, err := LoadLabelsCSV(filepath.Join("testdata", "labels.csv"))
	if err != nil {
		t.Fatalf("LoadLabelsCSV: %v", err)
	}

	det := NewDetector(30*time.Second, approvals)
	verdicts, alerts := det.ProcessBatch(events)
	metrics := EvaluateAgainstLabels(verdicts, alerts, labels)

	if len(verdicts) != 22 {
		t.Fatalf("expected 22 verdicts, got %d", len(verdicts))
	}
	if metrics.F1 < 0.99 {
		t.Fatalf("expected F1 >= 0.99 on practice set, got %.3f (TP=%d FP=%d FN=%d)",
			metrics.F1, metrics.TruePositives, metrics.FalsePositives, metrics.FalseNegatives)
	}
	if metrics.FalsePositives != 0 {
		t.Fatalf("expected 0 false positives on practice set, got %d", metrics.FalsePositives)
	}

	// Verify evt-015 clock offset normalization preserves raw EventTimeUTC.
	for _, v := range verdicts {
		if v.Event.EventID == "evt-015" {
			wantAdj := time.Date(2026, 1, 15, 9, 6, 1, 0, time.UTC)
			if !v.Event.AdjustedTimeUTC.Equal(wantAdj) {
				t.Fatalf("evt-015 AdjustedTimeUTC = %v, want %v", v.Event.AdjustedTimeUTC, wantAdj)
			}
			if v.Event.CollectorDelayMs != 200 {
				t.Fatalf("evt-015 CollectorDelayMs = %d, want 200", v.Event.CollectorDelayMs)
			}
		}
	}
}

func TestClockSkewAndOrderUncertainty(t *testing.T) {
	base := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	events := []NormalizedEvent{
		{
			EventID:         "e-late-arrival",
			EventTimeUTC:    base.Add(-90 * time.Second),
			ReceivedTimeUTC: base,
			AdjustedTimeUTC: base.Add(-90 * time.Second),
			ReceiptSeq:      1,
			Actor:           "user-a",
			Action:          "read",
			Outcome:         "allow",
		},
		{
			EventID:         "e-head",
			EventTimeUTC:    base,
			ReceivedTimeUTC: base,
			AdjustedTimeUTC: base,
			ReceiptSeq:      2,
			Actor:           "user-a",
			Action:          "read",
			Outcome:         "allow",
		},
		{
			EventID:         "e-near-1",
			EventTimeUTC:    base.Add(-5 * time.Second),
			ReceivedTimeUTC: base.Add(1 * time.Second),
			AdjustedTimeUTC: base.Add(-5 * time.Second),
			ReceiptSeq:      3,
			Actor:           "user-b",
			SessionID:       "sess-b",
			Action:          "role_change",
			RoleBefore:      "viewer",
			RoleAfter:       "operator",
			Outcome:         "success",
		},
		{
			EventID:         "e-near-2",
			EventTimeUTC:    base.Add(-1 * time.Second),
			ReceivedTimeUTC: base.Add(2 * time.Second),
			AdjustedTimeUTC: base.Add(-1 * time.Second),
			ReceiptSeq:      4,
			Actor:           "user-b",
			SessionID:       "sess-b",
			SourceService:   "portal",
			TargetService:   "reports",
			Action:          "read",
			RoleBefore:      "operator",
			RoleAfter:       "operator",
			Outcome:         "allow",
		},
	}

	det := NewDetector(60*time.Second, nil)
	_, alerts := det.ProcessBatch(events)
	if len(alerts) == 0 {
		t.Fatalf("expected alerts for user-b")
	}
	if !alerts[0].OrderUncertain {
		t.Fatalf("expected OrderUncertain=true for events within 2*60s skew")
	}
}
