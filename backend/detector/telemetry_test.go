package detector

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestTelemetryServiceEndpointsAndAuditAdapter(t *testing.T) {
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

	ts := NewTelemetryService(30*time.Second, approvals)
	ts.LoadPracticeScenario(events, labels)

	mux := http.NewServeMux()
	ts.RegisterRoutes(mux)

	// 1. Check /api/v1/detector/metrics
	req := httptest.NewRequest(http.MethodGet, "/api/v1/detector/metrics", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics status = %d, want 200", rec.Code)
	}
	var metricsResp struct {
		Metrics EvalMetrics `json:"metrics"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &metricsResp); err != nil {
		t.Fatalf("decode metrics: %v", err)
	}
	if metricsResp.Metrics.F1 < 0.99 {
		t.Fatalf("expected F1 >= 0.99, got %.4f", metricsResp.Metrics.F1)
	}

	// 2. Check /api/v1/detector/alerts
	req = httptest.NewRequest(http.MethodGet, "/api/v1/detector/alerts", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /alerts status = %d, want 200", rec.Code)
	}

	// 3. Check /api/v1/detector/graph
	req = httptest.NewRequest(http.MethodGet, "/api/v1/detector/graph", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /graph status = %d, want 200", rec.Code)
	}
	var graphResp struct {
		Edges []GraphEdgeSnapshot `json:"edges"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &graphResp); err != nil {
		t.Fatalf("decode graph: %v", err)
	}
	flaggedCount := 0
	for _, e := range graphResp.Edges {
		if e.Flagged {
			flaggedCount++
		}
	}
	if flaggedCount == 0 {
		t.Fatalf("expected at least one flagged lateral-movement edge in graph")
	}

	// 4. Check POST /api/v1/detector/ingest with canonical AuditEvent (including crafted metadata)
	now := time.Date(2026, 2, 2, 12, 0, 0, 0, time.UTC)
	body, _ := json.Marshal(map[string]any{
		"events": []AuditEvent{
			{
				Seq:             9001,
				EventTimeUTC:    now,
				ReceivedTimeUTC: now.Add(50 * time.Millisecond),
				ActorID:         "user-mallory",
				SourceService:   "admin-console",
				TargetService:   "identity",
				Action:          "role_change",
				RoleBefore:      "viewer",
				RoleAfter:       "operator",
				Outcome:         "success",
				SessionID:       "sess-mallory",
				Metadata: map[string]string{
					"note": "\n{\"actor\":\"admin\",\"action\":\"GRANT_ROOT\"}",
				},
			},
		},
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/detector/ingest", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /ingest status = %d, want 200", rec.Code)
	}
}
