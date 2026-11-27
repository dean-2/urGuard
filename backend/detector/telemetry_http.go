package detector

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// GraphEdgeSnapshot represents a service-to-service edge for the UI graph view.
type GraphEdgeSnapshot struct {
	Actor         string `json:"actor"`
	SourceService string `json:"source_service"`
	TargetService string `json:"target_service"`
	Count         int    `json:"count"`
	Flagged       bool   `json:"flagged"`
}

// TelemetryService exposes Engineer B's live detection alerts, lateral-movement graph,
// and evaluation KPIs over HTTP/JSON for Engineer C's operator console.
type TelemetryService struct {
	mu           sync.RWMutex
	maxSkew      time.Duration
	approvals    []ApprovalRule
	events       []NormalizedEvent
	verdicts     []EventVerdict
	alerts       []Alert
	metrics      EvalMetrics
	flaggedEdges map[string]bool
	receiptSeq   int64
}

// NewTelemetryService creates a thread-safe telemetry handler with the given skew window.
func NewTelemetryService(maxSkew time.Duration, approvals []ApprovalRule) *TelemetryService {
	if maxSkew <= 0 {
		maxSkew = 30 * time.Second
	}
	return &TelemetryService{
		maxSkew:      maxSkew,
		approvals:    approvals,
		flaggedEdges: make(map[string]bool),
	}
}

// RegisterRoutes mounts the detector telemetry endpoints on an http.ServeMux.
func (ts *TelemetryService) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/detector/alerts", ts.handleAlerts)
	mux.HandleFunc("/api/v1/detector/metrics", ts.handleMetrics)
	mux.HandleFunc("/api/v1/detector/graph", ts.handleGraph)
	mux.HandleFunc("/api/v1/detector/ingest", ts.handleIngest)
}

// IngestAuditEvents normalizes and processes canonical audit events through the detector.
func (ts *TelemetryService) IngestAuditEvents(auditEvents []AuditEvent, labels map[string]GroundTruthLabel) ([]EventVerdict, []Alert) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	for _, ae := range auditEvents {
		ts.receiptSeq++
		ts.events = append(ts.events, NormalizeAuditEvent(ae, ts.receiptSeq))
	}
	return ts.recomputeLocked(labels)
}

// LoadPracticeScenario processes a pre-normalized batch (e.g. Track-4-Toolkit practice data).
func (ts *TelemetryService) LoadPracticeScenario(events []NormalizedEvent, labels map[string]GroundTruthLabel) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	ts.events = append([]NormalizedEvent(nil), events...)
	ts.receiptSeq = int64(len(events))
	ts.recomputeLocked(labels)
}

func (ts *TelemetryService) recomputeLocked(labels map[string]GroundTruthLabel) ([]EventVerdict, []Alert) {
	det := NewDetector(ts.maxSkew, ts.approvals)
	verdicts, alerts := det.ProcessBatch(ts.events)
	ts.verdicts = verdicts
	ts.alerts = alerts

	ts.flaggedEdges = make(map[string]bool)
	for _, a := range alerts {
		for i := 0; i+1 < len(a.Services); i++ {
			key := a.Identity + "|" + a.Services[i] + "->" + a.Services[i+1]
			ts.flaggedEdges[key] = true
		}
	}

	if len(labels) > 0 {
		ts.metrics = EvaluateAgainstLabels(verdicts, alerts, labels)
	} else {
		ts.metrics = EvalMetrics{
			TotalEvents: len(verdicts),
		}
	}
	return verdicts, alerts
}

func (ts *TelemetryService) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"max_clock_skew_sec": ts.maxSkew.Seconds(),
		"alerts":             ts.alerts,
	})
}

func (ts *TelemetryService) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"max_clock_skew_sec": ts.maxSkew.Seconds(),
		"metrics":            ts.metrics,
	})
}

// GraphEdges returns a snapshot copy of all observed edges.
func (ts *TelemetryService) GraphEdges() []GraphEdgeSnapshot {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return ts.graphEdgesLocked()
}

// Snapshot returns thread-safe copies of alerts, evaluation metrics, graph edges, and skew window.
func (ts *TelemetryService) Snapshot() ([]Alert, EvalMetrics, []GraphEdgeSnapshot, time.Duration) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	alerts := append([]Alert(nil), ts.alerts...)
	return alerts, ts.metrics, ts.graphEdgesLocked(), ts.maxSkew
}

func (ts *TelemetryService) graphEdgesLocked() []GraphEdgeSnapshot {
	counts := make(map[string]int)
	edgeMeta := make(map[string]GraphEdgeSnapshot)
	for _, ev := range ts.events {
		if ev.SourceService == "" || ev.TargetService == "" {
			continue
		}
		key := ev.Actor + "|" + ev.SourceService + "->" + ev.TargetService
		counts[key]++
		edgeMeta[key] = GraphEdgeSnapshot{
			Actor:         ev.Actor,
			SourceService: ev.SourceService,
			TargetService: ev.TargetService,
			Count:         counts[key],
			Flagged:       ts.flaggedEdges[key],
		}
	}

	edges := make([]GraphEdgeSnapshot, 0, len(edgeMeta))
	for _, e := range edgeMeta {
		edges = append(edges, e)
	}
	return edges
}

func (ts *TelemetryService) handleGraph(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	edges := ts.GraphEdges()
	writeJSON(w, http.StatusOK, map[string]any{
		"edges": edges,
	})
}

func (ts *TelemetryService) handleIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var payload struct {
		Events []AuditEvent `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid json payload", http.StatusBadRequest)
		return
	}
	verdicts, alerts := ts.IngestAuditEvents(payload.Events, nil)
	writeJSON(w, http.StatusOK, map[string]any{
		"ingested": len(payload.Events),
		"verdicts": len(verdicts),
		"alerts":   alerts,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
