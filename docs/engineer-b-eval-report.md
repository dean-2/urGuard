# Engineer B — Phase 2 & Phase 3 Evaluation Report

**Module:** `backend/detector/`, `backend/cmd/detector-eval/`, `backend/cmd/controlplane/`, `backend/cmd/node/`  
**Compliance:** Pure Go 1.24+ standard library — **zero AI/ML dependencies**, zero external packages (`backend/go.mod`, `backend/go.sum`).

---

## 1. Completed Integration & Telemetry Endpoints

- **Live Audit Adapter ([audit_adapter.go](file:///c:/Users/sahas/urGuard/backend/detector/audit_adapter.go)):** `NormalizeAuditEvent` converts canonical `AuditEvent` records into `NormalizedEvent` without mutating raw source timestamps or trusting user-supplied `Metadata`.
- **HTTP/JSON Telemetry Service ([telemetry_http.go](file:///c:/Users/sahas/urGuard/backend/detector/telemetry_http.go)):** Mounted in [controlplane/main.go](file:///c:/Users/sahas/urGuard/backend/cmd/controlplane/main.go) (`URGUARD_MAX_CLOCK_SKEW_SEC`, default `30`):
  - `GET /healthz`
  - `GET /api/v1/detector/alerts`
  - `GET /api/v1/detector/metrics`
  - `GET /api/v1/detector/graph`
  - `POST /api/v1/detector/ingest`

---

## 2. Verified Test & Benchmark Results

### Unit & Integration Suite (`go test -v ./detector/...`)
All 6 test suites passed:
- `TestPracticeDatasetEvaluation` — PASS (22 Track-4-Toolkit practice events, `0` false positives, `F1 >= 0.99`)
- `TestClockSkewAndOrderUncertainty` — PASS (`±60s` skew, `OrderUncertain: true`)
- `TestSynthetic1kBenchmark` — PASS (1,000 benign events + approved admin change + role escalation + 3-hop lateral movement + EWMA rate spike; `0` false positives, `F1 >= 0.99`)
- `TestConcurrentDisjointNodeDetection` — PASS (`GRAPH_CONCURRENT_DISJOINT_NODE`)
- `TestWatermarkLateArrivalAndReordering30s` — PASS (`±30s` watermark emission + `LateArrival: true`)
- `TestTelemetryServiceEndpointsAndAuditAdapter` — PASS (HTTP `/metrics`, `/alerts`, `/graph`, `/ingest` with crafted metadata)

### CLI Evaluation (`go run ./cmd/detector-eval`)
Verified at both `--skew=30s` and `--skew=60s` on `detector/testdata/events.csv`:
- **Precision:** `1.0000`
- **Recall:** `1.0000`
- **F1:** `1.0000`
- **Median Time to Alert:** `200.00 ms`
- **False Alerts per 1,000 Benign Events:** `0.00`

---

## 3. Evidence Sheet Mapping & Known Limits

| Objective | Status | Evidence | Limits |
|---|---|---|---|
| **6. Routine vs. Suspicious** | `measured` | `go run ./cmd/detector-eval` & `TestSynthetic1kBenchmark` | Evaluated on synthetic practice (22 events) and generated 1k benchmark; not production traffic. |
| **7. Lateral Movement** | `measured` | `TestPracticeDatasetEvaluation` (`evt-010..012`), `TestConcurrentDisjointNodeDetection` | Relies on configured role-to-service edge allowlists in `graph.go`. |
| **8. Clock Differences** | `measured` | `TestClockSkewAndOrderUncertainty` (`±60s`), `TestWatermarkLateArrivalAndReordering30s` (`±30s`) | Assumes clock drift within `±URGUARD_MAX_CLOCK_SKEW_SEC` and known `source_clock_offset_ms`. |
