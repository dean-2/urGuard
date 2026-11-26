# Engineer B — Phase 0 & Phase 1 Summary

**Module:** `backend/detector/` (Explainable Detection Engine, Clock-Skew Pipeline & Toolkit Integration)  
**Stack:** Go 1.24+ (pure standard library — zero AI/ML, zero third-party dependencies)  
**Owned Track 4 Objectives:** #6 (Routine vs. Suspicious), #7 (Lateral Movement), #8 (Clock Differences) (`FR-11`, `FR-12`, `FR-13`)

---

## 1. What Was Built

### Phase 0: Contract Lock & Toolkit Fixtures
- Initialized Go module in [backend/go.mod](file:///c:/Users/sahas/urGuard/backend/go.mod).
- Copied Track-4-Toolkit practice fixtures into `backend/detector/testdata/`:
  - [events.csv](file:///c:/Users/sahas/urGuard/backend/detector/testdata/events.csv) (22 events in receipt order)
  - [approvals.json](file:///c:/Users/sahas/urGuard/backend/detector/testdata/approvals.json) (`change-100`, `change-101`)
  - [labels.csv](file:///c:/Users/sahas/urGuard/backend/detector/testdata/labels.csv) (used strictly for evaluation scoring, never in detection logic)

### Phase 1: Core Detection Engine MVP
| File | Responsibility | Requirement Mapping |
|---|---|---|
| [model.go](file:///c:/Users/sahas/urGuard/backend/detector/model.go) | `NormalizedEvent`, `ApprovalRule`, `Alert`, `EventVerdict`, `EvalMetrics`, `OrderAlternative`, and `Classification` constants | Shared schema |
| [adapter.go](file:///c:/Users/sahas/urGuard/backend/detector/adapter.go) | Parses `events.csv`, `approvals.json`, and `labels.csv`; preserves raw `EventTimeUTC` & `ReceivedTimeUTC` while computing `AdjustedTimeUTC` (`EventTimeUTC - SourceClockOffsetMs`) and `CollectorDelayMs` | `FR-13` (Clock Offset) |
| [watermark.go](file:///c:/Users/sahas/urGuard/backend/detector/watermark.go) | Min-heap `WatermarkBuffer` with configurable `MaxClockSkew` (`±30s` default, tested up to `±60s`), `LateArrival` flagging, and `DetectOrderUncertainty` for pairs within `2 * MaxClockSkew` | `FR-13` / Objective #8 |
| [rules.go](file:///c:/Users/sahas/urGuard/backend/detector/rules.go) | Deterministic `RuleEngine` + EWMA rate tracking: validates `approvals.json` (`ValidUntilUTC` exclusive), flags unapproved role escalations (`evt-008`) & post-escalation reads (`evt-009`), and separates post-revocation denials (`evt-017`, `evt-018`) and isolated denials (`evt-020`) | `FR-11` / Objective #6 |
| [graph.go](file:///c:/Users/sahas/urGuard/backend/detector/graph.go) | In-memory directed `Identity -> SourceService -> TargetService` `AccessGraph` with role allowlists; detects multi-hop unexpected pivots (`k >= 2` within `WindowW`, e.g., `evt-010 -> evt-011 -> evt-012`) while ignoring isolated single denials | `FR-12` / Objective #7 |
| [engine.go](file:///c:/Users/sahas/urGuard/backend/detector/engine.go) | `Detector.ProcessBatch` orchestrating watermark ordering, delayed-delivery detection (`evt-013`/`evt-014`), rule evaluation, graph pivot detection (excluding `ClassRoutineDenial`), and `OrderUncertain` annotations | `FR-11`, `FR-12`, `FR-13` |
| [eval.go](file:///c:/Users/sahas/urGuard/backend/detector/eval.go) | `EvaluateAgainstLabels` computing Precision, Recall, F1, Median Time to Alert (ms), and False Alerts per 1,000 Benign Events | `FR-11` Metrics |
| [detector_test.go](file:///c:/Users/sahas/urGuard/backend/detector/detector_test.go) | Unit tests for the 22-event practice dataset (`TestPracticeDatasetEvaluation`) and `±60s` clock-skew / `OrderUncertain` handling (`TestClockSkewAndOrderUncertainty`) | Verification #6, #7, #8 |

---

## 2. Verification Status

Command run in `backend/`:
```powershell
go test -v ./detector/...
```
Observed output:
```text
=== RUN   TestPracticeDatasetEvaluation
--- PASS: TestPracticeDatasetEvaluation (0.00s)
=== RUN   TestClockSkewAndOrderUncertainty
--- PASS: TestClockSkewAndOrderUncertainty (0.00s)
PASS
ok  	github.com/urguard/backend/detector	1.307s
```

- **Practice dataset (`22` events):** `0` false positives, `F1 >= 0.99`, and `evt-015` clock-offset normalization verified (`AdjustedTimeUTC = 2026-01-15T09:06:01Z`, `CollectorDelayMs = 200`).
- **Clock skew & ordering:** Out-of-order delivery (`evt-013`/`evt-014`) and `±60s` `OrderUncertain` flagging verified.

---

## 3. Next Steps (Phase 2)
1. **Expanded Synthetic Benchmarks & Tuning:** Generate larger labeled synthetic logs (routine admin bursts, EWMA rate spikes, `±30s`/`±60s` skew, concurrent disjoint-node usage) to tune thresholds and measure `false_alerts_per_1k_benign`.
2. **CLI Evaluation Runner (`backend/cmd/detector-eval/`):** Output JSON/table evaluation reports for the 2-Page Project Brief.
3. **Live Audit Adapter & ConnectRPC Telemetry:** Connect Engineer A's canonical audit stream and expose live alerts, graph hops, and KPI metrics for Engineer C's Security Detection & Graph View.
