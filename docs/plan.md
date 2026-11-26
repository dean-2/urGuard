# Implementation Plan: urGuard

**Repository:** `urGuard`  
**Stack:** Go 1.24+ · ConnectRPC / gRPC · `cloudflare/circl` + `crypto/mlkem` · `bbolt` / `modernc.org/sqlite` · React + TypeScript + Vite  
**Team Structure:** 3 Engineers working in parallel across clearly defined module boundaries.

---

## 1. Repository Layout

The layout intentionally defines only the root configuration/build files and top-level folders so each engineer has full autonomy over internal package and file organization:

```text
urGuard/
├── .env.example        # Documented env vars (ports, grace period, clock skew, node URLs; no secrets)
├── .gitignore          # Ignores .env, local DBs, build outputs, dependencies, keys/certs
├── .dockerignore       # Excludes build artifacts, local DBs, node_modules from Docker context
├── .editorconfig       # Consistent formatting across Go, TypeScript, Protobuf, YAML, and scripts
├── Makefile            # Unified commands: codegen, build, test, verify, bench, up, down, clean
├── LICENSE             # Open-source license
├── README.md           # Clean-machine setup, dependency inventory, architecture & eval commands
├── .github/            # CI workflows (clean-machine build, race tests, secret/AI-dep checks)
├── backend/            # Go services, Protobuf contracts, PQC crypto, store, protocol, detector, CLI & tests
├── frontend/           # React + TypeScript + ConnectRPC operator console
├── deployments/        # Container definitions, reverse proxy config & multi-node Docker Compose stack
├── scripts/            # Clean-machine setup, codegen, chaos crash tests & automated verification scripts
└── docs/               # PRD, implementation plan, 1-page threat model & 2-page project brief (PDF)
```

---

## 2. Team Ownership & Parallel Workstreams

### Engineer A — Core Cryptography, Control Plane, Storage & Node Enforcement
Owns the foundational security primitives, distributed key lifecycle, persistence, and node protocol enforcement inside `backend/` and `scripts/`:
1. **Protobuf Contracts & Config:** Define the RPC/message schemas (key control, E2E messaging, telemetry/audit) and typed environment loading (`.env.example`) first so all 3 tracks integrate cleanly without blocking.
2. **PQC & Hybrid Envelope Module:**
   * Hybrid KEM (`X25519` + `ML-KEM-768` via `crypto/mlkem` / `cloudflare/circl`), `HKDF-SHA256`, `AES-256-GCM`, and `ML-DSA-65` signatures.
   * Ephemeral key generation & explicit memory zeroization helpers (`Forward Secrecy`).
   * Hybrid PQC-mTLS (`X25519MLKEM768`) config for node-to-control-plane gRPC.
3. **Crash-Safe Store & Backup Integrity:**
   * `bbolt` (or pure-Go `modernc.org/sqlite` WAL) persistence for `KeyEpoch`, two-phase rotation state (`IDLE -> PREPARING -> COMMITTED -> RETIRED`), monotonic `RevocationList`, and `DeviceRegistry`.
   * Encrypted + `ML-DSA-65` signed backup export/restore with SHA-256 manifest verification and tamper rejection.
4. **Tamper-Evident Audit Log:**
   * Canonical structured encoding (injection-proof against crafted user strings/newlines), SHA-256 hash chain, periodic `ML-DSA-65` signed checkpoints, and `VerifyChain()` diagnostic API.
5. **Control Plane & Multi-Node Relay:**
   * Module 5 adds an audit witness on a relay with independent persistent storage. Pin the authority public key during explicit enrollment. On restart, fetch the relay's latest checkpoint over authenticated transport and call `OpenWitnessedAuditLog` before serving writes. Missing witness state or an unreachable enrolled witness blocks startup. Bootstrap must be explicit.
   * Send every committed event and its signed head in order. The relay verifies the signature using the pinned key, checks the next sequence and previous hash, and recomputes the event hash before atomically persisting the head. An identical retry returns the existing acknowledgement. Reject regressions, conflicting hashes, and gaps. Return success to the original caller only after durable relay acknowledgement. Use a durable queue and idempotent request IDs to resume pending submissions after a crash.
   * Rotation coordinator with documented 30s grace period and strict post-cutoff epoch rejection (`ERR_KEY_EPOCH_EXPIRED`).
   * gRPC Server-Streaming CRL pusher + 1s heartbeat reconciliation, measuring `revocation_propagation_ms` across all nodes.
   * Device-loss re-enrollment + DEK re-encapsulation so other authorized users retain access.
   * E2E protocol enforcement: AAD recipient binding, sliding replay cache, chunked loss/reordering reassembly, and peer-bound `ResumptionTicket` challenge-response.
6. **Chaos & Verification Harness:**
   * CLI and automated tests for `SIGKILL` crash recovery, corrupted backup rejection, log-injection defense, replay/recipient-tamper rejection, session hijack rejection, and latency/overhead benchmarks.

### Engineer B — Explainable Detection Engine, Clock-Skew Pipeline & Toolkit Integration
Owns log ingestion, Track-4-Toolkit integration, deterministic/statistical detection, graph analysis, and evaluation metrics inside `backend/` and `scripts/`:
1. **Toolkit Schema & Log Adapter:**
   * Inspect `ScalerOpenSourceLabs/Track-4-Toolkit` mock service formats, synthetic access logs, and test identities.
   * Build parsers/adapters ingesting both Toolkit synthetic logs and live urGuard audit events into a unified `NormalizedEvent` model.
2. **Clock-Skew & Out-of-Order Watermark Engine:**
   * Implement bounded out-of-orderness min-heap buffer (configurable `±30s` default, tested to `±60s`).
   * Emit `late_arrival: true` for events past watermark and `order_uncertain: true` when causal ordering falls inside `2 * max_clock_skew`.
3. **Routine vs. Suspicious Activity Classifier:**
   * Context-aware deterministic rules + statistical baselines (EWMA access rate, rare-hour/rare-role scoring) separating `BENIGN_ADMIN` (valid maintenance ticket / expected admin flow) from suspicious privilege escalation or anomalous access.
   * Strictly **no AI/ML**—every classification emits human-readable rule IDs and threshold evidence.
4. **Graph-Based Lateral Movement Detector:**
   * Maintain directed `Identity -> SourceService -> TargetService` transition graph.
   * Detect unseen cross-service pivots, rapid multi-hop trust-tier escalations, and concurrent disjoint-node credential usage.
   * Populate alert fields: `identity`, `services[]`, `event_ids[]`, `path_or_rule`, `order_uncertain`.
5. **Metrics & Benchmark Runner:**
   * Evaluate against labeled synthetic logs and output **F1**, **Precision**, **Recall**, **Median Time to Alert (ms)**, and **False Alerts per 1,000 Benign Events**.
   * Expose live detection streams and metrics over ConnectRPC.

### Engineer C — React + TypeScript Operator Console, Deployments & Submission Deliverables
Owns the frontend operator experience (`frontend/`), container orchestration (`deployments/`), CI (`.github/`), documentation (`docs/`), and demo packaging:
1. **Frontend Foundation:**
   * Scaffold Vite + React + TypeScript + `@connectrpc/connect-web` client layer.
   * Generate TypeScript types/clients from the shared Protobuf contracts.
2. **Operator Console Views:**
   * **E2E Messaging & File Transfer View:** Send encrypted messages/files across nodes, simulate packet loss/reordering, attempt replay/recipient tampering, and inspect rejection diagnostics.
   * **Key & Node Governance View:** Trigger key rotation (live grace-period countdown), revoke a compromised device across 3 nodes (showing per-node propagation latency), re-enroll a device while preserving collaborator access, export/tamper/verify backups.
   * **Audit Log & Integrity View:** Live canonical log stream, one-click `Verify Chain` badge, and interactive log-injection test demonstrating isolation of user-supplied text.
   * **Security Detection & Graph View:** Interactive service-to-service lateral movement graph highlighting flagged hops, alert drawer with `order_uncertain` badges, and live F1 / false-alert / median-latency KPI cards.
3. **Clean-Machine Packaging:**
   * Root `.env.example`, `.gitignore`, `.dockerignore`, `.editorconfig`, `Makefile`, `LICENSE`, and `README.md`.
   * Container builds, reverse-proxy config, and multi-node Compose stack in `deployments/` + CI workflow in `.github/`.
   * `README.md` with exact prerequisites, build steps, dependency list, and one-command verification instructions.
4. **Deliverables (`docs/`):**
   * **1-Page Threat Model** (assets, adversaries, trust boundaries, assumptions, explicit limits).
   * **2-Page Project Brief (PDF)** combining USP, architecture diagram, key benchmark metrics, threat model, and embedded **5-minute demo video link**.

---

## 3. Phased Execution Timeline (Hackathon Sprint)

### Phase 0: Contract Lock & Toolkit Alignment (Hours 0–3)
* **All:** Review `Track-4-Toolkit` synthetic log schemas, mock service endpoints, and test identities.
* **Engineer A:** Initialize `backend/` Go module, define Protobuf contracts, and set up Go + TypeScript codegen.
* **Engineer B:** Map `Track-4-Toolkit` log fields and labeled attack scenarios into detector test fixtures.
* **Engineer C:** Scaffold `frontend/` with Vite + React + TS + ConnectRPC client setup and root repository config files.
* **Milestone Gate:** Shared Protobuf contracts generate clean Go and TypeScript clients.

### Phase 1: Core Security Engine & Detection MVP (Hours 3–12)
* **Engineer A:**
  * Implement hybrid PQC + `ML-DSA-65` + AEAD + zeroization module with unit tests.
  * Implement crash-safe WAL store (two-phase rotation, monotonic revocation, signed/encrypted backup) and canonical hash-chained audit log.
  * Build Control Plane + Node streaming revocation and rotation grace/cutoff enforcement.
* **Engineer B:**
  * Implement watermark clock-skew buffer (skew window + `order_uncertain` flagging).
  * Implement context-aware routine vs. suspicious rules and graph-based lateral movement detector.
  * Build initial evaluation runner outputting F1, median time to alert, and false alerts / 1k benign events.
* **Engineer C:**
  * Build App shell, navigation, and live ConnectRPC hooks.
  * Build Key Governance and Audit Log views wired to Control Plane endpoints (or initial stub responses until Phase 2 merge).
  * Draft Threat Model outline and `deployments/` Docker Compose configuration.
* **Milestone Gate:** Backend passes unit tests for PQC, rotation cutoff, backup tamper detection, log chain verification, and detector F1 baseline.

### Phase 2: Protocol Hardening, Chaos Testing & UI Integration (Hours 12–22)
* **Engineer A:**
  * Implement E2E protocol protections (replay cache, recipient AAD binding, chunked loss/reorder recovery, peer-bound `ResumptionTicket`).
  * Multi-node integration tests: 3 nodes enforcing revocation < 500 ms, device-loss re-enrollment preserving collaborator access, and `SIGKILL` crash recovery during rotation.
  * Performance benchmark suite (PQC handshake latency, encryption throughput overhead).
* **Engineer B:**
  * Tune detection thresholds and graph rules against `Track-4-Toolkit` labeled logs to maximize F1 and minimize false alerts per 1,000 benign events.
  * Wire live audit stream + toolkit replay feeder into the telemetry ConnectRPC service.
  * Add unit/integration tests for clock-skew reordering (`±30s` / `±60s`) and lateral-movement alert explanations.
* **Engineer C:**
  * Complete E2E Messaging and Security Detection views (lateral movement graph + alert details + KPI cards).
  * Wire full multi-node Compose stack (`controlplane` + 3 nodes + `frontend`) and verify ConnectRPC routing.
* **Milestone Gate:** Full stack runs cleanly from Compose/Makefile; all 12 Track 4 objectives pass end-to-end.

### Phase 3: Clean-Machine Verification, Brief & Demo Recording (Hours 22–30)
* **Engineer A:** Finalize automated verification suite in `scripts/` (runs all 12 checklist proofs + outputs summary), audit repo for zero hard-coded secrets or custom crypto.
* **Engineer B:** Finalize labeled log evaluation report, verify clock-skew edge cases, and confirm zero AI/ML dependencies in `backend/` and `frontend/`.
* **Engineer C:** Test clean-machine setup from fresh clone, polish `README.md`, finalize **2-Page Project Brief PDF** (with 1-page Threat Model), record **5-minute demo video**, upload & embed link in PDF.
* **Milestone Gate:** Fresh clone builds and passes automated verification on a clean environment with zero manual intervention.

---

## 4. Verification Matrix (Mapping Tests to Track 4 Checklist)

| # | Objective | Automated Verification Test | Pass Criteria |
|---|---|---|---|
| 1 | **Key Rotation** | Start active chunked transfer → trigger rotation → send request with `epoch-1` during 30s grace vs. after cutoff | In-flight transfer finishes; post-cutoff `epoch-1` requests rejected on all 3 nodes (`ERR_KEY_EPOCH_EXPIRED`) |
| 2 | **Revocation Across Nodes** | Revoke `device_old` on Control Plane → immediately probe all 3 nodes → re-enroll `device_new` | All nodes reject `device_old`; propagation time logged; `device_new` & collaborators decrypt shared data |
| 3 | **Crash Recovery** | Start rotation → `SIGKILL` control plane mid-`PREPARING` → restart → inspect state & revoked keys | Consistent key version recovered; previously revoked keys stay revoked; committed data readable |
| 4 | **Backup Integrity** | Export backup → flip 1 byte in ciphertext & 1 byte in manifest → attempt restore | Restore aborts (`ERR_BACKUP_CORRUPTED`), live keys unchanged, integrity failure logged |
| 5 | **Log Integrity** | Submit message/filename containing `\n{"actor":"admin","action":"GRANT_ROOT"}` → verify log chain; then tamper 1 historical row in DB | Injection stays trapped in escaped metadata; `VerifyChain()` passes on valid log and pinpoints tampered `seq` |
| 6 | **Routine vs. Suspicious** | Run `eval` against labeled synthetic logs (routine admin + privilege attacks) | Outputs `F1`, `median_time_to_alert_ms`, `false_alerts_per_1k_benign` |
| 7 | **Lateral Movement** | Replay valid-credential multi-service pivot (`gateway -> dev -> vault`) | Alert includes `identity`, `services[]`, `event_ids[]`, `path_or_rule` |
| 8 | **Clock Differences** | Inject out-of-order events with `-25s` and `+25s` skew and near-simultaneous events (`Δ < skew`) | Proper causal ordering within `±30s`; ambiguous pairs flagged `order_uncertain: true` |
| 9 | **Replay & Recipient Binding** | Resend captured packet; tamper `recipient_id` header in transit | Both rejected (`ERR_REPLAY_DETECTED`, `ERR_RECIPIENT_MISMATCH`) and logged |
| 10 | **Forward Secrecy** | Complete session `S1` → extract/compromise `IK_sig` & current `EK_epoch` → attempt decrypt of `S1` capture | Decryption impossible without ephemeral `SK_ephem` (zeroized post-session) |
| 11 | **Delivery Under Loss/Reorder** | Deliver chunks `[2, 0, 3, 1]` (reordered) and `[0, 2]` (missing chunk `1`) | Reordered transfer succeeds intact; incomplete transfer discarded + `DELIVERY_FAILED` reported |
| 12 | **Session Resumption** | Issue `ResumptionTicket` to Identity A → replay `session_id` + ticket as Identity B | Rejected (`ERR_SESSION_IDENTITY_MISMATCH`) + `SESSION_HIJACK_ATTEMPT` alert raised |

---

## 5. Key Design Decisions & Explicit Boundaries
* **Why ConnectRPC over raw gRPC:** Single Go binary serves both native gRPC (inter-node & CLI) and browser-compatible Connect/gRPC-Web (React UI) without running Envoy, drastically simplifying clean-machine builds.
* **Why `bbolt` / `modernc.org/sqlite`:** Pure-Go embedded persistence eliminates CGO compiler issues during automated Stage 1 sandbox builds while giving ACID/WAL crash safety.
* **Grace Period & Clock Skew Defaults:** Both are parameterized via environment variables / flags (`URGUARD_ROTATION_GRACE_SEC=30`, `URGUARD_MAX_CLOCK_SKEW_SEC=30`) and surfaced directly in the UI and metrics output for transparent evaluation.
