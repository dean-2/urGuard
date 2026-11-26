# urGuard 5-Minute Live Demo Script

**Total Runtime:** `5:00` · **Targets:** All 12 Track 4 Checklist Objectives in the Operator Console UI

---

## `0:00 – 0:30` · Introduction & Multi-Node Cluster Health
- **Show:** Browser open at `/` (`urGuard` Operator Console).
- **Point out:** Left sidebar (`Messaging`, `Key Governance`, `Audit Log`, `Detection`) and top health strip (`controlplane: READY`, `node-a`, `node-b`, `node-c` with active key epoch and CRL epoch).
- **Talk track:** Explain urGuard's USP: hybrid PQC transport + E2E (`X25519 + ML-KEM-768`, `AES-256-GCM`, `ML-DSA-65`), crash-safe key governance, and zero-AI/ML explainable detection.

## `0:30 – 1:25` · E2E Messaging, Loss/Reorder, Replay, Recipient Binding & Session Hijack (`#9, #10, #11, #12`)
- **View:** **Messaging** (`/`).
- **Action 1 (`#11` Reorder & Loss):**
  - Click **Reorder chunks `[2,0,3,1]`** → point out `DELIVERED`, chunk visualiser arrival order `[2, 0, 3, 1]`, and `SK_ephem: ZEROIZED` (`#10` Forward Secrecy).
  - Click **Drop chunk 1 of `[0,1,2]`** → point out **`DELIVERY_FAILED`**, chunk #1 `MISSING`, and **Plaintext Withheld** (no partial plaintext exposed).
- **Action 2 (`#9` Replay & Recipient Binding):**
  - Click **Replay captured envelope** → point out **`ERR_REPLAY_DETECTED`** and matching `REPLAY_REJECTED` audit record.
  - Click **Tamper recipient_id** → point out **`ERR_RECIPIENT_MISMATCH`** and matching `RECIPIENT_BINDING_FAILED` audit record.
- **Action 3 (`#12` Session Resumption Binding):**
  - Click **Resume session as different identity** → point out **`ERR_SESSION_IDENTITY_MISMATCH`**, `SESSION_HIJACK_ATTEMPT` audit event, and `PROTOCOL_ATTACK` alert.

## `1:25 – 2:45` · Key Rotation, Multi-Node Revocation, Crash Recovery & Backup Integrity (`#1, #2, #3, #4`)
- **View:** **Key Governance** (`/governance`).
- **Action 1 (`#1` Key Rotation & Grace Period):**
  - Click **Rotate key** → show two-phase stepper (`IDLE → PREPARING → COMMITTED`), new epoch active, and **live `30s` grace-period countdown**.
  - Click **Enforce cutoff now** (or let timer hit `0`) → stepper moves to **`CUTOFF_ENFORCED`** (older epochs rejected with `ERR_KEY_EPOCH_EXPIRED`).
- **Action 2 (`#2` Revocation & Device-Loss Re-Enrollment):**
  - Select `dev-alice-laptop`, click **Revoke device** → show staggered per-node ack table (`node-a`, `node-b`, `node-c`) and **`revocation_propagation_ms` (`< 500 ms`)**.
  - Under **Device Loss Re-Enrollment**, click **Re-enroll device** → show active devices holding re-encapsulated DEKs (`device_new` + collaborators) with `dev-alice-laptop` marked **`EXCLUDED (REVOKED)`**.
- **Action 3 (`#4` Backup Integrity):**
  - Click **Export Backup** → click **Tamper 1 byte** (`1-BYTE TAMPERED`) → click **Restore Backup** → point out **`ERR_BACKUP_CORRUPTED`**, failed `AES-GCM Tag` / `SHA-256 Manifest` badges, and confirm live key epoch remained untouched.
- **Terminal / CLI Callout (`#3` Crash Recovery):**
  - Mention or show `make verify` output proving `SIGKILL` during `PREPARING` recovers consistent key state while preserving monotonic revoked keys.

## `2:45 – 3:35` · Tamper-Evident & Injection-Proof Audit Log (`#5`)
- **View:** **Audit Log** (`/audit`).
- **Action 1 (Log Injection Defense):**
  - Point out pre-filled payload `\n{"actor":"admin","action":"GRANT_ROOT"}` under `guest@urguard.local`, click **Submit Injection Test**.
  - Show expanded row: `actor_id` stays `guest@urguard.local`, `action` stays `USER_METADATA_SUBMITTED`, and the crafted string stays escaped inside plain-text `payload.metadata`.
- **Action 2 (`Verify Chain` & DB Tamper Detection):**
  - Click **Verify Chain** → green **`CHAIN VALID`** badge.
  - Set `Tamper seq` to `2`, click **Simulate DB Tamper**, then click **Verify Chain** → red **`CHAIN BROKEN at seq 2`** badge pinpointing the exact altered record.

## `3:35 – 4:35` · Explainable Detection, Lateral Movement Graph & Clock Skew (`#6, #7, #8`)
- **View:** **Detection** (`/detection`).
- **Point out (`#6` Metrics):** KPI cards at top (`Precision`, `Recall`, `F1 Score`, `Median Time to Alert`, `False Alerts / 1k Benign`) computed with zero AI/ML.
- **Point out (`#7` Lateral Movement Graph):** Interactive `@xyflow/react` graph highlighting red flagged edges `edge-gateway → dev-service → secrets-vault`.
- **Point out (`#8` Clock Skew & Alert Drawer):**
  - Select `alrt-102` (`svc-worker-04`) in Live Alert Feed → drawer displays `identity`, `services[]`, `event_ids[]`, `path_or_rule`, `explanation`, `confidence_score`, **`order_uncertain: true`** badge, and **both possible causal orderings** within the `±30s` skew window (plus `alrt-101` showing `BENIGN_ADMIN` maintenance separation).

## `4:35 – 5:00` · Threat Model Honesty & Clean-Machine Wrap-Up
- **Show:** [docs/threat-model.md](docs/threat-model.md) / Page 2 of the Project Brief PDF.
- **Talk track:** Summarize explicit limits (trusted host RAM before `SK_ephem` zeroization, `±60s` max clock skew, volumetric DoS out of scope) and note reproducible clean-machine setup via `scripts/clean-machine-check.sh` and `make up`.
