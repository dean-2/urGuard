# urGuard Threat Model

**System:** Post-Quantum Zero-Trust Messaging, Key Lifecycle & Explainable Guard · **Scope:** Control Plane, 3 Relay Nodes, Operator Console

## 1. Protected Assets
- **Identity Keys (`IK_sig`):** Long-term `ML-DSA-65` signing keys binding users, services, and device IDs.
- **Epoch & Session Keys (`EK_epoch`, `SK_ephem`):** Hybrid `X25519 + ML-KEM-768` pre-keys and per-session ephemeral keys zeroized after derivation/completion.
- **Collaborator DEKs & Backups:** Shared Data Encryption Keys re-encapsulated on device loss; `Argon2id + HKDF` / `AES-256-GCM` backup bundles signed with `ML-DSA-65`.
- **Canonical Audit Log & Access Graph:** `SHA256(seq || prev_hash || canonical_body)` log chain with signed checkpoints and identity-to-service transition graph.

## 2. Adversaries
- **Harvest-Now, Decrypt-Later Quantum Adversary:** Records ciphertexts today to break classical KEMs or exploits post-session `IK_sig` / expired `EK_epoch` leaks.
- **Active Network Attacker (MitM):** Replays packets, alters `recipient_id` or `key_epoch`, drops/reorders chunks, or presents stolen `ResumptionTicket` tokens.
- **Lost Device / Malicious Insider:** Compromises `device_old` or pivots laterally across services (`edge-gateway -> dev-service -> secrets-vault`) with valid credentials.
- **Injection / Storage Tamper Attacker:** Submits `\n`/JSON payloads into user fields or modifies/deletes historical audit rows and backup bytes.

## 3. Trust Boundaries
- **Console ↔ Control Plane:** Reverse proxy (`/api/`) + ConnectRPC; UI renders user-supplied metadata as plain text only (no raw HTML injection).
- **Control Plane ↔ Relay Nodes:** Mutual-authenticated `X25519MLKEM768` TLS using runtime-generated ephemeral mTLS CA/certs (never committed).
- **E2E Envelope vs. Transport:** Application `AES-256-GCM` AAD (`sender|recipient|session|epoch|seq`) + `ML-DSA-65` signature survive transport termination at relays.
- **Untrusted Input ↔ Audit Core:** User fields are isolated inside escaped `payload.metadata`; WAL commits precede CRL streaming or rotation acknowledgement.

## 4. Security Assumptions
- **Trusted Host Memory & OS Entropy:** Endpoint/node RAM and CSPRNG remain uncompromised during active sessions before `SK_ephem` zeroization.
- **Bounded Clock Skew:** Node/event clocks stay within **`±30s`** default (`±60s` max tested); causal pairs inside `2 * skew` are flagged `order_uncertain: true`.
- **Standardized Primitives & Atomic Storage:** Relies strictly on Go `crypto/mlkem`, `cloudflare/circl`, `AES-256-GCM`, `HKDF-SHA256`, and `bbolt`/WAL `fsync`.

## 5. Explicit Limits & Non-Goals (What Is Not Protected)
- **Active Host RAM / Cold-Boot Compromise:** Root or memory-dump access while plaintext or `SK_ephem` is live in RAM defeats E2E secrecy.
- **Extreme Clock Drift (`> ±60s`):** Clocks skewed past the configured watermark bound degrade causal ordering beyond `order_uncertain` reconciliation.
- **Volumetric DoS & Hardware Side Channels:** Bandwidth/CPU flooding and microarchitectural timing outside Go stdlib/`circl` are out of scope.
- **Trojanized Client Binaries & Bootstrap Compromise:** Compromised client code or initial out-of-band root device enrollment cannot be mitigated post-hoc.
