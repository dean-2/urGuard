# urGuard Threat Model (Draft Outline)

## 1. Protected Assets
- **Long-Term Identity Keys (`IK_sig`):** `ML-DSA-65` signing keypairs bound to user/service identities and device IDs.
- **Epoch Encryption Keys (`EK_epoch`):** Hybrid `X25519 + ML-KEM-768` pre-keys rotated atomically via two-phase WAL transitions.
- **Ephemeral Session Keys (`SK_ephem`) & Shared DEKs:** Per-session secrets zeroized on completion, plus collaborator Data Encryption Keys re-encapsulated on device loss.
- **Encrypted Key Store Backups:** Passphrase-derived (`Argon2id + HKDF`) `AES-256-GCM` ciphertext bundles signed with `ML-DSA-65` and verified via SHA-256 manifests.
- **Tamper-Evident Audit Log & Access Graph:** Canonical JSON records linked by `SHA256(seq || prev_hash || canonical_body)` with signed checkpoints and lateral-movement baselines.

## 2. Adversary Capabilities
- **Harvest-Now, Decrypt-Later (Quantum) Adversary:** Captures network ciphertexts today and later breaks classical asymmetric primitives or obtains retired keys.
- **Network Active Attacker (MitM):** Replays captured packets, tampers with envelope headers (`recipient_id`, `key_epoch`), drops/reorders chunks, or replays stolen `ResumptionTicket` tokens.
- **Compromised or Lost Endpoint Device:** Physical theft of an enrolled device (`device_old`) or post-session compromise of `IK_sig` / expired `EK_epoch`.
- **Malicious Insider / Pivoting Workload:** Uses valid credentials to traverse unseen service-to-service paths or escalate privileges outside approved maintenance windows.
- **Audit / Backup Tamper Attacker:** Submits crafted strings (`\n`, embedded JSON) to inject forged log records, alters historical rows in storage, or corrupts/rolls back backup bundles.

## 3. Trust Boundaries
- **Operator Console ↔ Control Plane (ConnectRPC / Reverse Proxy):** Browser UI renders untrusted metadata strictly as plain text and authenticates/proxies RPCs over `/api`.
- **Control Plane ↔ Relay Nodes (PQC-mTLS `X25519MLKEM768`):** Internal streaming CRL propagation, heartbeat reconciliation, and epoch cutoff enforcement.
- **Transport TLS Layer vs. Application E2E Envelope Layer:** Even if TLS terminates at a proxy or relay node, confidentiality, AAD recipient binding, and `ML-DSA-65` signatures hold end-to-end.
- **Untrusted Input Boundary vs. Canonical Audit Serializer:** User-supplied fields are confined to escaped `payload.metadata` fields and never cross into structural record boundaries.
- **Persistent WAL / Backup Store Boundary:** All state mutations commit atomically before streaming; backups must pass signature, AEAD tag, and manifest checks before touching live state.

## 4. Security Assumptions
- **Trusted Host Memory & OS Entropy:** Endpoint and node RAM are uncompromised during the active session window prior to `SK_ephem` zeroization.
- **Bounded Clock Skew (`±30s` default, tested to `±60s`):** Source and detector clocks remain within the configured watermark bound; pairs within `2 * skew` are flagged `order_uncertain: true`.
- **Vetted Cryptographic Primitives:** Security relies on standardized Go `crypto/mlkem`, `cloudflare/circl` (`ML-KEM-768`, `ML-DSA-65`), `AES-256-GCM`, `HKDF-SHA256`, and `SHA-256` with zero custom primitives.
- **Atomic Storage & Monotonic CRL Persistence:** Embedded `bbolt` / SQLite WAL honors `fsync` semantics across `SIGKILL` crashes, preserving monotonic `crl_epoch` values.
- **Authenticated Initial Root Enrollment:** Initial device onboarding and admin recovery approvals occur over an out-of-band authenticated channel.

## 5. Explicit Limits & Out-of-Scope Threats
- **Active Endpoint Memory Compromise / Cold-Boot Attacks:** An attacker with live root/memory-read access on an active sender/recipient device during a session can read plaintext or `SK_ephem` before zeroization.
- **Clock Drift Exceeding `±60s`:** Extreme unsynchronized clocks beyond the configured watermark window force late-arrival reconciliation and cannot guarantee strict causal ordering.
- **Volumetric Denial of Service (DoS):** Exhaustion of network bandwidth, CPU (excessive PQC handshakes), or disk space by unauthenticated flooding is outside protocol-level mitigation.
- **Side-Channel Attacks Outside Vetted Libraries:** Hardware/microarchitectural timing or power analysis beyond constant-time guarantees in Go stdlib and `cloudflare/circl`.
- **Compromised Client Binaries:** If a user executes a trojanized frontend or CLI binary, cryptographic client-side guarantees are bypassed.
