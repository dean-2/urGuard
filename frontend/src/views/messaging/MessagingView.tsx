import { useCallback, useState } from 'react';
import type { UrGuardClient } from '../../api/client.ts';
import type {
  AuditRecord,
  E2EMessageRecord,
  SecurityAlert,
  SessionResumptionResult,
} from '../../api/types.ts';
import { Badge, Card, StatusBanner } from '../../components/index.ts';
import { useQuery } from '../../hooks/index.ts';

interface MessagingViewProps {
  readonly client: UrGuardClient;
}

interface ActionDiagnostic {
  readonly code: string;
  readonly tone: 'success' | 'danger' | 'warning' | 'info';
  readonly summary: string;
  readonly auditRecord: AuditRecord | null;
  readonly alert: SecurityAlert | null;
}

/** E2E hybrid PQC messaging, chunk loss/reorder simulator, and protocol attack console. */
export function MessagingView({ client }: MessagingViewProps) {
  const fetchMessages = useCallback(() => client.listMessages(), [client]);
  const {
    data: messagesData,
    error: loadError,
    refetch: refetchMessages,
  } = useQuery<readonly E2EMessageRecord[]>(fetchMessages, [client]);

  const messages = messagesData ?? [];

  const [senderId, setSenderId] = useState<string>('alice@urguard.local');
  const [recipientId, setRecipientId] = useState<string>('bob@urguard.local');
  const [relayNode, setRelayNode] = useState<string>('node-a');
  const [payload, setPayload] = useState<string>('Verify hybrid PQC envelope & chunk MAC');
  const [chunkCount, setChunkCount] = useState<number>(4);

  const [activeTransfer, setActiveTransfer] = useState<E2EMessageRecord | null>(null);
  const [resumptionResult, setResumptionResult] = useState<SessionResumptionResult | null>(null);
  const [diagnostic, setDiagnostic] = useState<ActionDiagnostic | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState<boolean>(false);

  const displayedTransfer = activeTransfer ?? messages[0] ?? null;

  async function captureLatestTelemetry(
    code: string,
    tone: ActionDiagnostic['tone'],
    summary: string,
    expectedAction?: string,
  ) {
    const [logs, alerts] = await Promise.all([client.listAuditLogs(), client.listAlerts()]);
    const auditRecord =
      (expectedAction
        ? [...logs].reverse().find((r) => r.action === expectedAction)
        : logs[logs.length - 1]) ??
      logs[logs.length - 1] ??
      null;
    const alert = alerts[0] ?? null;
    setDiagnostic({ code, tone, summary, auditRecord, alert });
  }

  async function handleSend(options?: {
    readonly count?: number;
    readonly deliveryOrder?: readonly number[];
    readonly dropChunkIndices?: readonly number[];
    readonly summaryPrefix?: string;
  }) {
    setActionError(null);
    setResumptionResult(null);
    setBusy(true);
    try {
      const record = await client.sendE2EMessage({
        senderId: senderId.trim(),
        recipientId: recipientId.trim(),
        relayNode,
        payload,
        chunkCount: options?.count ?? chunkCount,
        ...(options?.deliveryOrder ? { deliveryOrder: options.deliveryOrder } : {}),
        ...(options?.dropChunkIndices ? { dropChunkIndices: options.dropChunkIndices } : {}),
      });
      setActiveTransfer(record);
      await refetchMessages();

      const code = record.errorCode ?? record.status;
      const tone = record.status === 'DELIVERED' ? 'success' : 'danger';
      const prefix = options?.summaryPrefix ?? 'E2E transfer';
      await captureLatestTelemetry(
        code,
        tone,
        `${prefix} (${record.transferId}) completed with ${code}.`,
        record.status === 'DELIVERED' ? 'E2E_ENVELOPE_DELIVERED' : record.status,
      );
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to send E2E message');
    } finally {
      setBusy(false);
    }
  }

  async function handleReplay() {
    const targetId = displayedTransfer?.transferId ?? 'xfer-0001';
    setActionError(null);
    setResumptionResult(null);
    setBusy(true);
    try {
      const rejected = await client.replayMessage(targetId);
      setActiveTransfer(rejected);
      const code = rejected.errorCode ?? 'ERR_REPLAY_DETECTED';
      await captureLatestTelemetry(
        code,
        'danger',
        `Replay of ${targetId} rejected by sliding replay cache (${code}).`,
        'REPLAY_REJECTED',
      );
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Replay test failed');
    } finally {
      setBusy(false);
    }
  }

  async function handleTamperRecipient() {
    const targetId = displayedTransfer?.transferId ?? 'xfer-0001';
    setActionError(null);
    setResumptionResult(null);
    setBusy(true);
    try {
      const rejected = await client.tamperRecipient(targetId, 'eve@urguard.local');
      setActiveTransfer(rejected);
      const code = rejected.errorCode ?? 'ERR_RECIPIENT_MISMATCH';
      await captureLatestTelemetry(
        code,
        'danger',
        `Forged recipient_id (eve@urguard.local) rejected by AEAD AAD & ML-DSA-65 check (${code}).`,
        'RECIPIENT_BINDING_FAILED',
      );
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Recipient tamper test failed');
    } finally {
      setBusy(false);
    }
  }

  async function handleHijackResumption() {
    setActionError(null);
    setBusy(true);
    try {
      const ticket = await client.issueResumptionTicket(senderId.trim());
      const res = await client.resumeSession(ticket, 'eve@urguard.local');
      setResumptionResult(res);
      const code = res.errorCode ?? (res.accepted ? 'RESUMED' : 'ERR_SESSION_IDENTITY_MISMATCH');
      await captureLatestTelemetry(
        code,
        res.accepted ? 'success' : 'danger',
        res.message,
        'SESSION_HIJACK_ATTEMPT',
      );
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Session resumption check failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="view-stack">
      {loadError || actionError ? (
        <StatusBanner tone="danger" title="Messaging error">
          {actionError ?? loadError}
        </StatusBanner>
      ) : null}

      <Card
        title="Hybrid Post-Quantum E2E Messaging & File Transfer"
        subtitle="X25519 + ML-KEM-768 ephemeral encapsulation, AES-256-GCM AAD recipient binding, and ML-DSA-65 envelope signatures."
      >
        <div className="form-row">
          <label className="field">
            <span>Sender Identity</span>
            <input
              type="text"
              aria-label="Sender Identity"
              value={senderId}
              onChange={(e) => {
                setSenderId(e.target.value);
              }}
            />
          </label>
          <label className="field">
            <span>Recipient Identity</span>
            <input
              type="text"
              aria-label="Recipient Identity"
              value={recipientId}
              onChange={(e) => {
                setRecipientId(e.target.value);
              }}
            />
          </label>
          <label className="field">
            <span>Relay Node</span>
            <select
              aria-label="Relay Node"
              value={relayNode}
              onChange={(e) => {
                setRelayNode(e.target.value);
              }}
            >
              <option value="node-a">node-a</option>
              <option value="node-b">node-b</option>
              <option value="node-c">node-c</option>
            </select>
          </label>
          <label className="field">
            <span>Chunks</span>
            <input
              type="number"
              min={1}
              max={8}
              aria-label="Chunks"
              value={String(chunkCount)}
              onChange={(e) => {
                const parsed = Number.parseInt(e.target.value, 10);
                setChunkCount(Number.isFinite(parsed) && parsed >= 1 ? parsed : 1);
              }}
            />
          </label>
        </div>

        <div className="form-stack subsection">
          <label className="field">
            <span>Message / File Payload</span>
            <input
              type="text"
              aria-label="Message Payload"
              value={payload}
              onChange={(e) => {
                setPayload(e.target.value);
              }}
            />
          </label>

          <div className="button-row">
            <button
              type="button"
              className="btn btn-primary"
              disabled={busy}
              onClick={() => {
                void handleSend();
              }}
            >
              Send E2E Message
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              disabled={busy}
              onClick={() => {
                void handleSend({
                  count: 4,
                  deliveryOrder: [2, 0, 3, 1],
                  summaryPrefix: 'Reordered delivery [2,0,3,1]',
                });
              }}
            >
              Reorder chunks [2,0,3,1]
            </button>
            <button
              type="button"
              className="btn btn-warning"
              disabled={busy}
              onClick={() => {
                void handleSend({
                  count: 3,
                  dropChunkIndices: [1],
                  summaryPrefix: 'Dropped chunk 1 of [0,1,2]',
                });
              }}
            >
              Drop chunk 1 of [0,1,2]
            </button>
            <button
              type="button"
              className="btn btn-danger"
              disabled={busy}
              onClick={() => {
                void handleReplay();
              }}
            >
              Replay captured envelope
            </button>
            <button
              type="button"
              className="btn btn-danger"
              disabled={busy}
              onClick={() => {
                void handleTamperRecipient();
              }}
            >
              Tamper recipient_id
            </button>
            <button
              type="button"
              className="btn btn-danger"
              disabled={busy}
              onClick={() => {
                void handleHijackResumption();
              }}
            >
              Resume session as different identity
            </button>
          </div>
        </div>
      </Card>

      {diagnostic ? (
        <Card title="Protocol Verification Result & Matching Telemetry">
          <div className="subsection">
            <StatusBanner
              tone={diagnostic.tone}
              title={diagnostic.code}
              testId="messaging-result-code"
            >
              {diagnostic.summary}
            </StatusBanner>

            {resumptionResult ? (
              <div className="meta-row" data-testid="resumption-details">
                <Badge tone="danger">Ticket Peer: {resumptionResult.ticketPeerId}</Badge>
                <Badge tone="warning">Presenter: {resumptionResult.presentedIdentity}</Badge>
              </div>
            ) : null}

            <div className="telemetry-grid">
              {diagnostic.auditRecord ? (
                <div className="kpi-card" data-testid="matching-audit-event">
                  <span className="kpi-label">Matching Audit Event</span>
                  <strong>
                    seq {String(diagnostic.auditRecord.seq)} · {diagnostic.auditRecord.action}
                  </strong>
                  <span className="mono muted">
                    actor: {diagnostic.auditRecord.actorId} | node:{' '}
                    {diagnostic.auditRecord.sourceNode}
                  </span>
                  <pre className="code-block">
                    {JSON.stringify(diagnostic.auditRecord.payload.metadata, null, 2)}
                  </pre>
                </div>
              ) : null}

              {diagnostic.alert ? (
                <div className="kpi-card" data-testid="matching-alert-event">
                  <span className="kpi-label">Latest Security Alert</span>
                  <strong>
                    {diagnostic.alert.alertId} · {diagnostic.alert.pathOrRule}
                  </strong>
                  <span className="muted">{diagnostic.alert.explanation}</span>
                </div>
              ) : null}
            </div>
          </div>
        </Card>
      ) : null}

      <Card
        title="Chunk Reassembly Visualiser & Envelope Metadata"
        subtitle="Out-of-order chunks buffer until root_manifest_hash and AEAD tags pass; incomplete payloads never release partial plaintext."
      >
        {displayedTransfer ? (
          <div className="subsection" data-testid="chunk-visualiser">
            <div className="meta-row">
              <Badge tone="info">{displayedTransfer.transferId}</Badge>
              <Badge tone={displayedTransfer.status === 'DELIVERED' ? 'success' : 'danger'}>
                {displayedTransfer.errorCode ?? displayedTransfer.status}
              </Badge>
              <Badge tone="neutral">{displayedTransfer.kemAlgorithm}</Badge>
              <Badge tone="neutral">{displayedTransfer.aeadAlgorithm}</Badge>
              <Badge tone={displayedTransfer.ephemeralZeroized ? 'success' : 'warning'}>
                SK_ephem: {displayedTransfer.ephemeralZeroized ? 'ZEROIZED' : 'ACTIVE'}
              </Badge>
              <span className="mono muted">
                arrival order: [{displayedTransfer.deliveredOrder.map(String).join(', ')}]
              </span>
            </div>

            <div className="chunk-grid">
              {displayedTransfer.chunks.map((chunk) => (
                <div
                  key={chunk.chunkIndex}
                  className={`chunk-tile ${chunk.received && chunk.verified ? 'chunk-ok' : 'chunk-missing'}`}
                  data-testid={`chunk-tile-${String(chunk.chunkIndex)}`}
                >
                  <div className="chunk-title">
                    Chunk #{String(chunk.chunkIndex)} / {String(chunk.totalChunks)}
                  </div>
                  <Badge
                    tone={chunk.received ? (chunk.verified ? 'success' : 'warning') : 'danger'}
                  >
                    {!chunk.received ? 'MISSING' : chunk.verified ? 'VERIFIED' : 'UNVERIFIED'}
                  </Badge>
                  <div className="mono muted">{chunk.chunkHash}</div>
                </div>
              ))}
            </div>

            <div className="mono muted">
              AAD: {displayedTransfer.aadCanonical} | root_manifest:{' '}
              {displayedTransfer.chunks[0]?.rootManifestHash ?? '--'}
            </div>
            {displayedTransfer.plaintextPreview ? (
              <StatusBanner tone="success" title="Verified Plaintext">
                {displayedTransfer.plaintextPreview}
              </StatusBanner>
            ) : (
              <StatusBanner tone="warning" title="Plaintext Withheld">
                Incomplete or rejected payload discarded; no partial plaintext exposed.
              </StatusBanner>
            )}
          </div>
        ) : (
          <p className="muted">No transfers recorded yet.</p>
        )}
      </Card>
    </div>
  );
}
