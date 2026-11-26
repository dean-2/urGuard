import { Fragment, useCallback, useState } from 'react';
import type { UrGuardClient } from '../../api/client.ts';
import type { AuditRecord, LogChainVerification } from '../../api/types.ts';
import { Badge, Card, StatusBanner } from '../../components/index.ts';
import { useSubscription } from '../../hooks/index.ts';

interface AuditViewProps {
  readonly client: UrGuardClient;
}

const DEFAULT_INJECTION_PAYLOAD = '\n{"actor":"admin","action":"GRANT_ROOT"}';

function shortHash(value: string): string {
  return value.length <= 12 ? value : `${value.slice(0, 12)}…`;
}

/** Tamper-evident canonical audit log viewer, chain verifier, and log-injection tester. */
export function AuditView({ client }: AuditViewProps) {
  const subscribeLogs = useCallback(
    (handlers: Parameters<UrGuardClient['subscribeAuditLogs']>[0]) =>
      client.subscribeAuditLogs(handlers),
    [client],
  );

  const { data: logsData, error: streamError } = useSubscription<readonly AuditRecord[]>(
    subscribeLogs,
    [client],
  );

  const records = logsData ?? [];
  const [expandedSeqs, setExpandedSeqs] = useState<ReadonlySet<number>>(() => new Set());
  const [verification, setVerification] = useState<LogChainVerification | null>(null);
  const [injectionActor, setInjectionActor] = useState<string>('guest@urguard.local');
  const [injectionText, setInjectionText] = useState<string>(DEFAULT_INJECTION_PAYLOAD);
  const [lastInjectedSeq, setLastInjectedSeq] = useState<number | null>(null);
  const [tamperSeq, setTamperSeq] = useState<string>('2');
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState<boolean>(false);

  function toggleRow(seq: number) {
    setExpandedSeqs((prev) => {
      const next = new Set(prev);
      if (next.has(seq)) {
        next.delete(seq);
      } else {
        next.add(seq);
      }
      return next;
    });
  }

  async function handleVerifyChain() {
    setActionError(null);
    setBusy(true);
    try {
      const res = await client.verifyLogChain();
      setVerification(res);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Chain verification failed');
    } finally {
      setBusy(false);
    }
  }

  async function handleTamperRow() {
    const seqNum = Number.parseInt(tamperSeq, 10);
    if (!Number.isFinite(seqNum) || seqNum < 1) {
      setActionError('Enter a valid positive seq number to tamper.');
      return;
    }
    setActionError(null);
    setBusy(true);
    try {
      await client.tamperAuditRecord(seqNum);
      setVerification(null);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to tamper record');
    } finally {
      setBusy(false);
    }
  }

  async function handleLogInjectionTest() {
    setActionError(null);
    setBusy(true);
    try {
      const created = await client.appendUserAuditTest(injectionActor.trim(), injectionText);
      setLastInjectedSeq(created.seq);
      setExpandedSeqs((prev) => new Set(prev).add(created.seq));
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to append audit record');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="view-stack">
      {streamError || actionError ? (
        <StatusBanner tone="danger" title="Audit stream error">
          {actionError ?? streamError}
        </StatusBanner>
      ) : null}

      <Card
        title="Canonical Hash-Chained Audit Log"
        subtitle="Structured canonical JSON records with SHA-256 hash chaining and ML-DSA-65 signed checkpoints."
        actions={
          <div className="button-row">
            <label className="inline-field">
              <span>Tamper seq</span>
              <input
                type="number"
                min={1}
                aria-label="Tamper seq"
                value={tamperSeq}
                onChange={(e) => {
                  setTamperSeq(e.target.value);
                }}
              />
            </label>
            <button
              type="button"
              className="btn btn-warning"
              disabled={busy || records.length === 0}
              onClick={() => {
                void handleTamperRow();
              }}
            >
              Simulate DB Tamper
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={busy}
              onClick={() => {
                void handleVerifyChain();
              }}
            >
              Verify Chain
            </button>
          </div>
        }
      >
        {verification ? (
          <div className="subsection">
            <StatusBanner
              tone={verification.valid ? 'success' : 'danger'}
              title={
                verification.valid
                  ? 'CHAIN VALID'
                  : `CHAIN BROKEN at seq ${String(verification.brokenSeq)}`
              }
              testId="chain-verification-result"
            >
              {verification.valid
                ? `Verified ${String(verification.totalRecords)} records through seq ${String(verification.lastVerifiedSeq)} (checkpoint signature verified).`
                : (verification.reason ?? 'Hash chain verification failed.')}
            </StatusBanner>
          </div>
        ) : null}

        <table className="data-table" aria-label="Audit log entries">
          <thead>
            <tr>
              <th>seq</th>
              <th>actor_id</th>
              <th>action</th>
              <th>entry_hash</th>
              <th>prev_hash</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {records.map((record) => {
              const expanded = expandedSeqs.has(record.seq);
              return (
                <Fragment key={record.seq}>
                  <tr data-testid={`audit-row-${String(record.seq)}`}>
                    <td className="mono">{String(record.seq)}</td>
                    <td className="mono">{record.actorId}</td>
                    <td>
                      <Badge tone={record.action.includes('FAILURE') ? 'danger' : 'neutral'}>
                        {record.action}
                      </Badge>
                    </td>
                    <td className="mono" title={record.entryHash}>
                      {shortHash(record.entryHash)}
                    </td>
                    <td className="mono" title={record.prevHash}>
                      {shortHash(record.prevHash)}
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn btn-small"
                        aria-expanded={expanded}
                        onClick={() => {
                          toggleRow(record.seq);
                        }}
                      >
                        {expanded ? 'Hide' : 'Inspect'}
                      </button>
                    </td>
                  </tr>
                  {expanded ? (
                    <tr
                      className="expanded-row"
                      data-testid={`audit-details-${String(record.seq)}`}
                    >
                      <td colSpan={6}>
                        <div className="expanded-details">
                          <div>
                            <strong>timestamp:</strong>{' '}
                            <span className="mono">{record.timestamp}</span> ·{' '}
                            <strong>target_service:</strong>{' '}
                            <span className="mono">{record.targetService}</span> ·{' '}
                            <strong>source_node:</strong>{' '}
                            <span className="mono">{record.sourceNode}</span>
                          </div>
                          <div>
                            <strong>full entry_hash:</strong>{' '}
                            <span className="mono">{record.entryHash}</span>
                          </div>
                          <div>
                            <strong>full prev_hash:</strong>{' '}
                            <span className="mono">{record.prevHash}</span>
                          </div>
                          {record.checkpointSignature ? (
                            <div>
                              <strong>checkpoint_signature:</strong>{' '}
                              <span className="mono">{record.checkpointSignature}</span>
                            </div>
                          ) : null}
                          <div>
                            <strong>escaped payload.metadata (plain text):</strong>
                            <pre className="code-block">
                              {JSON.stringify(record.payload.metadata, null, 2)}
                            </pre>
                          </div>
                          <div>
                            <strong>canonical_body:</strong>
                            <pre className="code-block">{record.canonicalBody}</pre>
                          </div>
                        </div>
                      </td>
                    </tr>
                  ) : null}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </Card>

      <Card
        title="Log Injection Defense Test"
        subtitle="Submit crafted newlines or JSON fragments; canonical serialization traps user strings inside escaped payload.metadata."
      >
        <div className="form-stack">
          <label className="field">
            <span>Submitting Actor ID</span>
            <input
              type="text"
              aria-label="Submitting Actor ID"
              value={injectionActor}
              onChange={(e) => {
                setInjectionActor(e.target.value);
              }}
            />
          </label>
          <label className="field">
            <span>Log injection test payload</span>
            <textarea
              rows={3}
              aria-label="Log injection test"
              value={injectionText}
              onChange={(e) => {
                setInjectionText(e.target.value);
              }}
            />
          </label>
          <div className="button-row">
            <button
              type="button"
              className="btn btn-primary"
              disabled={busy}
              onClick={() => {
                void handleLogInjectionTest();
              }}
            >
              Submit Injection Test
            </button>
          </div>
        </div>

        {lastInjectedSeq !== null ? (
          <div className="subsection">
            <StatusBanner
              tone="info"
              title="Isolated in payload.metadata"
              testId="injection-status"
            >
              Recorded at seq {String(lastInjectedSeq)} under actor_id &quot;{injectionActor}&quot;
              with action USER_METADATA_SUBMITTED. Crafted text cannot alter record boundaries.
            </StatusBanner>
          </div>
        ) : null}
      </Card>
    </div>
  );
}
