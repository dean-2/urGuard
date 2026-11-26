import { useCallback, useEffect, useRef, useState } from 'react';
import type { UrGuardClient } from '../../api/client.ts';
import type {
  BackupBundle,
  BackupRestoreResult,
  DeviceRecord,
  NodeAck,
  ReEnrollResult,
  RevocationResult,
  RotationPhase,
  RotationState,
  UnsubscribeFn,
} from '../../api/types.ts';
import { Badge, Card, StatusBanner } from '../../components/index.ts';
import { useQuery } from '../../hooks/index.ts';

interface GovernanceViewProps {
  readonly client: UrGuardClient;
}

const ROTATION_STEPS: readonly RotationPhase[] = [
  'IDLE',
  'PREPARING',
  'COMMITTED',
  'CUTOFF_ENFORCED',
];

function flipOneBase64Char(encoded: string): string {
  if (encoded.length === 0) return 'AA==';
  const first = encoded[0] ?? 'A';
  const replacement = first === 'A' ? 'B' : 'A';
  return `${replacement}${encoded.slice(1)}`;
}

/** Key lifecycle, multi-node revocation, device re-enrollment, and backup verification view. */
export function GovernanceView({ client }: GovernanceViewProps) {
  const fetchRotation = useCallback(() => client.getRotationState(), [client]);
  const fetchDevices = useCallback(() => client.listDevices(), [client]);

  const {
    data: rotationData,
    error: rotationError,
    refetch: refetchRotation,
  } = useQuery<RotationState>(fetchRotation, [client]);

  const {
    data: devicesData,
    error: devicesError,
    refetch: refetchDevices,
  } = useQuery<readonly DeviceRecord[]>(fetchDevices, [client]);

  const [rotationOverride, setRotationOverride] = useState<RotationState | null>(null);
  const rotation = rotationOverride ?? rotationData;
  const devices = devicesData ?? [];

  const [nowMs, setNowMs] = useState<number>(() => Date.now());
  const cutoffTriggeredRef = useRef(false);

  const [selectedRevokeId, setSelectedRevokeId] = useState<string>('');
  const [revokeReason, setRevokeReason] = useState<string>('Lost device');
  const [revocationResult, setRevocationResult] = useState<RevocationResult | null>(null);
  const [streamedAcks, setStreamedAcks] = useState<readonly NodeAck[]>([]);
  const ackUnsubRef = useRef<UnsubscribeFn | null>(null);

  const [selectedOldDeviceId, setSelectedOldDeviceId] = useState<string>('');
  const [newDeviceId, setNewDeviceId] = useState<string>('dev-alice-replacement-02');
  const [newOwnerId, setNewOwnerId] = useState<string>('alice@urguard.local');
  const [reEnrollResult, setReEnrollResult] = useState<ReEnrollResult | null>(null);

  const [backupBundle, setBackupBundle] = useState<BackupBundle | null>(null);
  const [backupTampered, setBackupTampered] = useState<boolean>(false);
  const [restoreResult, setRestoreResult] = useState<BackupRestoreResult | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);

  const activeDevices = devices.filter((d) => d.status === 'ACTIVE');
  const revokedDevices = devices.filter((d) => d.status === 'REVOKED');
  const effectiveRevokeId =
    selectedRevokeId && activeDevices.some((d) => d.deviceId === selectedRevokeId)
      ? selectedRevokeId
      : (activeDevices[0]?.deviceId ?? '');
  const effectiveOldDeviceId =
    selectedOldDeviceId && revokedDevices.some((d) => d.deviceId === selectedOldDeviceId)
      ? selectedOldDeviceId
      : (revokedDevices[0]?.deviceId ?? '');

  useEffect(() => {
    return () => {
      ackUnsubRef.current?.();
    };
  }, []);

  useEffect(() => {
    if (rotation?.phase !== 'COMMITTED' || !rotation.cutoffAt) {
      cutoffTriggeredRef.current = false;
      return undefined;
    }

    const cutoffMs = Date.parse(rotation.cutoffAt);
    const timer = setInterval(() => {
      const currentNow = Date.now();
      setNowMs(currentNow);
      if (currentNow >= cutoffMs && !cutoffTriggeredRef.current) {
        cutoffTriggeredRef.current = true;
        void client.enforceRotationCutoff().then((next) => {
          setRotationOverride(next);
        });
      }
    }, 1000);

    return () => {
      clearInterval(timer);
    };
  }, [client, rotation?.phase, rotation?.cutoffAt]);

  const remainingGraceSec =
    rotation?.phase === 'COMMITTED' && rotation.cutoffAt
      ? Math.max(0, Math.ceil((Date.parse(rotation.cutoffAt) - nowMs) / 1000))
      : null;

  async function handleRotateKey() {
    setActionError(null);
    setBusyAction('rotate');
    try {
      const preparing = await client.prepareRotation();
      setRotationOverride(preparing);
      const committed = await client.triggerRotation(preparing.gracePeriodSeconds);
      setNowMs(Date.now());
      setRotationOverride(committed);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Key rotation failed');
    } finally {
      setBusyAction(null);
    }
  }

  async function handleEnforceCutoff() {
    setActionError(null);
    setBusyAction('cutoff');
    try {
      const next = await client.enforceRotationCutoff();
      setRotationOverride(next);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to enforce rotation cutoff');
    } finally {
      setBusyAction(null);
    }
  }

  async function handleRevokeDevice() {
    if (!effectiveRevokeId) return;
    setActionError(null);
    setBusyAction('revoke');
    ackUnsubRef.current?.();
    setStreamedAcks([]);
    try {
      const result = await client.revokeDevice(effectiveRevokeId, revokeReason);
      setRevocationResult(result);
      setSelectedOldDeviceId(effectiveRevokeId);
      const revokedTarget = devices.find((d) => d.deviceId === effectiveRevokeId);
      if (revokedTarget) {
        setNewOwnerId(revokedTarget.ownerId);
      }
      await refetchDevices();

      ackUnsubRef.current = client.subscribeRevocationAcks(result.entry.crlEpoch, {
        onData: (ack) => {
          setStreamedAcks((prev) =>
            prev.some((item) => item.nodeId === ack.nodeId) ? prev : [...prev, ack],
          );
        },
        onError: (err) => {
          setActionError(err.message);
        },
      });
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Device revocation failed');
    } finally {
      setBusyAction(null);
    }
  }

  async function handleReEnroll() {
    if (!effectiveOldDeviceId || !newDeviceId.trim()) return;
    setActionError(null);
    setBusyAction('reenroll');
    try {
      const res = await client.reEnrollDevice(
        effectiveOldDeviceId,
        newDeviceId.trim(),
        newOwnerId.trim(),
      );
      setReEnrollResult(res);
      await refetchDevices();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Re-enrollment failed');
    } finally {
      setBusyAction(null);
    }
  }

  async function handleExportBackup() {
    setActionError(null);
    setBusyAction('export');
    try {
      const exported = await client.exportBackup();
      setBackupBundle(exported);
      setBackupTampered(false);
      setRestoreResult(null);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Backup export failed');
    } finally {
      setBusyAction(null);
    }
  }

  function handleTamperBackup() {
    if (!backupBundle) return;
    setBackupBundle({
      ...backupBundle,
      ciphertextBase64: flipOneBase64Char(backupBundle.ciphertextBase64),
    });
    setBackupTampered(true);
    setRestoreResult(null);
  }

  async function handleRestoreBackup() {
    if (!backupBundle) return;
    setActionError(null);
    setBusyAction('restore');
    try {
      const res = await client.restoreBackup(backupBundle);
      setRestoreResult(res);
      await Promise.all([refetchRotation(), refetchDevices()]);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Backup restore failed');
    } finally {
      setBusyAction(null);
    }
  }

  const displayedAcks = streamedAcks.length > 0 ? streamedAcks : (revocationResult?.nodeAcks ?? []);

  return (
    <div className="view-stack">
      {rotationError || devicesError || actionError ? (
        <StatusBanner tone="danger" title="Governance error">
          {actionError ?? rotationError ?? devicesError}
        </StatusBanner>
      ) : null}

      <Card
        title="Key Epoch & Two-Phase Rotation"
        subtitle="Atomic WAL rotation (IDLE → PREPARING → COMMITTED → CUTOFF_ENFORCED) with configurable grace period."
        actions={
          <div className="button-row">
            <button
              type="button"
              className="btn btn-primary"
              disabled={busyAction !== null}
              onClick={() => {
                void handleRotateKey();
              }}
            >
              Rotate key
            </button>
            {rotation?.phase === 'COMMITTED' ? (
              <button
                type="button"
                className="btn btn-secondary"
                disabled={busyAction !== null}
                onClick={() => {
                  void handleEnforceCutoff();
                }}
              >
                Enforce cutoff now
              </button>
            ) : null}
          </div>
        }
      >
        <div className="kpi-grid">
          <div className="kpi-card">
            <span className="kpi-label">Current Epoch</span>
            <strong className="kpi-value" data-testid="governance-current-epoch">
              {rotation ? `Epoch ${String(rotation.currentEpoch)}` : '--'}
            </strong>
          </div>
          <div className="kpi-card">
            <span className="kpi-label">Previous Epoch</span>
            <strong className="kpi-value">
              {rotation?.previousEpoch !== null && rotation?.previousEpoch !== undefined
                ? `Epoch ${String(rotation.previousEpoch)}`
                : 'None'}
            </strong>
          </div>
          <div className="kpi-card">
            <span className="kpi-label">Configured Grace Period</span>
            <strong className="kpi-value">
              {rotation ? `${String(rotation.gracePeriodSeconds)}s` : '--'}
            </strong>
          </div>
          <div className="kpi-card">
            <span className="kpi-label">Grace Countdown</span>
            <strong className="kpi-value" data-testid="grace-countdown">
              {remainingGraceSec !== null ? `${String(remainingGraceSec)}s` : 'Inactive'}
            </strong>
          </div>
        </div>

        <ol className="state-stepper" aria-label="Rotation state machine">
          {ROTATION_STEPS.map((step) => {
            const isActive = rotation?.phase === step;
            return (
              <li
                key={step}
                className={isActive ? 'state-step active' : 'state-step'}
                aria-current={isActive ? 'step' : undefined}
                data-testid={`rotation-step-${step}`}
              >
                <span>{step}</span>
              </li>
            );
          })}
        </ol>
      </Card>

      <Card
        title="Multi-Node Device Revocation"
        subtitle="Push signed CRL updates over server-streaming RPC and measure per-node propagation latency."
      >
        <div className="form-row">
          <label className="field">
            <span>Active Device</span>
            <select
              aria-label="Active Device"
              value={effectiveRevokeId}
              onChange={(e) => {
                setSelectedRevokeId(e.target.value);
              }}
            >
              {activeDevices.map((d) => (
                <option key={d.deviceId} value={d.deviceId}>
                  {d.deviceId} ({d.ownerId})
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Revocation Reason</span>
            <input
              type="text"
              aria-label="Revocation Reason"
              value={revokeReason}
              onChange={(e) => {
                setRevokeReason(e.target.value);
              }}
            />
          </label>
          <button
            type="button"
            className="btn btn-danger"
            disabled={!effectiveRevokeId || busyAction !== null}
            onClick={() => {
              void handleRevokeDevice();
            }}
          >
            Revoke device
          </button>
        </div>

        {revocationResult ? (
          <div className="subsection">
            <div className="meta-row">
              <Badge tone="warning" testId="revocation-crl-epoch">
                CRL Epoch #{String(revocationResult.entry.crlEpoch)}
              </Badge>
              <Badge tone="info" testId="revocation-propagation-ms">
                revocation_propagation_ms: {String(revocationResult.revocationPropagationMs)} ms
              </Badge>
              <span className="muted">
                Revoked {revocationResult.entry.revokedDeviceId} at {revocationResult.tRevoked}
              </span>
            </div>

            <table className="data-table" aria-label="Per-node revocation acknowledgments">
              <thead>
                <tr>
                  <th>Node</th>
                  <th>CRL Epoch</th>
                  <th>Propagation (ms)</th>
                  <th>Status</th>
                  <th>Acknowledged At</th>
                </tr>
              </thead>
              <tbody>
                {displayedAcks.map((ack) => (
                  <tr key={ack.nodeId}>
                    <td>{ack.nodeId}</td>
                    <td>{String(ack.crlEpoch)}</td>
                    <td>{String(ack.propagationMs)} ms</td>
                    <td>
                      <Badge tone={ack.enforced ? 'success' : 'warning'}>
                        {ack.enforced ? 'ENFORCED' : 'PENDING'}
                      </Badge>
                    </td>
                    <td className="mono">{ack.acknowledgedAt}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </Card>

      <Card
        title="Device Loss Re-Enrollment & DEK Re-Encapsulation"
        subtitle="Enroll replacement device and re-encapsulate shared DEKs across authorized devices while excluding device_old."
      >
        <div className="form-row">
          <label className="field">
            <span>Revoked Device (device_old)</span>
            <select
              aria-label="Revoked Device"
              value={effectiveOldDeviceId}
              onChange={(e) => {
                setSelectedOldDeviceId(e.target.value);
              }}
            >
              {revokedDevices.length === 0 ? (
                <option value="">Revoke a device first</option>
              ) : (
                revokedDevices.map((d) => (
                  <option key={d.deviceId} value={d.deviceId}>
                    {d.deviceId} ({d.ownerId})
                  </option>
                ))
              )}
            </select>
          </label>
          <label className="field">
            <span>New Device ID (device_new)</span>
            <input
              type="text"
              aria-label="New Device ID"
              value={newDeviceId}
              onChange={(e) => {
                setNewDeviceId(e.target.value);
              }}
            />
          </label>
          <label className="field">
            <span>Owner Identity</span>
            <input
              type="text"
              aria-label="Owner Identity"
              value={newOwnerId}
              onChange={(e) => {
                setNewOwnerId(e.target.value);
              }}
            />
          </label>
          <button
            type="button"
            className="btn btn-primary"
            disabled={!effectiveOldDeviceId || !newDeviceId.trim() || busyAction !== null}
            onClick={() => {
              void handleReEnroll();
            }}
          >
            Re-enroll device
          </button>
        </div>

        {reEnrollResult ? (
          <div className="subsection" data-testid="reenroll-summary">
            <StatusBanner tone="success" title="DEK Re-Encapsulated">
              {String(reEnrollResult.reEncapsulatedDekCount)} shared DEKs re-encapsulated to active
              devices; {reEnrollResult.revokedDeviceId} is excluded.
            </StatusBanner>
            <table className="data-table" aria-label="DEK holder devices">
              <thead>
                <tr>
                  <th>Device ID</th>
                  <th>Owner</th>
                  <th>DEK Access</th>
                </tr>
              </thead>
              <tbody>
                {reEnrollResult.dekHolderDevices.map((holder) => (
                  <tr key={holder.deviceId}>
                    <td className="mono">{holder.deviceId}</td>
                    <td>{holder.ownerId}</td>
                    <td>
                      <Badge tone="success">HOLDS RE-ENCAPSULATED DEK</Badge>
                    </td>
                  </tr>
                ))}
                <tr>
                  <td className="mono">{reEnrollResult.revokedDeviceId}</td>
                  <td>revoked</td>
                  <td>
                    <Badge tone="danger">EXCLUDED (REVOKED)</Badge>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        ) : null}
      </Card>

      <Card
        title="Cryptographic Backup & Integrity Verification"
        subtitle="Export AES-256-GCM + ML-DSA-65 signed backup, test 1-byte tamper rejection, and verify live keys remain untouched."
        actions={
          <div className="button-row">
            <button
              type="button"
              className="btn btn-primary"
              disabled={busyAction !== null}
              onClick={() => {
                void handleExportBackup();
              }}
            >
              Export Backup
            </button>
            <button
              type="button"
              className="btn btn-warning"
              disabled={!backupBundle || busyAction !== null}
              onClick={handleTamperBackup}
            >
              Tamper 1 byte
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              disabled={!backupBundle || busyAction !== null}
              onClick={() => {
                void handleRestoreBackup();
              }}
            >
              Restore Backup
            </button>
          </div>
        }
      >
        {backupBundle ? (
          <div className="subsection">
            <div className="meta-row">
              <Badge tone="neutral">Backup ID: {backupBundle.header.backupId}</Badge>
              <Badge tone="neutral">Epoch: {String(backupBundle.header.keyEpoch)}</Badge>
              <Badge tone={backupTampered ? 'danger' : 'success'} testId="backup-tamper-state">
                {backupTampered ? '1-BYTE TAMPERED' : 'INTACT'}
              </Badge>
            </div>
            <pre className="code-block">
              {JSON.stringify(
                {
                  header: backupBundle.header,
                  ciphertextPreview: `${backupBundle.ciphertextBase64.slice(0, 40)}...`,
                  signaturePreview: `${backupBundle.signatureBase64.slice(0, 40)}...`,
                },
                null,
                2,
              )}
            </pre>
          </div>
        ) : (
          <p className="muted">Export a backup bundle to inspect or test integrity verification.</p>
        )}

        {restoreResult ? (
          <div className="subsection">
            <StatusBanner
              tone={restoreResult.success ? 'success' : 'danger'}
              title={restoreResult.errorCode ?? 'RESTORE_OK'}
              testId="backup-restore-result"
            >
              {restoreResult.message}
            </StatusBanner>
            <div className="meta-row">
              <Badge tone={restoreResult.verifiedSignature ? 'success' : 'danger'}>
                ML-DSA-65 Sig: {restoreResult.verifiedSignature ? 'PASS' : 'FAIL'}
              </Badge>
              <Badge tone={restoreResult.verifiedAeadTag ? 'success' : 'danger'}>
                AES-GCM Tag: {restoreResult.verifiedAeadTag ? 'PASS' : 'FAIL'}
              </Badge>
              <Badge tone={restoreResult.verifiedManifest ? 'success' : 'danger'}>
                SHA-256 Manifest: {restoreResult.verifiedManifest ? 'PASS' : 'FAIL'}
              </Badge>
            </div>
          </div>
        ) : null}
      </Card>
    </div>
  );
}
