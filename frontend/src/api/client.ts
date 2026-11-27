import { createClient, type Transport } from '@connectrpc/connect';
import { createConnectTransport } from '@connectrpc/connect-web';
import { CryptoControlService } from '../gen/urguard/v1/crypto_control_pb.ts';
import { TelemetryService } from '../gen/urguard/v1/telemetry_pb.ts';
import type {
  AccessGraph,
  AuditRecord,
  BackupBundle,
  BackupRestoreResult,
  CrlEntry,
  DetectionMetrics,
  DeviceRecord,
  E2EMessageRecord,
  LogChainVerification,
  NodeAck,
  ReEnrollResult,
  ResumptionTicket,
  RevocationResult,
  RotationState,
  SecurityAlert,
  SendE2EMessageInput,
  SessionResumptionResult,
  StreamHandlers,
  SystemHealth,
  UnsubscribeFn,
} from './types.ts';
import { createMockClient } from '../mocks/mockClient.ts';

/**
 * Typed client interface consumed by all operator console views.
 * Both the live ConnectRPC adapter and the in-memory mock implement this contract.
 */
export interface UrGuardClient {
  readonly mode: 'mock' | 'live';
  readonly baseUrl: string;

  getSystemHealth(): Promise<SystemHealth>;
  subscribeSystemHealth(handlers: StreamHandlers<SystemHealth>): UnsubscribeFn;

  getRotationState(): Promise<RotationState>;
  prepareRotation(): Promise<RotationState>;
  triggerRotation(gracePeriodSeconds?: number): Promise<RotationState>;
  enforceRotationCutoff(): Promise<RotationState>;

  listDevices(): Promise<readonly DeviceRecord[]>;
  listCrl(): Promise<readonly CrlEntry[]>;
  revokeDevice(deviceId: string, reason: string): Promise<RevocationResult>;
  subscribeRevocationAcks(crlEpoch: number, handlers: StreamHandlers<NodeAck>): UnsubscribeFn;
  reEnrollDevice(
    revokedDeviceId: string,
    newDeviceId: string,
    ownerId: string,
  ): Promise<ReEnrollResult>;

  exportBackup(): Promise<BackupBundle>;
  restoreBackup(bundle: BackupBundle): Promise<BackupRestoreResult>;

  sendE2EMessage(input: SendE2EMessageInput): Promise<E2EMessageRecord>;
  listMessages(): Promise<readonly E2EMessageRecord[]>;
  replayMessage(transferId: string): Promise<E2EMessageRecord>;
  tamperRecipient(transferId: string, forgedRecipientId: string): Promise<E2EMessageRecord>;
  issueResumptionTicket(identity: string): Promise<ResumptionTicket>;
  resumeSession(
    ticket: ResumptionTicket,
    presenterIdentity: string,
  ): Promise<SessionResumptionResult>;

  listAuditLogs(): Promise<readonly AuditRecord[]>;
  subscribeAuditLogs(handlers: StreamHandlers<readonly AuditRecord[]>): UnsubscribeFn;
  appendUserAuditTest(actorId: string, userMetadataText: string): Promise<AuditRecord>;
  tamperAuditRecord(seq: number): Promise<AuditRecord>;
  verifyLogChain(tamperSeq?: number): Promise<LogChainVerification>;

  listAlerts(): Promise<readonly SecurityAlert[]>;
  subscribeAlerts(handlers: StreamHandlers<readonly SecurityAlert[]>): UnsubscribeFn;
  getAccessGraph(): Promise<AccessGraph>;
  getMetrics(): Promise<DetectionMetrics>;
}

export interface ClientConfig {
  readonly useMocks: boolean;
  readonly baseUrl: string;
}

export interface ClientEnv {
  readonly VITE_USE_MOCKS?: string;
  readonly VITE_API_BASE_URL?: string;
}

const DEFAULT_API_BASE_URL = 'http://localhost:8080';

/** Resolve client mode and base URL from Vite environment variables. */
export function resolveClientConfig(env: ClientEnv = import.meta.env): ClientConfig {
  const rawUseMocks = env.VITE_USE_MOCKS ?? 'true';
  const useMocks = rawUseMocks.toLowerCase() === 'true';
  const configuredBaseUrl = env.VITE_API_BASE_URL?.trim();
  const baseUrl =
    configuredBaseUrl && configuredBaseUrl.length > 0 ? configuredBaseUrl : DEFAULT_API_BASE_URL;

  return { useMocks, baseUrl };
}

export interface LiveUrGuardClient extends UrGuardClient {
  readonly transport: Transport;
}

interface DetectionSnapshotPayload {
  readonly graph: AccessGraph;
  readonly alerts: readonly SecurityAlert[];
  readonly metrics: DetectionMetrics;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function protoTimestampToIso(ts?: { readonly seconds: bigint; readonly nanos: number }): string {
  if (!ts) return new Date().toISOString();
  const ms = Number(ts.seconds) * 1000 + Math.floor(ts.nanos / 1_000_000);
  return new Date(ms).toISOString();
}

function startPollingSubscription<T>(
  loader: () => Promise<T>,
  handlers: StreamHandlers<T>,
  intervalMs = 2000,
): UnsubscribeFn {
  let cancelled = false;
  let timer: ReturnType<typeof setInterval> | null = null;

  const poll = async () => {
    try {
      const value = await loader();
      if (!cancelled) {
        handlers.onData(value);
      }
    } catch (err) {
      if (!cancelled) {
        handlers.onError?.(err instanceof Error ? err : new Error(String(err)));
      }
    }
  };

  void poll();
  timer = setInterval(() => {
    void poll();
  }, intervalMs);

  return () => {
    cancelled = true;
    if (timer !== null) {
      clearInterval(timer);
      timer = null;
    }
    handlers.onComplete?.();
  };
}

/**
 * Live ConnectRPC + Console bridge client communicating with the Go control plane
 * via generated Protobuf/ConnectRPC descriptors and Nginx mTLS proxy routes.
 */
export function createConnectUrGuardClient(baseUrl: string): LiveUrGuardClient {
  const normalizedBase = baseUrl.replace(/\/+$/, '');
  const transport: Transport = createConnectTransport({
    baseUrl: normalizedBase,
  });

  const controlRpc = createClient(CryptoControlService, transport);
  const telemetryRpc = createClient(TelemetryService, transport);
  const decoder = new TextDecoder();

  async function consoleFetch<T>(path: string, init?: RequestInit): Promise<T> {
    const headers = new Headers(init?.headers);
    if (!headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }
    const res = await fetch(`${normalizedBase}/console/v1/${path}`, {
      ...init,
      headers,
    });
    const text = await res.text();
    let parsed: unknown = null;
    if (text.length > 0) {
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = null;
      }
    }
    if (!res.ok) {
      const errMsg =
        parsed &&
        typeof parsed === 'object' &&
        'error' in parsed &&
        typeof parsed.error === 'string'
          ? parsed.error
          : `Request failed (${String(res.status)}): ${text}`;
      throw new Error(errMsg);
    }
    return parsed as T;
  }

  async function getSystemHealth(): Promise<SystemHealth> {
    return consoleFetch<SystemHealth>('health');
  }

  async function getRotationState(): Promise<RotationState> {
    const health = await getSystemHealth();
    return health.rotation;
  }

  async function listAuditLogs(): Promise<readonly AuditRecord[]> {
    const res = await telemetryRpc.listAuditEvents({ fromSeq: 1n, limit: 200 });
    return res.events.map((ev): AuditRecord => {
      const canonicalBody = decoder.decode(ev.canonicalBody);
      const metadata: Record<string, string> = ev.userText ? { user_text: ev.userText } : {};
      return {
        seq: Number(ev.seq),
        prevHash: bytesToHex(ev.prevHash),
        entryHash: bytesToHex(ev.entryHash),
        timestamp: protoTimestampToIso(ev.timestamp),
        actorId: ev.actorId,
        action: ev.action,
        targetService: 'controlplane',
        sourceNode: 'controlplane',
        payload: {
          metadata,
        },
        canonicalBody,
      };
    });
  }

  async function fetchDetectionSnapshot(): Promise<DetectionSnapshotPayload> {
    return consoleFetch<DetectionSnapshotPayload>('detection/snapshot');
  }

  return {
    mode: 'live',
    baseUrl: normalizedBase,
    transport,

    getSystemHealth,

    subscribeSystemHealth(handlers) {
      return startPollingSubscription(getSystemHealth, handlers, 2500);
    },

    getRotationState,

    async prepareRotation() {
      const current = await controlRpc.getEpochState({});
      const active = current.state?.activeEpoch ?? 1n;
      await controlRpc.prepareRotation({ expectedActiveEpoch: active });
      return getRotationState();
    },

    async triggerRotation() {
      const current = await controlRpc.getEpochState({});
      const prepared = current.state?.preparedEpoch ?? 0n;
      if (prepared === 0n) {
        const active = current.state?.activeEpoch ?? 1n;
        const prepRes = await controlRpc.prepareRotation({ expectedActiveEpoch: active });
        await controlRpc.commitRotation({
          preparedEpoch: prepRes.state?.preparedEpoch ?? active + 1n,
        });
      } else {
        await controlRpc.commitRotation({ preparedEpoch: prepared });
      }
      return getRotationState();
    },

    async enforceRotationCutoff() {
      return consoleFetch<RotationState>('rotation/cutoff', { method: 'POST', body: '{}' });
    },

    async listDevices() {
      return consoleFetch<readonly DeviceRecord[]>('devices');
    },

    async listCrl() {
      return consoleFetch<readonly CrlEntry[]>('crl');
    },

    async revokeDevice(deviceId, reason) {
      const res = await controlRpc.revokeDevice({ deviceId, reason });
      const epoch = res.revocation?.crlEpoch ?? 1n;
      return consoleFetch<RevocationResult>(`revocation/status?crl_epoch=${String(epoch)}`);
    },

    subscribeRevocationAcks(crlEpoch, handlers) {
      const seen = new Set<string>();
      return startPollingSubscription(
        async () => {
          const status = await consoleFetch<RevocationResult>(
            `revocation/status?crl_epoch=${String(crlEpoch)}`,
          );
          return status.nodeAcks;
        },
        {
          onData: (acks) => {
            acks.forEach((ack) => {
              if (ack.enforced && !seen.has(ack.nodeId)) {
                seen.add(ack.nodeId);
                handlers.onData(ack);
              }
            });
          },
          onError: handlers.onError,
          onComplete: handlers.onComplete,
        },
        600,
      );
    },

    async reEnrollDevice(revokedDeviceId, newDeviceId, ownerId) {
      return consoleFetch<ReEnrollResult>('devices/reenroll', {
        method: 'POST',
        body: JSON.stringify({ revokedDeviceId, newDeviceId, ownerId }),
      });
    },

    async exportBackup() {
      return consoleFetch<BackupBundle>('backups/export', { method: 'POST', body: '{}' });
    },

    async restoreBackup(bundle) {
      return consoleFetch<BackupRestoreResult>('backups/restore', {
        method: 'POST',
        body: JSON.stringify(bundle),
      });
    },

    async sendE2EMessage(input: SendE2EMessageInput) {
      return consoleFetch<E2EMessageRecord>('messages/send', {
        method: 'POST',
        body: JSON.stringify(input),
      });
    },

    async listMessages() {
      return consoleFetch<readonly E2EMessageRecord[]>('messages');
    },

    async replayMessage(transferId) {
      return consoleFetch<E2EMessageRecord>('messages/replay', {
        method: 'POST',
        body: JSON.stringify({ transferId }),
      });
    },

    async tamperRecipient(transferId, forgedRecipientId) {
      return consoleFetch<E2EMessageRecord>('messages/tamper-recipient', {
        method: 'POST',
        body: JSON.stringify({ transferId, forgedRecipientId }),
      });
    },

    async issueResumptionTicket(identity) {
      return consoleFetch<ResumptionTicket>('resumption/ticket', {
        method: 'POST',
        body: JSON.stringify({ identity }),
      });
    },

    async resumeSession(ticket, presenterIdentity) {
      return consoleFetch<SessionResumptionResult>('resumption/resume', {
        method: 'POST',
        body: JSON.stringify({ ticket, presenterIdentity }),
      });
    },

    listAuditLogs,

    subscribeAuditLogs(handlers) {
      return startPollingSubscription(listAuditLogs, handlers, 2000);
    },

    async appendUserAuditTest(actorId, userMetadataText) {
      return consoleFetch<AuditRecord>('audit/test-event', {
        method: 'POST',
        body: JSON.stringify({ actorId, userMetadataText }),
      });
    },

    async tamperAuditRecord(seq) {
      return consoleFetch<AuditRecord>('audit/tamper', {
        method: 'POST',
        body: JSON.stringify({ seq }),
      });
    },

    async verifyLogChain(tamperSeq) {
      if (tamperSeq !== undefined) {
        await consoleFetch<AuditRecord>('audit/tamper', {
          method: 'POST',
          body: JSON.stringify({ seq: tamperSeq }),
        });
      }
      const res = await telemetryRpc.verifyAuditChain({});
      return {
        valid: res.valid,
        totalRecords: Number(res.checkedEvents),
        lastVerifiedSeq: Number(res.checkedEvents),
        brokenSeq: res.brokenSeq !== undefined ? Number(res.brokenSeq) : null,
        reason: res.reason || null,
        verifiedAt: new Date().toISOString(),
        checkpointVerified: res.checkedCheckpoints > 0 || res.valid,
      };
    },

    async listAlerts() {
      const snap = await fetchDetectionSnapshot();
      return snap.alerts;
    },

    subscribeAlerts(handlers) {
      return startPollingSubscription(
        async () => (await fetchDetectionSnapshot()).alerts,
        handlers,
        2500,
      );
    },

    async getAccessGraph() {
      const snap = await fetchDetectionSnapshot();
      return snap.graph;
    },

    async getMetrics() {
      const snap = await fetchDetectionSnapshot();
      return snap.metrics;
    },
  };
}

/** Create either the mock client or live ConnectRPC client based on VITE_USE_MOCKS. */
export function createUrGuardClient(config: ClientConfig = resolveClientConfig()): UrGuardClient {
  if (config.useMocks) {
    return createMockClient(config.baseUrl);
  }
  return createConnectUrGuardClient(config.baseUrl);
}

export const urGuardClient: UrGuardClient = createUrGuardClient();
