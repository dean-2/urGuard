import { ConnectError, Code, type Transport } from '@connectrpc/connect';
import { createConnectTransport } from '@connectrpc/connect-web';
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

function unimplementedConnectRpc(methodName: string, baseUrl: string): Promise<never> {
  return Promise.reject(
    new ConnectError(
      `Live ConnectRPC method "${methodName}" requires generated Protobuf bindings from backend/proto/. Run "npm run codegen" once .proto contracts are present (target: ${baseUrl}).`,
      Code.Unimplemented,
    ),
  );
}

function unimplementedStream(
  methodName: string,
  baseUrl: string,
  onError?: (err: Error) => void,
): UnsubscribeFn {
  const err = new ConnectError(
    `Live ConnectRPC stream "${methodName}" requires generated Protobuf bindings from backend/proto/. Run "npm run codegen" once .proto contracts are present (target: ${baseUrl}).`,
    Code.Unimplemented,
  );
  onError?.(err);
  return () => undefined;
}

export interface LiveUrGuardClient extends UrGuardClient {
  readonly transport: Transport;
}

/**
 * Live ConnectRPC client shell configured with @connectrpc/connect-web transport.
 * Once Engineer A adds backend/proto/*.proto and codegen runs, methods delegate to
 * createClient(Service, transport).
 */
export function createConnectUrGuardClient(baseUrl: string): LiveUrGuardClient {
  const transport: Transport = createConnectTransport({
    baseUrl,
  });

  return {
    mode: 'live',
    baseUrl,
    transport,
    getSystemHealth: () => unimplementedConnectRpc('getSystemHealth', baseUrl),
    subscribeSystemHealth: (handlers) =>
      unimplementedStream('subscribeSystemHealth', baseUrl, handlers.onError),
    getRotationState: () => unimplementedConnectRpc('getRotationState', baseUrl),
    prepareRotation: () => unimplementedConnectRpc('prepareRotation', baseUrl),
    triggerRotation: () => unimplementedConnectRpc('triggerRotation', baseUrl),
    enforceRotationCutoff: () => unimplementedConnectRpc('enforceRotationCutoff', baseUrl),
    listDevices: () => unimplementedConnectRpc('listDevices', baseUrl),
    listCrl: () => unimplementedConnectRpc('listCrl', baseUrl),
    revokeDevice: () => unimplementedConnectRpc('revokeDevice', baseUrl),
    subscribeRevocationAcks: (_crlEpoch, handlers) =>
      unimplementedStream('subscribeRevocationAcks', baseUrl, handlers.onError),
    reEnrollDevice: () => unimplementedConnectRpc('reEnrollDevice', baseUrl),
    exportBackup: () => unimplementedConnectRpc('exportBackup', baseUrl),
    restoreBackup: () => unimplementedConnectRpc('restoreBackup', baseUrl),
    sendE2EMessage: () => unimplementedConnectRpc('sendE2EMessage', baseUrl),
    listMessages: () => unimplementedConnectRpc('listMessages', baseUrl),
    replayMessage: () => unimplementedConnectRpc('replayMessage', baseUrl),
    tamperRecipient: () => unimplementedConnectRpc('tamperRecipient', baseUrl),
    issueResumptionTicket: () => unimplementedConnectRpc('issueResumptionTicket', baseUrl),
    resumeSession: () => unimplementedConnectRpc('resumeSession', baseUrl),
    listAuditLogs: () => unimplementedConnectRpc('listAuditLogs', baseUrl),
    subscribeAuditLogs: (handlers) =>
      unimplementedStream('subscribeAuditLogs', baseUrl, handlers.onError),
    appendUserAuditTest: () => unimplementedConnectRpc('appendUserAuditTest', baseUrl),
    tamperAuditRecord: () => unimplementedConnectRpc('tamperAuditRecord', baseUrl),
    verifyLogChain: () => unimplementedConnectRpc('verifyLogChain', baseUrl),
    listAlerts: () => unimplementedConnectRpc('listAlerts', baseUrl),
    subscribeAlerts: (handlers) =>
      unimplementedStream('subscribeAlerts', baseUrl, handlers.onError),
    getAccessGraph: () => unimplementedConnectRpc('getAccessGraph', baseUrl),
    getMetrics: () => unimplementedConnectRpc('getMetrics', baseUrl),
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
