/** Lifecycle phases of the two-phase atomic key rotation state machine (FR-2). */
export type RotationPhase = 'IDLE' | 'PREPARING' | 'COMMITTED' | 'CUTOFF_ENFORCED';

/** Health status of a relay/storage node or control plane service. */
export type NodeStatus = 'HEALTHY' | 'DEGRADED' | 'OFFLINE';

/** Enrollment status of a registered device identity key. */
export type DeviceStatus = 'ACTIVE' | 'REVOKED';

/** Standard protocol error codes defined in the PRD. */
export type ProtocolErrorCode =
  | 'ERR_KEY_EPOCH_EXPIRED'
  | 'ERR_BACKUP_CORRUPTED'
  | 'ERR_REPLAY_DETECTED'
  | 'ERR_RECIPIENT_MISMATCH'
  | 'ERR_SESSION_IDENTITY_MISMATCH'
  | 'DELIVERY_FAILED';

/** Cryptographic suites permitted by Track 4 policy (FR-1). */
export type KemAlgorithm = 'X25519+ML-KEM-768';
export type SignatureAlgorithm = 'ML-DSA-65';
export type AeadAlgorithm = 'AES-256-GCM';

/** Node metadata and synchronized epoch/CRL state. */
export interface NodeInfo {
  readonly nodeId: string;
  readonly name: string;
  readonly endpoint: string;
  readonly status: NodeStatus;
  readonly activeKeyEpoch: number;
  readonly crlEpoch: number;
  readonly lastHeartbeatAt: string;
}

/** Hybrid post-quantum epoch key metadata (FR-1, FR-2). */
export interface KeyEpoch {
  readonly epoch: number;
  readonly kemAlgorithm: KemAlgorithm;
  readonly sigAlgorithm: SignatureAlgorithm;
  readonly publicKeyFingerprint: string;
  readonly phase: RotationPhase;
  readonly createdAt: string;
  readonly committedAt: string | null;
  readonly cutoffAt: string | null;
  readonly gracePeriodSeconds: number;
}

/** Per-node key rotation state snapshot. */
export interface NodeRotationState {
  readonly nodeId: string;
  readonly currentEpoch: number;
  readonly acceptedPreviousEpoch: number | null;
  readonly phase: RotationPhase;
  readonly updatedAt: string;
}

/** Cluster-wide key rotation state and active grace-period tracking (FR-2). */
export interface RotationState {
  readonly currentEpoch: number;
  readonly previousEpoch: number | null;
  readonly phase: RotationPhase;
  readonly gracePeriodSeconds: number;
  readonly committedAt: string | null;
  readonly cutoffAt: string | null;
  readonly activeInFlightTransfers: number;
  readonly epochs: readonly KeyEpoch[];
  readonly nodeStates: readonly NodeRotationState[];
}

/** Registered user/service device bound to an ML-DSA-65 identity key (FR-1, FR-3). */
export interface DeviceRecord {
  readonly deviceId: string;
  readonly ownerId: string;
  readonly role: string;
  readonly ikFingerprint: string;
  readonly status: DeviceStatus;
  readonly enrolledAt: string;
  readonly revokedAt: string | null;
}

/** Signed Certificate/Key Revocation List entry pushed via gRPC streaming (FR-3). */
export interface CrlEntry {
  readonly crlEpoch: number;
  readonly revokedKeyId: string;
  readonly revokedDeviceId: string;
  readonly reason: string;
  readonly issuedAt: string;
  readonly signatureHex: string;
}

/** Per-node acknowledgment of CRL enforcement and propagation latency (FR-3). */
export interface NodeAck {
  readonly nodeId: string;
  readonly nodeName: string;
  readonly crlEpoch: number;
  readonly acknowledgedAt: string;
  readonly propagationMs: number;
  readonly enforced: boolean;
}

/** Result returned when revoking a key/device across all cluster nodes (FR-3). */
export interface RevocationResult {
  readonly entry: CrlEntry;
  readonly tRevoked: string;
  readonly tEnforcedLastNode: string;
  readonly revocationPropagationMs: number;
  readonly nodeAcks: readonly NodeAck[];
}

/** Result of device loss recovery and DEK re-encapsulation (FR-3). */
export interface ReEnrollResult {
  readonly revokedDeviceId: string;
  readonly newDevice: DeviceRecord;
  readonly reEncapsulatedDekCount: number;
  readonly retainedCollaborators: readonly string[];
  readonly dekHolderDevices: readonly DeviceRecord[];
}

/** Authenticated header of an encrypted backup bundle (FR-5). */
export interface BackupHeader {
  readonly formatVersion: string;
  readonly backupId: string;
  readonly createdAt: string;
  readonly keyEpoch: number;
  readonly sha256Manifest: string;
}

/** Signed and AES-256-GCM encrypted key store backup bundle (FR-5). */
export interface BackupBundle {
  readonly header: BackupHeader;
  readonly ciphertextBase64: string;
  readonly signatureBase64: string;
}

/** Verification outcome when attempting to restore a backup bundle (FR-5). */
export interface BackupRestoreResult {
  readonly success: boolean;
  readonly errorCode?: 'ERR_BACKUP_CORRUPTED';
  readonly verifiedSignature: boolean;
  readonly verifiedAeadTag: boolean;
  readonly verifiedManifest: boolean;
  readonly message: string;
}

/** E2E envelope header with replay and recipient-binding fields (FR-7). */
export interface EnvelopeHeader {
  readonly senderId: string;
  readonly recipientId: string;
  readonly sessionId: string;
  readonly keyEpoch: number;
  readonly msgSeq: number;
  readonly nonceHex: string;
  readonly timestamp: string;
}

/** Chunk status for loss/reordering recovery (FR-9). */
export interface ChunkState {
  readonly chunkIndex: number;
  readonly totalChunks: number;
  readonly transferId: string;
  readonly chunkHash: string;
  readonly rootManifestHash: string;
  readonly received: boolean;
  readonly verified: boolean;
}

export type TransferStatus = 'IN_FLIGHT' | 'DELIVERED' | 'DELIVERY_FAILED' | 'REJECTED';

/** End-to-end hybrid encrypted message or chunked file transfer record (FR-1, FR-7..FR-9). */
export interface E2EMessageRecord {
  readonly transferId: string;
  readonly header: EnvelopeHeader;
  readonly kemAlgorithm: KemAlgorithm;
  readonly aeadAlgorithm: AeadAlgorithm;
  readonly sigAlgorithm: SignatureAlgorithm;
  readonly aadCanonical: string;
  readonly signatureValid: boolean;
  readonly ephemeralZeroized: boolean;
  readonly status: TransferStatus;
  readonly errorCode?: ProtocolErrorCode;
  readonly chunks: readonly ChunkState[];
  readonly deliveredOrder: readonly number[];
  readonly plaintextPreview?: string;
  readonly latencyMs: number;
}

/** Request payload to send an E2E message or chunked transfer. */
export interface SendE2EMessageInput {
  readonly senderId: string;
  readonly recipientId: string;
  readonly payload: string;
  readonly relayNode?: string;
  readonly chunkCount?: number;
  readonly keyEpoch?: number;
  readonly deliveryOrder?: readonly number[];
  readonly dropChunkIndices?: readonly number[];
}

/** Peer-bound session resumption ticket (FR-10). */
export interface ResumptionTicket {
  readonly sessionId: string;
  readonly authenticatedPeerId: string;
  readonly peerIkFingerprint: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

/** Outcome of a session resumption challenge-response check (FR-10). */
export interface SessionResumptionResult {
  readonly accepted: boolean;
  readonly errorCode?: 'ERR_SESSION_IDENTITY_MISMATCH';
  readonly presentedIdentity: string;
  readonly ticketPeerId: string;
  readonly message: string;
}

/** Tamper-evident, canonical hash-chained audit record (FR-6). */
export interface AuditRecord {
  readonly seq: number;
  readonly prevHash: string;
  readonly entryHash: string;
  readonly timestamp: string;
  readonly actorId: string;
  readonly action: string;
  readonly targetService: string;
  readonly sourceNode: string;
  readonly payload: {
    readonly metadata: Readonly<Record<string, string>>;
    readonly changeTicket?: string;
  };
  readonly canonicalBody: string;
  readonly checkpointSignature?: string;
}

/** Chain integrity verification summary returned by VerifyLogChain (FR-6). */
export interface LogChainVerification {
  readonly valid: boolean;
  readonly totalRecords: number;
  readonly lastVerifiedSeq: number;
  readonly brokenSeq: number | null;
  readonly reason: string | null;
  readonly verifiedAt: string;
  readonly checkpointVerified: boolean;
}

/** Explainable activity classifications (FR-11, FR-12). */
export type ActivityClassification =
  'BENIGN_ADMIN' | 'SUSPICIOUS_ESCALATION' | 'LATERAL_MOVEMENT' | 'PROTOCOL_ATTACK';

export type AlertSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

/** Node in the identity-to-service access graph (FR-12). */
export interface AccessGraphNode {
  readonly id: string;
  readonly kind: 'IDENTITY' | 'SERVICE' | 'ENCLAVE';
  readonly trustTier: number;
  readonly label: string;
}

/** Directed transition edge in the access graph (FR-12). */
export interface AccessGraphEdge {
  readonly id: string;
  readonly source: string;
  readonly target: string;
  readonly identity: string;
  readonly baselineCount: number;
  readonly flagged: boolean;
  readonly lastSeenAt: string;
}

export interface AccessGraph {
  readonly nodes: readonly AccessGraphNode[];
  readonly edges: readonly AccessGraphEdge[];
}

/** Explainable security alert with clock-skew uncertainty metadata (FR-11..FR-13). */
export interface SecurityAlert {
  readonly alertId: string;
  readonly identity: string;
  readonly classification: ActivityClassification;
  readonly severity: AlertSeverity;
  readonly services: readonly string[];
  readonly eventIds: readonly number[];
  readonly pathOrRule: string;
  readonly explanation: string;
  readonly confidenceScore: number;
  readonly orderUncertain: boolean;
  readonly lateArrival: boolean;
  readonly possibleOrderings?: readonly string[];
  readonly eventTimestamp: string;
  readonly ingestTimestamp: string;
  readonly detectedAt: string;
}

/** Evaluation, latency, and policy metrics exposed by control plane and detector (FR-11..FR-13). */
export interface DetectionMetrics {
  readonly f1Score: number;
  readonly precision: number;
  readonly recall: number;
  readonly medianTimeToAlertMs: number;
  readonly falseAlertsPer1kBenign: number;
  readonly pqcHandshakeLatencyMs: number;
  readonly e2eThroughputOverheadPct: number;
  readonly revocationPropagationMs: number;
  readonly gracePeriodSeconds: number;
  readonly maxClockSkewSeconds: number;
  readonly evaluatedEventCount: number;
  readonly updatedAt: string;
}

/** Overall system health and transport mode reported to the console. */
export interface SystemHealth {
  readonly mode: 'mock' | 'live';
  readonly apiBaseUrl: string;
  readonly controlPlaneReady: boolean;
  readonly nodes: readonly NodeInfo[];
  readonly rotation: RotationState;
}

/** Callbacks for server-streaming RPC subscriptions. */
export interface StreamHandlers<T> {
  readonly onData: (item: T) => void;
  readonly onError?: (err: Error) => void;
  readonly onComplete?: () => void;
}

/** Cleanup function returned by subscription helpers. */
export type UnsubscribeFn = () => void;
