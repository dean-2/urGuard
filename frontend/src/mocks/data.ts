import type {
  AccessGraph,
  AuditRecord,
  CrlEntry,
  DetectionMetrics,
  DeviceRecord,
  E2EMessageRecord,
  KeyEpoch,
  NodeInfo,
  SecurityAlert,
} from '../api/types.ts';

export const GENESIS_PREV_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

/** Deterministic 64-hex digest helper for mock hash chaining and fingerprints. */
export function deterministicHex(seed: string, length = 64): string {
  let h1 = 0x811c9dc5;
  let h2 = 0x9e3779b9;
  for (let i = 0; i < seed.length; i += 1) {
    const ch = seed.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ (ch + i), 0x85ebca6b) >>> 0;
  }
  let out = '';
  for (let i = 0; i < length; i += 1) {
    h1 = Math.imul(h1 ^ (h2 + i), 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ (h1 >>> 3), 0xc2b2ae35) >>> 0;
    out += ((h1 ^ h2) & 0xf).toString(16);
  }
  return out;
}

/** Computes a deterministic audit entry hash matching the FR-6 chain structure. */
export function computeAuditEntryHash(
  seq: number,
  prevHash: string,
  canonicalBody: string,
): string {
  return deterministicHex(`${String(seq)}|${prevHash}|${canonicalBody}`, 64);
}

export const SEED_NODES: readonly NodeInfo[] = [
  {
    nodeId: 'node-a',
    name: 'Relay Node A',
    endpoint: 'http://localhost:8081',
    status: 'HEALTHY',
    activeKeyEpoch: 3,
    crlEpoch: 12,
    lastHeartbeatAt: '2026-11-26T10:15:00Z',
  },
  {
    nodeId: 'node-b',
    name: 'Relay Node B',
    endpoint: 'http://localhost:8082',
    status: 'HEALTHY',
    activeKeyEpoch: 3,
    crlEpoch: 12,
    lastHeartbeatAt: '2026-11-26T10:15:00Z',
  },
  {
    nodeId: 'node-c',
    name: 'Relay Node C',
    endpoint: 'http://localhost:8083',
    status: 'HEALTHY',
    activeKeyEpoch: 3,
    crlEpoch: 12,
    lastHeartbeatAt: '2026-11-26T10:15:00Z',
  },
];

export const SEED_EPOCHS: readonly KeyEpoch[] = [
  {
    epoch: 2,
    kemAlgorithm: 'X25519+ML-KEM-768',
    sigAlgorithm: 'ML-DSA-65',
    publicKeyFingerprint: 'mldsa65:8b12f9c0441a7e2d',
    phase: 'CUTOFF_ENFORCED',
    createdAt: '2026-11-26T08:00:00Z',
    committedAt: '2026-11-26T08:00:02Z',
    cutoffAt: '2026-11-26T08:00:32Z',
    gracePeriodSeconds: 30,
  },
  {
    epoch: 3,
    kemAlgorithm: 'X25519+ML-KEM-768',
    sigAlgorithm: 'ML-DSA-65',
    publicKeyFingerprint: 'mldsa65:3d91a0e772bc1109',
    phase: 'IDLE',
    createdAt: '2026-11-26T09:30:00Z',
    committedAt: '2026-11-26T09:30:01Z',
    cutoffAt: null,
    gracePeriodSeconds: 30,
  },
];

export const SEED_DEVICES: readonly DeviceRecord[] = [
  {
    deviceId: 'dev-alice-laptop',
    ownerId: 'alice@urguard.local',
    role: 'security-operator',
    ikFingerprint: 'ik:mldsa65:a1094e8f7712',
    status: 'ACTIVE',
    enrolledAt: '2026-11-25T14:20:00Z',
    revokedAt: null,
  },
  {
    deviceId: 'dev-bob-workstation',
    ownerId: 'bob@urguard.local',
    role: 'collaborator',
    ikFingerprint: 'ik:mldsa65:b7421c039e54',
    status: 'ACTIVE',
    enrolledAt: '2026-11-25T15:05:00Z',
    revokedAt: null,
  },
  {
    deviceId: 'dev-svc-vault-01',
    ownerId: 'svc-vault@urguard.local',
    role: 'service-enclave',
    ikFingerprint: 'ik:mldsa65:f9012d84a310',
    status: 'ACTIVE',
    enrolledAt: '2026-11-25T16:00:00Z',
    revokedAt: null,
  },
];

export const SEED_CRL: readonly CrlEntry[] = [
  {
    crlEpoch: 12,
    revokedKeyId: 'ek-old-0011',
    revokedDeviceId: 'dev-legacy-edge-09',
    reason: 'Scheduled decommission',
    issuedAt: '2026-11-26T07:45:00Z',
    signatureHex: 'mldsa65sig:5e90a1c4f0192b83e11a7740c901',
  },
];

export const SEED_MESSAGES: readonly E2EMessageRecord[] = [
  {
    transferId: 'xfer-0001',
    header: {
      senderId: 'alice@urguard.local',
      recipientId: 'bob@urguard.local',
      sessionId: 'sess-7401',
      keyEpoch: 3,
      msgSeq: 1,
      nonceHex: '4a9f0c2e81b4770199a012cc',
      timestamp: '2026-11-26T10:10:00Z',
    },
    kemAlgorithm: 'X25519+ML-KEM-768',
    aeadAlgorithm: 'AES-256-GCM',
    sigAlgorithm: 'ML-DSA-65',
    aadCanonical: 'alice@urguard.local|bob@urguard.local|sess-7401|3|1',
    signatureValid: true,
    ephemeralZeroized: true,
    status: 'DELIVERED',
    chunks: [
      {
        chunkIndex: 0,
        totalChunks: 1,
        transferId: 'xfer-0001',
        chunkHash: 'sha256:9f82c1e044d7',
        rootManifestHash: 'sha256:9f82c1e044d7',
        received: true,
        verified: true,
      },
    ],
    deliveredOrder: [0],
    plaintextPreview: 'Key epoch 3 operational handshake verified.',
    latencyMs: 6.4,
  },
];

const SEQ_1_BODY =
  '{"action":"KEY_ROTATION_COMMITTED","actor_id":"admin@urguard.local","payload":{"change_ticket":"CHG-2026-1142","metadata":{"epoch":"3","grace_period_seconds":"30"}},"source_node":"controlplane","target_service":"key-authority"}';
const SEQ_1_HASH = computeAuditEntryHash(1, GENESIS_PREV_HASH, SEQ_1_BODY);

const SEQ_2_BODY =
  '{"action":"E2E_ENVELOPE_DELIVERED","actor_id":"alice@urguard.local","payload":{"metadata":{"key_epoch":"3","recipient":"bob@urguard.local","transfer_id":"xfer-0001"}},"source_node":"node-a","target_service":"relay-node-a"}';
const SEQ_2_HASH = computeAuditEntryHash(2, SEQ_1_HASH, SEQ_2_BODY);

export const SEED_AUDIT_LOGS: readonly AuditRecord[] = [
  {
    seq: 1,
    prevHash: GENESIS_PREV_HASH,
    entryHash: SEQ_1_HASH,
    timestamp: '2026-11-26T09:30:01Z',
    actorId: 'admin@urguard.local',
    action: 'KEY_ROTATION_COMMITTED',
    targetService: 'key-authority',
    sourceNode: 'controlplane',
    payload: {
      metadata: { epoch: '3', grace_period_seconds: '30' },
      changeTicket: 'CHG-2026-1142',
    },
    canonicalBody: SEQ_1_BODY,
    checkpointSignature: `mldsa65:cp:1:${SEQ_1_HASH.slice(0, 12)}`,
  },
  {
    seq: 2,
    prevHash: SEQ_1_HASH,
    entryHash: SEQ_2_HASH,
    timestamp: '2026-11-26T10:10:00Z',
    actorId: 'alice@urguard.local',
    action: 'E2E_ENVELOPE_DELIVERED',
    targetService: 'relay-node-a',
    sourceNode: 'node-a',
    payload: {
      metadata: { recipient: 'bob@urguard.local', transfer_id: 'xfer-0001', key_epoch: '3' },
    },
    canonicalBody: SEQ_2_BODY,
  },
];

export const SEED_ACCESS_GRAPH: AccessGraph = {
  nodes: [
    { id: 'id:admin', kind: 'IDENTITY', trustTier: 3, label: 'admin@urguard.local' },
    { id: 'id:svc-worker', kind: 'IDENTITY', trustTier: 1, label: 'svc-worker-04' },
    { id: 'svc:edge-gateway', kind: 'SERVICE', trustTier: 1, label: 'edge-gateway' },
    { id: 'svc:dev-service', kind: 'SERVICE', trustTier: 2, label: 'dev-service' },
    { id: 'svc:secrets-vault', kind: 'ENCLAVE', trustTier: 3, label: 'secrets-vault' },
    { id: 'svc:key-authority', kind: 'ENCLAVE', trustTier: 3, label: 'key-authority' },
  ],
  edges: [
    {
      id: 'edge-1',
      source: 'id:admin',
      target: 'svc:key-authority',
      identity: 'admin@urguard.local',
      baselineCount: 42,
      flagged: false,
      lastSeenAt: '2026-11-26T09:30:01Z',
    },
    {
      id: 'edge-2',
      source: 'id:svc-worker',
      target: 'svc:edge-gateway',
      identity: 'svc-worker-04',
      baselineCount: 310,
      flagged: false,
      lastSeenAt: '2026-11-26T10:12:04Z',
    },
    {
      id: 'edge-3',
      source: 'svc:edge-gateway',
      target: 'svc:dev-service',
      identity: 'svc-worker-04',
      baselineCount: 0,
      flagged: true,
      lastSeenAt: '2026-11-26T10:12:11Z',
    },
    {
      id: 'edge-4',
      source: 'svc:dev-service',
      target: 'svc:secrets-vault',
      identity: 'svc-worker-04',
      baselineCount: 0,
      flagged: true,
      lastSeenAt: '2026-11-26T10:12:18Z',
    },
  ],
};

export const SEED_ALERTS: readonly SecurityAlert[] = [
  {
    alertId: 'alrt-101',
    identity: 'admin@urguard.local',
    classification: 'BENIGN_ADMIN',
    severity: 'LOW',
    services: ['key-authority'],
    eventIds: [1],
    pathOrRule: 'RULE_APPROVED_MAINT_ROTATION',
    explanation:
      'Key epoch rotation executed by security-admin role under approved change ticket CHG-2026-1142.',
    confidenceScore: 0.98,
    orderUncertain: false,
    lateArrival: false,
    eventTimestamp: '2026-11-26T09:30:01Z',
    ingestTimestamp: '2026-11-26T09:30:02Z',
    detectedAt: '2026-11-26T09:30:02Z',
  },
  {
    alertId: 'alrt-102',
    identity: 'svc-worker-04',
    classification: 'LATERAL_MOVEMENT',
    severity: 'CRITICAL',
    services: ['edge-gateway', 'dev-service', 'secrets-vault'],
    eventIds: [14, 15, 16],
    pathOrRule: 'GRAPH_MULTIHOP_TIER_ESCALATION (edge-gateway -> dev-service -> secrets-vault)',
    explanation:
      'Identity svc-worker-04 traversed 2 unseen cross-tier service edges within 14s using valid credentials; causal order of hops 15 and 16 falls within 2*skew bound.',
    confidenceScore: 0.94,
    orderUncertain: true,
    lateArrival: false,
    possibleOrderings: [
      'evt-15 (dev-service) -> evt-16 (secrets-vault)',
      'evt-16 (secrets-vault) -> evt-15 (dev-service)',
    ],
    eventTimestamp: '2026-11-26T10:12:18Z',
    ingestTimestamp: '2026-11-26T10:12:34Z',
    detectedAt: '2026-11-26T10:12:48Z',
  },
];

export const SEED_METRICS: DetectionMetrics = {
  f1Score: 0.96,
  precision: 0.97,
  recall: 0.95,
  medianTimeToAlertMs: 145,
  falseAlertsPer1kBenign: 0.8,
  pqcHandshakeLatencyMs: 4.8,
  e2eThroughputOverheadPct: 6.2,
  revocationPropagationMs: 112,
  gracePeriodSeconds: 30,
  maxClockSkewSeconds: 30,
  evaluatedEventCount: 5000,
  updatedAt: '2026-11-26T10:15:00Z',
};
