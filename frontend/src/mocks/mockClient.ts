import type { UrGuardClient } from '../api/client.ts';
import type {
  AccessGraph,
  AuditRecord,
  BackupBundle,
  BackupRestoreResult,
  ChunkState,
  CrlEntry,
  DetectionMetrics,
  DeviceRecord,
  E2EMessageRecord,
  KeyEpoch,
  LogChainVerification,
  NodeAck,
  NodeInfo,
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
} from '../api/types.ts';
import {
  GENESIS_PREV_HASH,
  SEED_ACCESS_GRAPH,
  SEED_ALERTS,
  SEED_AUDIT_LOGS,
  SEED_CRL,
  SEED_DEVICES,
  SEED_EPOCHS,
  SEED_MESSAGES,
  SEED_METRICS,
  SEED_NODES,
  computeAuditEntryHash,
  deterministicHex,
} from './data.ts';

/**
 * Stateful in-memory mock implementation of UrGuardClient.
 * Mirrors Track 4 protocol behaviors (two-phase rotation, grace-period countdown,
 * staggered CRL streaming acks, backup tamper checks, canonical audit chaining,
 * replay/recipient checks) for standalone frontend development and testing.
 */
export function createMockClient(baseUrl = 'http://localhost:8080'): UrGuardClient {
  let nodes: NodeInfo[] = SEED_NODES.map((n) => ({ ...n }));
  let epochs: KeyEpoch[] = SEED_EPOCHS.map((e) => ({ ...e }));
  let devices: DeviceRecord[] = SEED_DEVICES.map((d) => ({ ...d }));
  let crl: CrlEntry[] = SEED_CRL.map((c) => ({ ...c }));
  let messages: E2EMessageRecord[] = SEED_MESSAGES.map((m) => ({ ...m }));
  let auditLogs: AuditRecord[] = SEED_AUDIT_LOGS.map((a) => ({ ...a }));
  let alerts: SecurityAlert[] = SEED_ALERTS.map((a) => ({ ...a }));
  const accessGraph: AccessGraph = {
    nodes: SEED_ACCESS_GRAPH.nodes.map((n) => ({ ...n })),
    edges: SEED_ACCESS_GRAPH.edges.map((e) => ({ ...e })),
  };
  let metrics: DetectionMetrics = { ...SEED_METRICS };

  let currentEpoch = 3;
  let previousEpoch: number | null = 2;
  let rotationPhase: RotationState['phase'] = 'IDLE';
  let gracePeriodSeconds = 30;
  let committedAt: string | null = '2026-11-26T09:30:01Z';
  let cutoffAt: string | null = null;
  let msgSeqCounter = 2;
  const seenReplayKeys = new Set<string>(['sess-7401|alice@urguard.local|1']);

  let lastExportedBackup: BackupBundle | null = null;
  const acksByCrlEpoch = new Map<number, readonly NodeAck[]>();

  const healthListeners = new Set<(health: SystemHealth) => void>();
  const auditListeners = new Set<(logs: readonly AuditRecord[]) => void>();
  const alertListeners = new Set<(nextAlerts: readonly SecurityAlert[]) => void>();

  function snapshotRotation(): RotationState {
    return {
      currentEpoch,
      previousEpoch,
      phase: rotationPhase,
      gracePeriodSeconds,
      committedAt,
      cutoffAt,
      activeInFlightTransfers: messages.filter((m) => m.status === 'IN_FLIGHT').length,
      epochs,
      nodeStates: nodes.map((n) => ({
        nodeId: n.nodeId,
        currentEpoch: n.activeKeyEpoch,
        acceptedPreviousEpoch: rotationPhase === 'COMMITTED' ? previousEpoch : null,
        phase: rotationPhase,
        updatedAt: n.lastHeartbeatAt,
      })),
    };
  }

  function snapshotHealth(): SystemHealth {
    return {
      mode: 'mock',
      apiBaseUrl: baseUrl,
      controlPlaneReady: true,
      nodes,
      rotation: snapshotRotation(),
    };
  }

  function notifyHealthListeners(): void {
    const health = snapshotHealth();
    healthListeners.forEach((listener) => {
      listener(health);
    });
  }

  function notifyAuditListeners(): void {
    auditListeners.forEach((listener) => {
      listener(auditLogs);
    });
  }

  function notifyAlertListeners(): void {
    alertListeners.forEach((listener) => {
      listener(alerts);
    });
  }

  function pushProtocolAlert(
    identity: string,
    service: string,
    pathOrRule: string,
    explanation: string,
  ): void {
    alerts = [
      {
        alertId: `alrt-${String(100 + alerts.length + 1)}`,
        identity,
        classification: 'PROTOCOL_ATTACK',
        severity: 'HIGH',
        services: [service],
        eventIds: [auditLogs.length],
        pathOrRule,
        explanation,
        confidenceScore: 1,
        orderUncertain: false,
        lateArrival: false,
        eventTimestamp: new Date().toISOString(),
        ingestTimestamp: new Date().toISOString(),
        detectedAt: new Date().toISOString(),
      },
      ...alerts,
    ];
    notifyAlertListeners();
  }

  function appendAudit(
    actorId: string,
    action: string,
    targetService: string,
    sourceNode: string,
    metadata: Record<string, string>,
    changeTicket?: string,
  ): AuditRecord {
    const prev = auditLogs[auditLogs.length - 1];
    const seq = (prev?.seq ?? 0) + 1;
    const prevHash = prev?.entryHash ?? GENESIS_PREV_HASH;
    const sortedMeta = Object.fromEntries(
      Object.entries(metadata).sort(([a], [b]) => a.localeCompare(b)),
    );
    const canonicalObj = {
      action,
      actor_id: actorId,
      payload: changeTicket
        ? { change_ticket: changeTicket, metadata: sortedMeta }
        : { metadata: sortedMeta },
      source_node: sourceNode,
      target_service: targetService,
    };
    const canonicalBody = JSON.stringify(canonicalObj);
    const entryHash = computeAuditEntryHash(seq, prevHash, canonicalBody);
    const record: AuditRecord = {
      seq,
      prevHash,
      entryHash,
      timestamp: new Date().toISOString(),
      actorId,
      action,
      targetService,
      sourceNode,
      payload: {
        metadata: sortedMeta,
        ...(changeTicket ? { changeTicket } : {}),
      },
      canonicalBody,
      ...(seq % 5 === 0
        ? { checkpointSignature: `mldsa65:cp:${String(seq)}:${entryHash.slice(0, 12)}` }
        : {}),
    };
    auditLogs = [...auditLogs, record];
    notifyAuditListeners();
    return record;
  }

  return {
    mode: 'mock',
    baseUrl,

    getSystemHealth(): Promise<SystemHealth> {
      return Promise.resolve(snapshotHealth());
    },

    subscribeSystemHealth(handlers: StreamHandlers<SystemHealth>): UnsubscribeFn {
      handlers.onData(snapshotHealth());
      healthListeners.add(handlers.onData);
      return () => {
        healthListeners.delete(handlers.onData);
      };
    },

    getRotationState(): Promise<RotationState> {
      return Promise.resolve(snapshotRotation());
    },

    prepareRotation(): Promise<RotationState> {
      rotationPhase = 'PREPARING';
      notifyHealthListeners();
      return Promise.resolve(snapshotRotation());
    },

    triggerRotation(graceSec = 30): Promise<RotationState> {
      const now = new Date();
      const cutoff = new Date(now.getTime() + graceSec * 1000);
      previousEpoch = currentEpoch;
      currentEpoch += 1;
      gracePeriodSeconds = graceSec;
      rotationPhase = 'COMMITTED';
      committedAt = now.toISOString();
      cutoffAt = cutoff.toISOString();

      epochs = [
        ...epochs.map((ep) =>
          ep.epoch === previousEpoch ? { ...ep, phase: 'COMMITTED' as const, cutoffAt } : ep,
        ),
        {
          epoch: currentEpoch,
          kemAlgorithm: 'X25519+ML-KEM-768',
          sigAlgorithm: 'ML-DSA-65',
          publicKeyFingerprint: `mldsa65:${deterministicHex(`epoch-${String(currentEpoch)}`, 16)}`,
          phase: 'COMMITTED',
          createdAt: committedAt,
          committedAt,
          cutoffAt: null,
          gracePeriodSeconds,
        },
      ];

      nodes = nodes.map((n) => ({
        ...n,
        activeKeyEpoch: currentEpoch,
        lastHeartbeatAt: committedAt ?? n.lastHeartbeatAt,
      }));

      appendAudit(
        'admin@urguard.local',
        'KEY_ROTATION_COMMITTED',
        'key-authority',
        'controlplane',
        {
          epoch: String(currentEpoch),
          previous_epoch: String(previousEpoch),
          grace_period_seconds: String(gracePeriodSeconds),
        },
      );
      notifyHealthListeners();

      return Promise.resolve(snapshotRotation());
    },

    enforceRotationCutoff(): Promise<RotationState> {
      const nowIso = new Date().toISOString();
      rotationPhase = 'CUTOFF_ENFORCED';
      cutoffAt = nowIso;
      epochs = epochs.map((ep) =>
        ep.epoch === previousEpoch
          ? { ...ep, phase: 'CUTOFF_ENFORCED', cutoffAt: nowIso }
          : ep.epoch === currentEpoch
            ? { ...ep, phase: 'IDLE' }
            : ep,
      );
      appendAudit(
        'key-authority',
        'KEY_ROTATION_CUTOFF_ENFORCED',
        'key-authority',
        'controlplane',
        {
          retired_epoch: String(previousEpoch ?? currentEpoch - 1),
          active_epoch: String(currentEpoch),
        },
      );
      notifyHealthListeners();
      return Promise.resolve(snapshotRotation());
    },

    listDevices(): Promise<readonly DeviceRecord[]> {
      return Promise.resolve(devices);
    },

    listCrl(): Promise<readonly CrlEntry[]> {
      return Promise.resolve(crl);
    },

    revokeDevice(deviceId: string, reason: string): Promise<RevocationResult> {
      const now = new Date();
      const tRevoked = now.toISOString();
      const nextCrlEpoch = (crl[crl.length - 1]?.crlEpoch ?? 0) + 1;
      const target = devices.find((d) => d.deviceId === deviceId);

      devices = devices.map((d) =>
        d.deviceId === deviceId ? { ...d, status: 'REVOKED', revokedAt: tRevoked } : d,
      );

      const entry: CrlEntry = {
        crlEpoch: nextCrlEpoch,
        revokedKeyId: target?.ikFingerprint ?? `ik:${deviceId}`,
        revokedDeviceId: deviceId,
        reason,
        issuedAt: tRevoked,
        signatureHex: `mldsa65sig:${deterministicHex(`${String(nextCrlEpoch)}|${deviceId}`, 28)}`,
      };
      crl = [...crl, entry];

      const latencies = [42, 78, 114];
      const nodeAcks: NodeAck[] = nodes.map((n, idx) => {
        const propagationMs = latencies[idx % latencies.length] ?? 95;
        return {
          nodeId: n.nodeId,
          nodeName: n.name,
          crlEpoch: nextCrlEpoch,
          acknowledgedAt: new Date(now.getTime() + propagationMs).toISOString(),
          propagationMs,
          enforced: true,
        };
      });
      acksByCrlEpoch.set(nextCrlEpoch, nodeAcks);

      const maxPropagation = Math.max(...nodeAcks.map((a) => a.propagationMs));
      const tEnforcedLastNode = new Date(now.getTime() + maxPropagation).toISOString();

      nodes = nodes.map((n) => ({
        ...n,
        crlEpoch: nextCrlEpoch,
        lastHeartbeatAt: tEnforcedLastNode,
      }));
      metrics = {
        ...metrics,
        revocationPropagationMs: maxPropagation,
        updatedAt: tEnforcedLastNode,
      };

      appendAudit('admin@urguard.local', 'DEVICE_REVOKED', 'key-authority', 'controlplane', {
        revoked_device_id: deviceId,
        crl_epoch: String(nextCrlEpoch),
        revocation_propagation_ms: String(maxPropagation),
      });
      notifyHealthListeners();

      return Promise.resolve({
        entry,
        tRevoked,
        tEnforcedLastNode,
        revocationPropagationMs: maxPropagation,
        nodeAcks,
      });
    },

    subscribeRevocationAcks(crlEpoch: number, handlers: StreamHandlers<NodeAck>): UnsubscribeFn {
      const acks = acksByCrlEpoch.get(crlEpoch) ?? [];
      if (acks.length === 0) {
        handlers.onComplete?.();
        return () => undefined;
      }

      const timers: ReturnType<typeof setTimeout>[] = [];
      let cancelled = false;

      acks.forEach((ack, index) => {
        const timer = setTimeout(() => {
          if (cancelled) return;
          handlers.onData(ack);
          if (index === acks.length - 1) {
            handlers.onComplete?.();
          }
        }, ack.propagationMs);
        timers.push(timer);
      });

      return () => {
        cancelled = true;
        timers.forEach((timer) => {
          clearTimeout(timer);
        });
      };
    },

    reEnrollDevice(
      revokedDeviceId: string,
      newDeviceId: string,
      ownerId: string,
    ): Promise<ReEnrollResult> {
      const nowIso = new Date().toISOString();
      const newDevice: DeviceRecord = {
        deviceId: newDeviceId,
        ownerId,
        role: 'security-operator',
        ikFingerprint: `ik:mldsa65:${deterministicHex(newDeviceId, 12)}`,
        status: 'ACTIVE',
        enrolledAt: nowIso,
        revokedAt: null,
      };
      devices = [...devices, newDevice];
      const dekHolderDevices = devices.filter(
        (d) => d.status === 'ACTIVE' && d.deviceId !== revokedDeviceId,
      );
      const retainedCollaborators = dekHolderDevices
        .filter((d) => d.deviceId !== newDeviceId)
        .map((d) => d.ownerId);

      appendAudit(ownerId, 'DEVICE_REENROLLED', 'key-authority', 'controlplane', {
        revoked_device_id: revokedDeviceId,
        new_device_id: newDeviceId,
        reencapsulated_deks: String(dekHolderDevices.length),
      });

      return Promise.resolve({
        revokedDeviceId,
        newDevice,
        reEncapsulatedDekCount: dekHolderDevices.length,
        retainedCollaborators,
        dekHolderDevices,
      });
    },

    exportBackup(): Promise<BackupBundle> {
      const nowIso = new Date().toISOString();
      const ciphertextBase64 = btoa(
        `urguard-keystore-epoch-${String(currentEpoch)}-crl-${String(crl.length)}`,
      );
      const sha256Manifest = deterministicHex(`${String(currentEpoch)}|${ciphertextBase64}`, 64);
      const bundle: BackupBundle = {
        header: {
          formatVersion: '1.0',
          backupId: `bkp-${deterministicHex(nowIso, 10)}`,
          createdAt: nowIso,
          keyEpoch: currentEpoch,
          sha256Manifest,
        },
        ciphertextBase64,
        signatureBase64: btoa(`mldsa65-sig:${sha256Manifest}`),
      };
      lastExportedBackup = bundle;
      appendAudit('admin@urguard.local', 'BACKUP_EXPORTED', 'key-authority', 'controlplane', {
        backup_id: bundle.header.backupId,
        key_epoch: String(currentEpoch),
      });
      return Promise.resolve(bundle);
    },

    restoreBackup(bundle: BackupBundle): Promise<BackupRestoreResult> {
      const expectedManifest = deterministicHex(
        `${String(bundle.header.keyEpoch)}|${bundle.ciphertextBase64}`,
        64,
      );
      const expectedSig = btoa(`mldsa65-sig:${expectedManifest}`);
      const verifiedManifest = bundle.header.sha256Manifest === expectedManifest;
      const verifiedSignature = bundle.signatureBase64 === expectedSig;
      const verifiedAeadTag =
        lastExportedBackup === null
          ? verifiedManifest && verifiedSignature
          : bundle.ciphertextBase64 === lastExportedBackup.ciphertextBase64;

      if (!verifiedManifest || !verifiedSignature || !verifiedAeadTag) {
        appendAudit(
          'admin@urguard.local',
          'BACKUP_INTEGRITY_FAILURE',
          'key-authority',
          'controlplane',
          {
            backup_id: bundle.header.backupId,
            error_code: 'ERR_BACKUP_CORRUPTED',
          },
        );
        return Promise.resolve({
          success: false,
          errorCode: 'ERR_BACKUP_CORRUPTED',
          verifiedSignature,
          verifiedAeadTag,
          verifiedManifest,
          message: 'Restore aborted (ERR_BACKUP_CORRUPTED); live key material left untouched.',
        });
      }

      appendAudit('admin@urguard.local', 'BACKUP_RESTORED', 'key-authority', 'controlplane', {
        backup_id: bundle.header.backupId,
      });

      return Promise.resolve({
        success: true,
        verifiedSignature: true,
        verifiedAeadTag: true,
        verifiedManifest: true,
        message: 'Backup signature, AES-256-GCM tag, and SHA-256 manifest verified.',
      });
    },

    sendE2EMessage(input: SendE2EMessageInput): Promise<E2EMessageRecord> {
      const epochUsed = input.keyEpoch ?? currentEpoch;
      const expired =
        epochUsed < currentEpoch &&
        (rotationPhase === 'CUTOFF_ENFORCED' || rotationPhase === 'IDLE');
      const totalChunks = Math.max(1, input.chunkCount ?? 1);
      const transferId = `xfer-${String(messages.length + 1).padStart(4, '0')}`;
      const msgSeq = msgSeqCounter;
      msgSeqCounter += 1;
      const sessionId = 'sess-7401';
      const droppedSet = new Set(input.dropChunkIndices ?? []);
      const deliveredOrder =
        input.deliveryOrder && input.deliveryOrder.length > 0
          ? input.deliveryOrder.filter((idx) => !droppedSet.has(idx))
          : Array.from({ length: totalChunks }, (_, idx) => idx).filter(
              (idx) => !droppedSet.has(idx),
            );
      const rootManifestHash = `sha256:${deterministicHex(`${transferId}|${input.payload}`, 16)}`;

      const chunks: ChunkState[] = Array.from({ length: totalChunks }, (_, idx) => {
        const received = !droppedSet.has(idx);
        return {
          chunkIndex: idx,
          totalChunks,
          transferId,
          chunkHash: `sha256:${deterministicHex(`${transferId}|${String(idx)}`, 12)}`,
          rootManifestHash,
          received,
          verified: received && !expired,
        };
      });

      const hasMissing = chunks.some((c) => !c.received);
      const status: E2EMessageRecord['status'] = expired
        ? 'REJECTED'
        : hasMissing
          ? 'DELIVERY_FAILED'
          : 'DELIVERED';
      const errorCode = expired
        ? 'ERR_KEY_EPOCH_EXPIRED'
        : hasMissing
          ? 'DELIVERY_FAILED'
          : undefined;

      seenReplayKeys.add(`${sessionId}|${input.senderId}|${String(msgSeq)}`);

      const record: E2EMessageRecord = {
        transferId,
        header: {
          senderId: input.senderId,
          recipientId: input.recipientId,
          sessionId,
          keyEpoch: epochUsed,
          msgSeq,
          nonceHex: deterministicHex(`${transferId}|nonce`, 24),
          timestamp: new Date().toISOString(),
        },
        kemAlgorithm: 'X25519+ML-KEM-768',
        aeadAlgorithm: 'AES-256-GCM',
        sigAlgorithm: 'ML-DSA-65',
        aadCanonical: `${input.senderId}|${input.recipientId}|${sessionId}|${String(epochUsed)}|${String(msgSeq)}`,
        signatureValid: !expired,
        ephemeralZeroized: true,
        status,
        ...(errorCode ? { errorCode } : {}),
        chunks,
        deliveredOrder,
        ...(status === 'DELIVERED' ? { plaintextPreview: input.payload } : {}),
        latencyMs: 5.2,
      };

      const relayNode = input.relayNode ?? 'node-a';
      messages = [record, ...messages];
      appendAudit(
        input.senderId,
        status === 'DELIVERED' ? 'E2E_ENVELOPE_DELIVERED' : status,
        `relay-${relayNode}`,
        relayNode,
        {
          transfer_id: transferId,
          recipient: input.recipientId,
          key_epoch: String(epochUsed),
          ...(errorCode ? { error_code: errorCode } : {}),
        },
      );
      if (status === 'DELIVERY_FAILED') {
        pushProtocolAlert(
          input.senderId,
          `relay-${relayNode}`,
          'CHUNK_INTEGRITY_INCOMPLETE',
          `Transfer ${transferId} dropped missing chunk(s); partial plaintext discarded (${errorCode ?? 'DELIVERY_FAILED'}).`,
        );
      }

      return Promise.resolve(record);
    },

    listMessages(): Promise<readonly E2EMessageRecord[]> {
      return Promise.resolve(messages);
    },

    replayMessage(transferId: string): Promise<E2EMessageRecord> {
      const original = messages.find((m) => m.transferId === transferId) ?? messages[0];
      if (!original) {
        return Promise.reject(new Error(`Message ${transferId} not found`));
      }
      const rejected: E2EMessageRecord = {
        ...original,
        transferId: `${original.transferId}-replay`,
        status: 'REJECTED',
        errorCode: 'ERR_REPLAY_DETECTED',
        plaintextPreview: undefined,
      };
      appendAudit(original.header.senderId, 'REPLAY_REJECTED', 'relay-node-b', 'node-b', {
        transfer_id: original.transferId,
        msg_seq: String(original.header.msgSeq),
        error_code: 'ERR_REPLAY_DETECTED',
      });
      pushProtocolAlert(
        original.header.senderId,
        'relay-node-b',
        'REPLAY_WINDOW_DUPLICATE',
        `Duplicate envelope (${original.header.sessionId}, msg_seq=${String(original.header.msgSeq)}) rejected with ERR_REPLAY_DETECTED.`,
      );
      return Promise.resolve(rejected);
    },

    tamperRecipient(transferId: string, forgedRecipientId: string): Promise<E2EMessageRecord> {
      const original = messages.find((m) => m.transferId === transferId) ?? messages[0];
      if (!original) {
        return Promise.reject(new Error(`Message ${transferId} not found`));
      }
      const rejected: E2EMessageRecord = {
        ...original,
        transferId: `${original.transferId}-tampered`,
        header: { ...original.header, recipientId: forgedRecipientId },
        signatureValid: false,
        status: 'REJECTED',
        errorCode: 'ERR_RECIPIENT_MISMATCH',
        plaintextPreview: undefined,
      };
      appendAudit(original.header.senderId, 'RECIPIENT_BINDING_FAILED', 'relay-node-b', 'node-b', {
        transfer_id: original.transferId,
        forged_recipient: forgedRecipientId,
        error_code: 'ERR_RECIPIENT_MISMATCH',
      });
      pushProtocolAlert(
        original.header.senderId,
        'relay-node-b',
        'AEAD_AAD_RECIPIENT_MISMATCH',
        `Modified recipient_id (${forgedRecipientId}) failed AES-256-GCM AAD + ML-DSA-65 verification (ERR_RECIPIENT_MISMATCH).`,
      );
      return Promise.resolve(rejected);
    },

    issueResumptionTicket(identity: string): Promise<ResumptionTicket> {
      const now = new Date();
      return Promise.resolve({
        sessionId: `sess-res-${deterministicHex(identity, 6)}`,
        authenticatedPeerId: identity,
        peerIkFingerprint: `ik:mldsa65:${deterministicHex(identity, 12)}`,
        issuedAt: now.toISOString(),
        expiresAt: new Date(now.getTime() + 300_000).toISOString(),
      });
    },

    resumeSession(
      ticket: ResumptionTicket,
      presenterIdentity: string,
    ): Promise<SessionResumptionResult> {
      const accepted = presenterIdentity === ticket.authenticatedPeerId;
      if (!accepted) {
        appendAudit(presenterIdentity, 'SESSION_HIJACK_ATTEMPT', 'relay-node-c', 'node-c', {
          session_id: ticket.sessionId,
          ticket_peer: ticket.authenticatedPeerId,
          error_code: 'ERR_SESSION_IDENTITY_MISMATCH',
        });
        pushProtocolAlert(
          presenterIdentity,
          'relay-node-c',
          'SESSION_RESUMPTION_BINDING_MISMATCH',
          `Identity ${presenterIdentity} attempted to resume ticket bound to ${ticket.authenticatedPeerId}.`,
        );
        return Promise.resolve({
          accepted: false,
          errorCode: 'ERR_SESSION_IDENTITY_MISMATCH',
          presentedIdentity: presenterIdentity,
          ticketPeerId: ticket.authenticatedPeerId,
          message:
            'Session resume rejected: ML-DSA-65 challenge signature does not match ticket peer.',
        });
      }

      return Promise.resolve({
        accepted: true,
        presentedIdentity: presenterIdentity,
        ticketPeerId: ticket.authenticatedPeerId,
        message: 'Session resumed with verified peer identity challenge signature.',
      });
    },

    listAuditLogs(): Promise<readonly AuditRecord[]> {
      return Promise.resolve(auditLogs);
    },

    subscribeAuditLogs(handlers: StreamHandlers<readonly AuditRecord[]>): UnsubscribeFn {
      handlers.onData(auditLogs);
      auditListeners.add(handlers.onData);
      return () => {
        auditListeners.delete(handlers.onData);
      };
    },

    appendUserAuditTest(actorId: string, userMetadataText: string): Promise<AuditRecord> {
      const record = appendAudit(actorId, 'USER_METADATA_SUBMITTED', 'relay-node-a', 'node-a', {
        user_input: userMetadataText,
      });
      return Promise.resolve(record);
    },

    tamperAuditRecord(seq: number): Promise<AuditRecord> {
      const target = auditLogs.find((r) => r.seq === seq);
      if (!target) {
        return Promise.reject(new Error(`Audit seq ${String(seq)} not found`));
      }
      const tampered: AuditRecord = {
        ...target,
        canonicalBody: `${target.canonicalBody}/*tampered*/`,
      };
      auditLogs = auditLogs.map((r) => (r.seq === seq ? tampered : r));
      notifyAuditListeners();
      return Promise.resolve(tampered);
    },

    verifyLogChain(tamperSeq?: number): Promise<LogChainVerification> {
      if (tamperSeq !== undefined && tamperSeq >= 1 && tamperSeq <= auditLogs.length) {
        return Promise.resolve({
          valid: false,
          totalRecords: auditLogs.length,
          lastVerifiedSeq: tamperSeq - 1,
          brokenSeq: tamperSeq,
          reason: `SHA-256 chain mismatch at seq ${String(tamperSeq)}: entry_hash does not match canonical_body`,
          verifiedAt: new Date().toISOString(),
          checkpointVerified: false,
        });
      }

      let expectedPrevHash = GENESIS_PREV_HASH;
      for (const record of auditLogs) {
        const expectedHash = computeAuditEntryHash(
          record.seq,
          expectedPrevHash,
          record.canonicalBody,
        );
        if (record.prevHash !== expectedPrevHash || record.entryHash !== expectedHash) {
          return Promise.resolve({
            valid: false,
            totalRecords: auditLogs.length,
            lastVerifiedSeq: record.seq - 1,
            brokenSeq: record.seq,
            reason: `SHA-256 chain mismatch at seq ${String(record.seq)}: entry_hash does not match canonical_body`,
            verifiedAt: new Date().toISOString(),
            checkpointVerified: false,
          });
        }
        expectedPrevHash = record.entryHash;
      }

      const last = auditLogs[auditLogs.length - 1];
      return Promise.resolve({
        valid: true,
        totalRecords: auditLogs.length,
        lastVerifiedSeq: last?.seq ?? 0,
        brokenSeq: null,
        reason: null,
        verifiedAt: new Date().toISOString(),
        checkpointVerified: true,
      });
    },

    listAlerts(): Promise<readonly SecurityAlert[]> {
      return Promise.resolve(alerts);
    },

    subscribeAlerts(handlers: StreamHandlers<readonly SecurityAlert[]>): UnsubscribeFn {
      handlers.onData(alerts);
      alertListeners.add(handlers.onData);
      return () => {
        alertListeners.delete(handlers.onData);
      };
    },

    getAccessGraph(): Promise<AccessGraph> {
      return Promise.resolve(accessGraph);
    },

    getMetrics(): Promise<DetectionMetrics> {
      return Promise.resolve(metrics);
    },
  };
}
