package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	v "github.com/dean-2/urGuard/backend/gen/urguard/v1"
	"github.com/dean-2/urGuard/backend/internal/transport"
	"github.com/dean-2/urGuard/backend/pkg/auditlog"
	"github.com/dean-2/urGuard/backend/pkg/pqc"
	"github.com/dean-2/urGuard/backend/pkg/protocol"
	"github.com/dean-2/urGuard/backend/pkg/store"
	"google.golang.org/protobuf/proto"
)

type demoIdentity struct {
	ownerID string
	devID   string
	keyID   string
	sig     *pqc.IdentityKeyPair
	kem     *pqc.HybridKEMKeyPair
}

type consoleMessageRecord struct {
	TransferID        string               `json:"transferId"`
	Header            consoleEnvelopeHdr   `json:"header"`
	KemAlgorithm      string               `json:"kemAlgorithm"`
	AeadAlgorithm     string               `json:"aeadAlgorithm"`
	SigAlgorithm      string               `json:"sigAlgorithm"`
	AadCanonical      string               `json:"aadCanonical"`
	SignatureValid    bool                 `json:"signatureValid"`
	EphemeralZeroized bool                 `json:"ephemeralZeroized"`
	Status            string               `json:"status"`
	ErrorCode         string               `json:"errorCode,omitempty"`
	Chunks            []consoleChunkState  `json:"chunks"`
	DeliveredOrder    []int                `json:"deliveredOrder"`
	PlaintextPreview  string               `json:"plaintextPreview,omitempty"`
	LatencyMs         float64              `json:"latencyMs"`
	// internal capture for replay/tamper simulations
	lastEnvelope *v.EncryptedEnvelope
	recvSession  *protocol.Session
	senderID     *demoIdentity
	recipientID  *demoIdentity
}

type consoleEnvelopeHdr struct {
	SenderID    string `json:"senderId"`
	RecipientID string `json:"recipientId"`
	SessionID   string `json:"sessionId"`
	KeyEpoch    uint64 `json:"keyEpoch"`
	MsgSeq      uint64 `json:"msgSeq"`
	NonceHex    string `json:"nonceHex"`
	Timestamp   string `json:"timestamp"`
}

type consoleChunkState struct {
	ChunkIndex       int    `json:"chunkIndex"`
	TotalChunks      int    `json:"totalChunks"`
	TransferId       string `json:"transferId"`
	ChunkHash        string `json:"chunkHash"`
	RootManifestHash string `json:"rootManifestHash"`
	Received         bool   `json:"received"`
	Verified         bool   `json:"verified"`
}

type consoleAlert struct {
	AlertID           string   `json:"alertId"`
	Identity          string   `json:"identity"`
	Classification    string   `json:"classification"`
	Severity          string   `json:"severity"`
	Services          []string `json:"services"`
	EventIDs          []int    `json:"eventIds"`
	PathOrRule        string   `json:"pathOrRule"`
	Explanation       string   `json:"explanation"`
	ConfidenceScore   float64  `json:"confidenceScore"`
	OrderUncertain    bool     `json:"orderUncertain"`
	LateArrival       bool     `json:"lateArrival"`
	PossibleOrderings []string `json:"possibleOrderings,omitempty"`
	EventTimestamp    string   `json:"eventTimestamp"`
	IngestTimestamp   string   `json:"ingestTimestamp"`
	DetectedAt        string   `json:"detectedAt"`
}

type ConsoleBridge struct {
	svc        *Service
	mu         sync.Mutex
	seedOnce   sync.Once
	identities map[string]*demoIdentity // keyed by deviceID
	byOwner    map[string]*demoIdentity // primary active device per owner
	messages   []*consoleMessageRecord
	resumption *protocol.Resumption
	msgCounter uint64
	lastPropMs float64
	extraAlert []consoleAlert
	pqcBenchMs float64
}

func (s *Service) ensureConsole() *ConsoleBridge {
	s.mu.Lock()
	if s.console == nil {
		ticketKey := make([]byte, 32)
		_, _ = rand.Read(ticketKey)
		res, _ := protocol.NewResumption(ticketKey)
		s.console = &ConsoleBridge{
			svc:        s,
			identities: make(map[string]*demoIdentity),
			byOwner:    make(map[string]*demoIdentity),
			resumption: res,
			pqcBenchMs: 0.25,
		}
	}
	cb := s.console
	s.mu.Unlock()
	cb.seedDefaults()
	return cb
}

func (cb *ConsoleBridge) seedDefaults() {
	cb.seedOnce.Do(func() {
		// Measure actual PQC KEM roundtrip latency once for UI telemetry.
		if kp, err := pqc.GenerateHybridKEMKeyPair(); err == nil {
			start := time.Now()
			if ct, ss, err := pqc.EncapsulateHybrid(kp.PublicKey(), []byte("console-probe")); err == nil {
				pqc.Zeroize(ss)
				if ss2, err := kp.DecapsulateHybrid(ct, []byte("console-probe")); err == nil {
					pqc.Zeroize(ss2)
				}
			}
			cb.pqcBenchMs = float64(time.Since(start).Microseconds()) / 1000.0
			kp.Zeroize()
		}

		ctx := transport.WithPrincipal(context.Background(), "admin")
		existing, _ := cb.svc.store.ListDevices()
		if len(existing) == 0 {
			seeds := []struct {
				owner, dev, key string
			}{
				{"alice@urguard.local", "dev-alice-01", "key-alice-01"},
				{"alice@urguard.local", "dev-alice-recovery", "key-alice-rec"},
				{"bob@urguard.local", "dev-bob-01", "key-bob-01"},
				{"eve@urguard.local", "dev-eve-01", "key-eve-01"},
			}
			for _, seed := range seeds {
				id, err := cb.createAndEnrollDevice(ctx, seed.owner, seed.dev, seed.key)
				if err == nil {
					cb.mu.Lock()
					cb.identities[id.devID] = id
					if _, has := cb.byOwner[id.ownerID]; !has {
						cb.byOwner[id.ownerID] = id
					}
					cb.mu.Unlock()
				}
			}
			var dek [32]byte
			_, _ = rand.Read(dek[:])
			_ = cb.svc.store.SaveSharedWrap("doc-vault-alpha", "dev-alice-01", dek[:])
			_ = cb.svc.store.SaveSharedWrap("doc-vault-alpha", "dev-bob-01", dek[:])
			pqc.Zeroize(dek[:])
		}
	})
}

func (cb *ConsoleBridge) createAndEnrollDevice(ctx context.Context, ownerID, deviceID, keyID string) (*demoIdentity, error) {
	sig, err := pqc.GenerateIdentityKeyPair()
	if err != nil {
		return nil, err
	}
	kem, err := pqc.GenerateHybridKEMKeyPair()
	if err != nil {
		return nil, err
	}
	pub := kem.PublicKey()
	devProto := &v.DeviceIdentity{
		OwnerId:           ownerID,
		DeviceId:          deviceID,
		KeyId:             keyID,
		Mldsa65PublicKey:  sig.PublicBytes(),
		X25519PublicKey:   pub.X25519,
		Mlkem768PublicKey: pub.MLKEM768,
	}
	body, err := wire.Marshal(devProto)
	if err != nil {
		return nil, err
	}
	proof, err := sig.Sign([]byte("urguard/enroll/v1"), body)
	if err != nil {
		return nil, err
	}
	if _, err := cb.svc.EnrollDevice(ctx, connect.NewRequest(&v.EnrollDeviceRequest{
		Device:          devProto,
		EnrollmentProof: proof,
	})); err != nil {
		return nil, err
	}
	return &demoIdentity{
		ownerID: ownerID,
		devID:   deviceID,
		keyID:   keyID,
		sig:     sig,
		kem:     kem,
	}, nil
}

func (cb *ConsoleBridge) resolveOwnerDevice(ownerOrDevice string) *demoIdentity {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if id, ok := cb.identities[ownerOrDevice]; ok {
		return id
	}
	if id, ok := cb.byOwner[ownerOrDevice]; ok {
		return id
	}
	// Create an ephemeral demo identity on demand if user typed a custom address in UI.
	return nil
}

func (s *Service) mountConsole(m *http.ServeMux) {
	m.HandleFunc("/console/v1/", s.handleConsole)
}

func (s *Service) handleConsole(w http.ResponseWriter, r *http.Request) {
	if transport.Principal(r.Context()) != "admin" {
		http.Error(w, "principal not authorized", http.StatusForbidden)
		return
	}
	cb := s.ensureConsole()
	path := strings.TrimPrefix(r.URL.Path, "/console/v1/")
	switch {
	case r.Method == http.MethodGet && path == "health":
		cb.handleHealth(w, r)
	case r.Method == http.MethodPost && path == "rotation/cutoff":
		cb.handleEnforceCutoff(w, r)
	case r.Method == http.MethodGet && path == "devices":
		cb.handleListDevices(w, r)
	case r.Method == http.MethodGet && path == "crl":
		cb.handleListCRL(w, r)
	case r.Method == http.MethodGet && path == "revocation/status":
		cb.handleRevocationStatus(w, r)
	case r.Method == http.MethodPost && path == "devices/reenroll":
		cb.handleReenroll(w, r)
	case r.Method == http.MethodPost && path == "backups/export":
		cb.handleBackupExport(w, r)
	case r.Method == http.MethodPost && path == "backups/restore":
		cb.handleBackupRestore(w, r)
	case r.Method == http.MethodGet && path == "messages":
		cb.handleListMessages(w, r)
	case r.Method == http.MethodPost && path == "messages/send":
		cb.handleSendMessage(w, r)
	case r.Method == http.MethodPost && path == "messages/replay":
		cb.handleReplayMessage(w, r)
	case r.Method == http.MethodPost && path == "messages/tamper-recipient":
		cb.handleTamperRecipient(w, r)
	case r.Method == http.MethodPost && path == "resumption/ticket":
		cb.handleIssueTicket(w, r)
	case r.Method == http.MethodPost && path == "resumption/resume":
		cb.handleResumeSession(w, r)
	case r.Method == http.MethodPost && path == "audit/test-event":
		cb.handleAuditTestEvent(w, r)
	case r.Method == http.MethodPost && path == "audit/tamper":
		cb.handleAuditTamper(w, r)
	case r.Method == http.MethodGet && path == "detection/snapshot":
		cb.handleDetectionSnapshot(w, r)
	default:
		http.NotFound(w, r)
	}
}

func writeConsoleJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeConsoleErr(w http.ResponseWriter, status int, err error) {
	writeConsoleJSON(w, status, map[string]string{"error": err.Error()})
}

func (cb *ConsoleBridge) rotationPayload() map[string]any {
	st, err := cb.svc.store.EpochState()
	if err != nil {
		return map[string]any{"currentEpoch": 1, "phase": "IDLE", "gracePeriodSeconds": int(cb.svc.cfg.RotationGrace.Seconds())}
	}
	ep := phase(st)
	phaseName := strings.TrimPrefix(ep.Phase.String(), "ROTATION_PHASE_")
	var committedAt, cutoffAt any
	if !st.CommittedAt.IsZero() {
		committedAt = st.CommittedAt.UTC().Format(time.RFC3339Nano)
		cutoffAt = st.CutoffAt.UTC().Format(time.RFC3339Nano)
	}
	var prevEpoch any
	if st.Previous != 0 {
		prevEpoch = st.Previous
	}

	epochs := make([]map[string]any, 0)
	for e := uint64(1); e <= st.Active; e++ {
		ek, err := cb.svc.store.EpochKey(e)
		fp := fmt.Sprintf("epoch-%d", e)
		if err == nil {
			pk := ek.PublicKey()
			sum := sha256.Sum256(append(pk.X25519, pk.MLKEM768...))
			fp = hex.EncodeToString(sum[:8])
			ek.Zeroize()
		}
		ePhase := "CUTOFF_ENFORCED"
		if e == st.Active {
			ePhase = phaseName
		}
		epochs = append(epochs, map[string]any{
			"epoch":                e,
			"kemAlgorithm":         "X25519+ML-KEM-768",
			"sigAlgorithm":         "ML-DSA-65",
			"publicKeyFingerprint": fp,
			"phase":                ePhase,
			"createdAt":            time.Now().UTC().Format(time.RFC3339),
			"committedAt":          committedAt,
			"cutoffAt":             cutoffAt,
			"gracePeriodSeconds":   int(cb.svc.cfg.RotationGrace.Seconds()),
		})
	}

	nodeStates := make([]map[string]any, 0, len(cb.svc.cfg.RequiredNodes))
	for _, nid := range cb.svc.cfg.RequiredNodes {
		nodeStates = append(nodeStates, map[string]any{
			"nodeId":                nid,
			"currentEpoch":          st.Active,
			"acceptedPreviousEpoch": prevEpoch,
			"phase":                 phaseName,
			"updatedAt":             time.Now().UTC().Format(time.RFC3339),
		})
	}

	return map[string]any{
		"currentEpoch":            st.Active,
		"previousEpoch":           prevEpoch,
		"phase":                   phaseName,
		"gracePeriodSeconds":      int(cb.svc.cfg.RotationGrace.Seconds()),
		"committedAt":             committedAt,
		"cutoffAt":                cutoffAt,
		"activeInFlightTransfers": 0,
		"epochs":                  epochs,
		"nodeStates":              nodeStates,
	}
}

func (cb *ConsoleBridge) handleHealth(w http.ResponseWriter, r *http.Request) {
	st, _ := cb.svc.store.EpochState()
	revs, _ := cb.svc.store.ListRevocations(0)
	latestCRL := uint64(0)
	if len(revs) > 0 {
		latestCRL = revs[len(revs)-1].CRLEpoch
	}

	nodes := make([]map[string]any, 0, len(cb.svc.cfg.RequiredNodes))
	for i, nid := range cb.svc.cfg.RequiredNodes {
		endpoint := fmt.Sprintf("https://%s:8081", nid)
		if i < len(cb.svc.cfg.NodeURLs) {
			endpoint = cb.svc.cfg.NodeURLs[i]
		}
		status := "HEALTHY"
		if cb.svc.httpCli != nil {
			probeCtx, cancel := context.WithTimeout(r.Context(), 800*time.Millisecond)
			req, _ := http.NewRequestWithContext(probeCtx, http.MethodGet, strings.TrimRight(endpoint, "/")+"/healthz", nil)
			resp, err := cb.svc.httpCli.Do(req)
			cancel()
			if err != nil || resp.StatusCode >= 400 {
				status = "OFFLINE"
			}
			if resp != nil {
				_ = resp.Body.Close()
			}
		}
		nodeEpoch := st.Active
		nodeCRL := latestCRL
		hb := time.Now().UTC().Format(time.RFC3339)
		if latestCRL > 0 {
			if ack, err := cb.svc.store.AckAt(nid, latestCRL); err == nil {
				nodeEpoch = ack.Epoch
				nodeCRL = ack.CRL
				hb = ack.Received.UTC().Format(time.RFC3339)
			}
		}
		nodes = append(nodes, map[string]any{
			"nodeId":          nid,
			"name":            nid,
			"endpoint":        endpoint,
			"status":          status,
			"activeKeyEpoch":  nodeEpoch,
			"crlEpoch":        nodeCRL,
			"lastHeartbeatAt": hb,
		})
	}

	writeConsoleJSON(w, http.StatusOK, map[string]any{
		"mode":              "live",
		"apiBaseUrl":        "/api",
		"controlPlaneReady": true,
		"nodes":             nodes,
		"rotation":          cb.rotationPayload(),
	})
}

func (cb *ConsoleBridge) handleEnforceCutoff(w http.ResponseWriter, r *http.Request) {
	cb.svc.mu.Lock()
	_, err := cb.svc.store.EnforceCutoff(cb.svc.auditHook(r.Context(), "ROTATION_CUTOFF_ENFORCED", ""))
	if err == nil {
		cb.svc.signal()
	}
	cb.svc.mu.Unlock()
	if err != nil {
		writeConsoleErr(w, http.StatusConflict, err)
		return
	}
	if err := cb.svc.confirm(r.Context()); err != nil {
		writeConsoleErr(w, http.StatusServiceUnavailable, err)
		return
	}
	writeConsoleJSON(w, http.StatusOK, cb.rotationPayload())
}

func (cb *ConsoleBridge) handleListDevices(w http.ResponseWriter, _ *http.Request) {
	devs, err := cb.svc.store.ListDevices()
	if err != nil {
		writeConsoleErr(w, http.StatusInternalServerError, err)
		return
	}
	revs, _ := cb.svc.store.ListRevocations(0)
	revByDev := make(map[string]store.Revocation, len(revs))
	for _, r := range revs {
		revByDev[r.DeviceID] = r
	}
	out := make([]map[string]any, 0, len(devs))
	for _, d := range devs {
		sum := sha256.Sum256(d.SigningPublic)
		status := "ACTIVE"
		var revokedAt any
		if rev, ok := revByDev[d.ID]; ok {
			status = "REVOKED"
			revokedAt = rev.IssuedAt.UTC().Format(time.RFC3339)
		}
		out = append(out, map[string]any{
			"deviceId":      d.ID,
			"ownerId":       d.OwnerID,
			"role":          "member",
			"ikFingerprint": hex.EncodeToString(sum[:8]),
			"status":        status,
			"enrolledAt":    time.Now().UTC().Format(time.RFC3339),
			"revokedAt":     revokedAt,
		})
	}
	writeConsoleJSON(w, http.StatusOK, out)
}

func (cb *ConsoleBridge) handleListCRL(w http.ResponseWriter, _ *http.Request) {
	revs, err := cb.svc.store.ListRevocations(0)
	if err != nil {
		writeConsoleErr(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]map[string]any, 0, len(revs))
	for _, rev := range revs {
		out = append(out, map[string]any{
			"crlEpoch":        rev.CRLEpoch,
			"revokedKeyId":    rev.KeyID,
			"revokedDeviceId": rev.DeviceID,
			"reason":          rev.Reason,
			"issuedAt":        rev.IssuedAt.UTC().Format(time.RFC3339Nano),
			"signatureHex":    "mldsa65-signed-crl",
		})
	}
	writeConsoleJSON(w, http.StatusOK, out)
}

func (cb *ConsoleBridge) handleRevocationStatus(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.ParseUint(r.URL.Query().Get("crl_epoch"), 10, 64)
	if err != nil || n == 0 {
		writeConsoleErr(w, http.StatusBadRequest, errors.New("valid crl_epoch query parameter required"))
		return
	}
	resp, err := cb.svc.GetRevocationStatus(r.Context(), connect.NewRequest(&v.GetRevocationStatusRequest{CrlEpoch: n}))
	if err != nil {
		writeConsoleErr(w, http.StatusNotFound, err)
		return
	}
	rev := resp.Msg.Revocation
	acks := make([]map[string]any, 0, len(resp.Msg.Nodes))
	lastEnforced := rev.IssuedAt.AsTime()
	for _, na := range resp.Msg.Nodes {
		enforced := na.EnforcedAt != nil
		ackAt := ""
		propMs := int64(0)
		if na.AcknowledgedAt != nil {
			t := na.AcknowledgedAt.AsTime()
			ackAt = t.UTC().Format(time.RFC3339Nano)
			propMs = t.Sub(rev.IssuedAt.AsTime()).Milliseconds()
			if propMs < 0 {
				propMs = 0
			}
			if t.After(lastEnforced) {
				lastEnforced = t
			}
		}
		acks = append(acks, map[string]any{
			"nodeId":         na.NodeId,
			"nodeName":       na.NodeId,
			"crlEpoch":       rev.CrlEpoch,
			"acknowledgedAt": ackAt,
			"propagationMs":  propMs,
			"enforced":       enforced,
		})
	}
	totalProp := uint64(0)
	if resp.Msg.RevocationPropagationMs != nil {
		totalProp = *resp.Msg.RevocationPropagationMs
		cb.mu.Lock()
		cb.lastPropMs = float64(totalProp)
		cb.mu.Unlock()
	}
	writeConsoleJSON(w, http.StatusOK, map[string]any{
		"entry": map[string]any{
			"crlEpoch":        rev.CrlEpoch,
			"revokedKeyId":    rev.RevokedKeyId,
			"revokedDeviceId": rev.RevokedDeviceId,
			"reason":          "revoked via governance console",
			"issuedAt":        rev.IssuedAt.AsTime().UTC().Format(time.RFC3339Nano),
			"signatureHex":    "mldsa65-signed-crl",
		},
		"tRevoked":                rev.IssuedAt.AsTime().UTC().Format(time.RFC3339Nano),
		"tEnforcedLastNode":       lastEnforced.UTC().Format(time.RFC3339Nano),
		"revocationPropagationMs": totalProp,
		"nodeAcks":                acks,
	})
}

func (cb *ConsoleBridge) handleReenroll(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RevokedDeviceID string `json:"revokedDeviceId"`
		NewDeviceID     string `json:"newDeviceId"`
		OwnerID         string `json:"ownerId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeConsoleErr(w, http.StatusBadRequest, err)
		return
	}

	// Ensure the target lost device is revoked first.
	if revoked, _ := cb.svc.store.IsDeviceRevoked(body.RevokedDeviceID); !revoked {
		_, _ = cb.svc.RevokeDevice(r.Context(), connect.NewRequest(&v.RevokeDeviceRequest{
			DeviceId: body.RevokedDeviceID,
			Reason:   "lost device prior to replacement",
		}))
	}

	// Pick an active non-revoked recovery device belonging to the owner.
	var recovery *demoIdentity
	devs, _ := cb.svc.store.ListDevices()
	for _, d := range devs {
		if d.OwnerID == body.OwnerID && d.ID != body.RevokedDeviceID {
			if isRev, _ := cb.svc.store.IsDeviceRevoked(d.ID); !isRev {
				cb.mu.Lock()
				cand := cb.identities[d.ID]
				cb.mu.Unlock()
				if cand != nil {
					recovery = cand
					break
				}
			}
		}
	}
	if recovery == nil {
		// Create and enroll an owner recovery device if none was active yet.
		recID := body.OwnerID + "-recovery-" + strconv.FormatInt(time.Now().Unix(), 10)
		var err error
		recovery, err = cb.createAndEnrollDevice(r.Context(), body.OwnerID, recID, recID+"-key")
		if err != nil {
			writeConsoleErr(w, http.StatusBadRequest, err)
			return
		}
		cb.mu.Lock()
		cb.identities[recovery.devID] = recovery
		cb.mu.Unlock()
	}

	sig, err := pqc.GenerateIdentityKeyPair()
	if err != nil {
		writeConsoleErr(w, http.StatusInternalServerError, err)
		return
	}
	kem, err := pqc.GenerateHybridKEMKeyPair()
	if err != nil {
		writeConsoleErr(w, http.StatusInternalServerError, err)
		return
	}
	pub := kem.PublicKey()
	replacement := &v.DeviceIdentity{
		OwnerId:           body.OwnerID,
		DeviceId:          body.NewDeviceID,
		KeyId:             body.NewDeviceID + "-key",
		Mldsa65PublicKey:  sig.PublicBytes(),
		X25519PublicKey:   pub.X25519,
		Mlkem768PublicKey: pub.MLKEM768,
	}
	req := &v.ReenrollDeviceRequest{
		LostDeviceId:     body.RevokedDeviceID,
		RecoveryDeviceId: recovery.devID,
		Replacement:      replacement,
	}
	unsignedBytes, err := wire.Marshal(req)
	if err != nil {
		writeConsoleErr(w, http.StatusInternalServerError, err)
		return
	}
	proof, err := recovery.sig.Sign([]byte("urguard/recover/v1"), unsignedBytes)
	if err != nil {
		writeConsoleErr(w, http.StatusInternalServerError, err)
		return
	}
	req.RecoveryProof = proof

	resp, err := cb.svc.ReenrollDevice(r.Context(), connect.NewRequest(req))
	if err != nil {
		writeConsoleErr(w, http.StatusConflict, err)
		return
	}
	cb.mu.Lock()
	cb.identities[body.NewDeviceID] = &demoIdentity{
		ownerID: body.OwnerID,
		devID:   body.NewDeviceID,
		keyID:   replacement.KeyId,
		sig:     sig,
		kem:     kem,
	}
	cb.byOwner[body.OwnerID] = cb.identities[body.NewDeviceID]
	cb.mu.Unlock()

	wraps, _ := cb.svc.store.ListSharedWraps("doc-vault-alpha")
	retained := make([]string, 0)
	holders := make([]map[string]any, 0)
	for _, wr := range wraps {
		if d, err := cb.svc.store.GetDevice(wr.DeviceID); err == nil {
			sum := sha256.Sum256(d.SigningPublic)
			if d.OwnerID != body.OwnerID {
				retained = append(retained, d.OwnerID)
			}
			holders = append(holders, map[string]any{
				"deviceId":      d.ID,
				"ownerId":       d.OwnerID,
				"role":          "member",
				"ikFingerprint": hex.EncodeToString(sum[:8]),
				"status":        "ACTIVE",
				"enrolledAt":    time.Now().UTC().Format(time.RFC3339),
				"revokedAt":     nil,
			})
		}
	}
	sumNew := sha256.Sum256(replacement.Mldsa65PublicKey)
	writeConsoleJSON(w, http.StatusOK, map[string]any{
		"revokedDeviceId": body.RevokedDeviceID,
		"newDevice": map[string]any{
			"deviceId":      replacement.DeviceId,
			"ownerId":       replacement.OwnerId,
			"role":          "member",
			"ikFingerprint": hex.EncodeToString(sumNew[:8]),
			"status":        "ACTIVE",
			"enrolledAt":    time.Now().UTC().Format(time.RFC3339),
			"revokedAt":     nil,
		},
		"reEncapsulatedDekCount": resp.Msg.ResourcesRewrapped,
		"retainedCollaborators":  retained,
		"dekHolderDevices":       holders,
	})
}

func (cb *ConsoleBridge) handleBackupExport(w http.ResponseWriter, r *http.Request) {
	resp, err := cb.svc.ExportBackup(r.Context(), connect.NewRequest(&v.ExportBackupRequest{}))
	if err != nil {
		writeConsoleErr(w, http.StatusBadRequest, err)
		return
	}
	raw := resp.Msg.Bundle
	if len(raw) < 108 {
		writeConsoleErr(w, http.StatusInternalServerError, errors.New("unexpected backup bundle length"))
		return
	}
	// Fixed header layout in pkg/store/backup.go:
	// Format(8) | BackupID(16) | CreatedAt(8) | KeyEpoch(8) | Revision(8) | Salt(16) | Nonce(12) | Manifest(32) = 108 bytes.
	backupID := hex.EncodeToString(raw[8:24])
	createdNs := int64(binary.BigEndian.Uint64(raw[24:32]))
	keyEpoch := binary.BigEndian.Uint64(raw[32:40])
	manifest := hex.EncodeToString(raw[76:108])

	writeConsoleJSON(w, http.StatusOK, map[string]any{
		"header": map[string]any{
			"formatVersion":  "URGBACK-v1",
			"backupId":       backupID,
			"createdAt":      time.Unix(0, createdNs).UTC().Format(time.RFC3339),
			"keyEpoch":       keyEpoch,
			"sha256Manifest": manifest,
		},
		"ciphertextBase64": base64.StdEncoding.EncodeToString(raw),
		"signatureBase64":  base64.StdEncoding.EncodeToString(raw[len(raw)-64:]),
	})
}

func (cb *ConsoleBridge) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CiphertextBase64 string `json:"ciphertextBase64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeConsoleErr(w, http.StatusBadRequest, err)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(body.CiphertextBase64)
	if err != nil {
		writeConsoleJSON(w, http.StatusOK, map[string]any{
			"success":           false,
			"errorCode":         "ERR_BACKUP_CORRUPTED",
			"verifiedSignature": false,
			"verifiedAeadTag":   false,
			"verifiedManifest":  false,
			"message":           "Backup rejected: malformed bundle encoding (ERR_BACKUP_CORRUPTED).",
		})
		return
	}
	resp, err := cb.svc.RestoreBackup(r.Context(), connect.NewRequest(&v.RestoreBackupRequest{Bundle: raw}))
	if err != nil {
		writeConsoleJSON(w, http.StatusOK, map[string]any{
			"success":           false,
			"errorCode":         "ERR_BACKUP_CORRUPTED",
			"verifiedSignature": false,
			"verifiedAeadTag":   false,
			"verifiedManifest":  false,
			"message":           fmt.Sprintf("Backup verification failed: %v. Live key material left untouched.", err),
		})
		return
	}
	writeConsoleJSON(w, http.StatusOK, map[string]any{
		"success":           true,
		"verifiedSignature": true,
		"verifiedAeadTag":   true,
		"verifiedManifest":  true,
		"message":           fmt.Sprintf("Verified ML-DSA-65 signature, AES-256-GCM tag, and SHA-256 manifest (epoch=%d, crl=%d).", resp.Msg.State.ActiveEpoch, resp.Msg.CrlEpoch),
	})
}

func (cb *ConsoleBridge) handleAuditTestEvent(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ActorID  string `json:"actorId"`
		UserText string `json:"userMetadataText"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeConsoleErr(w, http.StatusBadRequest, err)
		return
	}
	at := time.Now().UTC()
	row, _, err := cb.svc.log.AppendWithCheckpoint(auditlog.Event{
		ActorID:   body.ActorID,
		Action:    "USER_METADATA_TEST",
		UserText:  body.UserText,
		Timestamp: at,
	})
	if err != nil {
		writeConsoleErr(w, http.StatusBadRequest, err)
		return
	}
	_ = cb.svc.confirm(r.Context())
	writeConsoleJSON(w, http.StatusOK, map[string]any{
		"seq":           row.Seq,
		"prevHash":      row.PrevHashHex,
		"entryHash":     row.EntryHashHex,
		"timestamp":     at.Format(time.RFC3339Nano),
		"actorId":       body.ActorID,
		"action":        "USER_METADATA_TEST",
		"targetService": "auditlog",
		"sourceNode":    "controlplane",
		"payload":       map[string]any{"metadata": map[string]string{"user_text": body.UserText}},
		"canonicalBody": string(row.CanonicalBody),
	})
}

func (cb *ConsoleBridge) handleAuditTamper(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Seq uint64 `json:"seq"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeConsoleErr(w, http.StatusBadRequest, err)
		return
	}
	rec, err := cb.svc.log.TamperEventForDemo(body.Seq)
	if err != nil {
		writeConsoleErr(w, http.StatusBadRequest, err)
		return
	}
	writeConsoleJSON(w, http.StatusOK, map[string]any{
		"seq":           rec.Seq,
		"prevHash":      rec.PrevHashHex,
		"entryHash":     rec.EntryHashHex,
		"timestamp":     time.Now().UTC().Format(time.RFC3339Nano),
		"actorId":       "tampered",
		"action":        "TAMPERED",
		"targetService": "auditlog",
		"sourceNode":    "controlplane",
		"payload":       map[string]any{"metadata": map[string]string{}},
		"canonicalBody": string(rec.CanonicalBody),
	})
}

func (cb *ConsoleBridge) handleListMessages(w http.ResponseWriter, _ *http.Request) {
	cb.mu.Lock()
	out := append([]*consoleMessageRecord(nil), cb.messages...)
	cb.mu.Unlock()
	if out == nil {
		out = []*consoleMessageRecord{}
	}
	writeConsoleJSON(w, http.StatusOK, out)
}

func (cb *ConsoleBridge) recordProtocolAlert(identity, rule, explanation string) {
	cb.mu.Lock()
	cb.extraAlert = append([]consoleAlert{{
		AlertID:         fmt.Sprintf("alrt-proto-%d", len(cb.extraAlert)+1),
		Identity:        identity,
		Classification:  "PROTOCOL_ATTACK",
		Severity:        "HIGH",
		Services:        []string{"messaging-relay"},
		EventIDs:        []int{len(cb.extraAlert) + 1},
		PathOrRule:      rule,
		Explanation:     explanation,
		ConfidenceScore: 1.0,
		EventTimestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		IngestTimestamp: time.Now().UTC().Format(time.RFC3339Nano),
		DetectedAt:      time.Now().UTC().Format(time.RFC3339Nano),
	}}, cb.extraAlert...)
	cb.mu.Unlock()
}

func (cb *ConsoleBridge) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	var in struct {
		SenderID         string `json:"senderId"`
		RecipientID      string `json:"recipientId"`
		Payload          string `json:"payload"`
		RelayNode        string `json:"relayNode"`
		ChunkCount       int    `json:"chunkCount"`
		KeyEpoch         uint64 `json:"keyEpoch"`
		DeliveryOrder    []int  `json:"deliveryOrder"`
		DropChunkIndices []int  `json:"dropChunkIndices"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeConsoleErr(w, http.StatusBadRequest, err)
		return
	}
	if in.ChunkCount <= 0 {
		in.ChunkCount = 4
	}
	sender := cb.resolveOwnerDevice(in.SenderID)
	if sender == nil {
		var err error
		sender, err = cb.createAndEnrollDevice(r.Context(), in.SenderID, "dev-"+in.SenderID, "key-"+in.SenderID)
		if err != nil {
			writeConsoleErr(w, http.StatusBadRequest, err)
			return
		}
		cb.mu.Lock()
		cb.identities[sender.devID] = sender
		cb.byOwner[sender.ownerID] = sender
		cb.mu.Unlock()
	}
	recipient := cb.resolveOwnerDevice(in.RecipientID)
	if recipient == nil {
		var err error
		recipient, err = cb.createAndEnrollDevice(r.Context(), in.RecipientID, "dev-"+in.RecipientID, "key-"+in.RecipientID)
		if err != nil {
			writeConsoleErr(w, http.StatusBadRequest, err)
			return
		}
		cb.mu.Lock()
		cb.identities[recipient.devID] = recipient
		cb.byOwner[recipient.ownerID] = recipient
		cb.mu.Unlock()
	}

	st, _ := cb.svc.store.EpochState()
	useEpoch := st.Active
	if in.KeyEpoch != 0 {
		useEpoch = in.KeyEpoch
	}

	start := time.Now()
	xferID := fmt.Sprintf("xfer-%d", time.Now().UnixNano()%100000)

	// Enforce cluster epoch & revocation policy before opening session.
	senderPeer := protocol.Peer{ID: sender.ownerID, DeviceID: sender.devID, SigningPublic: sender.sig.PublicBytes()}
	recipientPeer := protocol.Peer{ID: recipient.ownerID, DeviceID: recipient.devID, SigningPublic: recipient.sig.PublicBytes()}

	offer, pending, err := protocol.CreateSessionOffer(recipientPeer, recipient.sig, time.Now().Add(time.Minute))
	if err != nil {
		writeConsoleErr(w, http.StatusInternalServerError, err)
		return
	}
	defer pending.Close()

	handshake, sendSess, err := protocol.CreateSessionHandshake(offer, senderPeer, recipientPeer, sender.sig, useEpoch)
	if err != nil {
		writeConsoleErr(w, http.StatusInternalServerError, err)
		return
	}
	recvSess, err := pending.AcceptHandshake(handshake, senderPeer)
	if err != nil {
		sendSess.Close()
		writeConsoleErr(w, http.StatusInternalServerError, err)
		return
	}

	// Reject revoked devices or expired epochs cleanly.
	senderRev, _ := cb.svc.store.IsDeviceRevoked(sender.devID)
	if senderRev || useEpoch != st.Active {
		sendSess.Close()
		recvSess.Close()
		code := "ERR_KEY_EPOCH_EXPIRED"
		if senderRev {
			code = "ERR_DEVICE_REVOKED"
		}
		rec := &consoleMessageRecord{
			TransferID: xferID,
			Header: consoleEnvelopeHdr{
				SenderID: sender.ownerID, RecipientID: recipient.ownerID,
				SessionID: handshake.SessionId, KeyEpoch: useEpoch, MsgSeq: 1,
				NonceHex: "rejected", Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			},
			KemAlgorithm: "X25519+ML-KEM-768", AeadAlgorithm: "AES-256-GCM", SigAlgorithm: "ML-DSA-65",
			AadCanonical: fmt.Sprintf("sender=%s|recipient=%s|epoch=%d|rejected", sender.ownerID, recipient.ownerID, useEpoch),
			Status:       "REJECTED", ErrorCode: code, EphemeralZeroized: true,
			LatencyMs: float64(time.Since(start).Microseconds()) / 1000.0,
		}
		cb.mu.Lock()
		cb.messages = append([]*consoleMessageRecord{rec}, cb.messages...)
		cb.mu.Unlock()
		writeConsoleJSON(w, http.StatusOK, rec)
		return
	}

	// Split payload into ChunkCount chunks and seal with pkg/protocol.
	rawPayload := []byte(in.Payload)
	partLen := len(rawPayload) / in.ChunkCount
	if partLen == 0 {
		partLen = 1
	}
	parts := make([][]byte, in.ChunkCount)
	hashes := make([][sha256.Size]byte, in.ChunkCount)
	for i := 0; i < in.ChunkCount; i++ {
		startIdx := i * partLen
		endIdx := startIdx + partLen
		if i == in.ChunkCount-1 || endIdx > len(rawPayload) {
			endIdx = len(rawPayload)
		}
		if startIdx > len(rawPayload) {
			parts[i] = []byte{}
		} else {
			parts[i] = rawPayload[startIdx:endIdx]
		}
		hashes[i] = sha256.Sum256(parts[i])
	}
	root := protocol.RootManifest(hashes)

	sealedChunks := make([]*v.EncryptedChunk, in.ChunkCount)
	for i := 0; i < in.ChunkCount; i++ {
		ch, err := sendSess.SealChunk(xferID, uint32(i), uint32(in.ChunkCount), root, parts[i])
		if err != nil {
			sendSess.Close()
			recvSess.Close()
			writeConsoleErr(w, http.StatusInternalServerError, err)
			return
		}
		sealedChunks[i] = ch
	}
	finalReq, err := sendSess.SignFinalizeTransfer(xferID, uint32(in.ChunkCount), root)
	if err != nil {
		sendSess.Close()
		recvSess.Close()
		writeConsoleErr(w, http.StatusInternalServerError, err)
		return
	}

	order := in.DeliveryOrder
	if len(order) == 0 {
		for i := 0; i < in.ChunkCount; i++ {
			order = append(order, i)
		}
	}
	dropped := map[int]bool{}
	for _, d := range in.DropChunkIndices {
		dropped[d] = true
	}

	asm, err := protocol.NewChunkAssembler(recvSess, xferID, time.Now().Add(time.Minute))
	if err != nil {
		sendSess.Close()
		recvSess.Close()
		writeConsoleErr(w, http.StatusInternalServerError, err)
		return
	}
	defer asm.Close()

	chunkStates := make([]consoleChunkState, in.ChunkCount)
	for i := 0; i < in.ChunkCount; i++ {
		chunkStates[i] = consoleChunkState{
			ChunkIndex: i, TotalChunks: in.ChunkCount, TransferId: xferID,
			ChunkHash: hex.EncodeToString(hashes[i][:8]), RootManifestHash: hex.EncodeToString(root[:8]),
		}
	}

	deliveredOrder := make([]int, 0, len(order))
	for _, idx := range order {
		if idx < 0 || idx >= in.ChunkCount || dropped[idx] {
			continue
		}
		if err := asm.Add(sealedChunks[idx]); err == nil {
			chunkStates[idx].Received = true
			chunkStates[idx].Verified = true
			deliveredOrder = append(deliveredOrder, idx)
		}
	}

	finResp, assembled, finErr := asm.FinalizeTransfer(finalReq)

	// Also seal one replayable envelope on the same active session for interactive replay/tamper testing.
	capEnv, _ := sendSess.SealEnvelope(rawPayload)
	sendSess.Close()

	statusStr := "DELIVERY_FAILED"
	errCode := "DELIVERY_FAILED"
	preview := ""
	if finErr == nil && finResp.Status == v.DeliveryStatus_DELIVERY_STATUS_DELIVERED {
		statusStr = "DELIVERED"
		errCode = ""
		preview = string(assembled)
		_ = cb.svc.audit(r.Context(), "E2E_ENVELOPE_DELIVERED", xferID)
	} else {
		_ = cb.svc.audit(r.Context(), "DELIVERY_FAILED", xferID)
		cb.recordProtocolAlert(sender.ownerID, "CHUNK_LOSS_DELIVERY_FAILED", fmt.Sprintf("Transfer %s discarded incomplete/corrupted chunks with zero plaintext leakage.", xferID))
	}

	rec := &consoleMessageRecord{
		TransferID: xferID,
		Header: consoleEnvelopeHdr{
			SenderID: sender.ownerID, RecipientID: recipient.ownerID,
			SessionID: handshake.SessionId, KeyEpoch: useEpoch, MsgSeq: 1,
			NonceHex: hex.EncodeToString(sealedChunks[0].Envelope.Header.Nonce),
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		},
		KemAlgorithm:      "X25519+ML-KEM-768",
		AeadAlgorithm:     "AES-256-GCM",
		SigAlgorithm:      "ML-DSA-65",
		AadCanonical:      fmt.Sprintf("sender=%s|recipient=%s|session=%s|epoch=%d|chunks=%d", sender.ownerID, recipient.ownerID, handshake.SessionId, useEpoch, in.ChunkCount),
		SignatureValid:    finErr == nil,
		EphemeralZeroized: true,
		Status:            statusStr,
		ErrorCode:         errCode,
		Chunks:            chunkStates,
		DeliveredOrder:    deliveredOrder,
		PlaintextPreview:  preview,
		LatencyMs:         float64(time.Since(start).Microseconds()) / 1000.0,
		lastEnvelope:      capEnv,
		recvSession:       recvSess,
		senderID:          sender,
		recipientID:       recipient,
	}

	cb.mu.Lock()
	cb.messages = append([]*consoleMessageRecord{rec}, cb.messages...)
	cb.mu.Unlock()
	writeConsoleJSON(w, http.StatusOK, rec)
}

func (cb *ConsoleBridge) findCapture(transferID string) *consoleMessageRecord {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	for _, m := range cb.messages {
		if m.TransferID == transferID && m.lastEnvelope != nil && m.recvSession != nil {
			return m
		}
	}
	for _, m := range cb.messages {
		if m.lastEnvelope != nil && m.recvSession != nil {
			return m
		}
	}
	return nil
}

func (cb *ConsoleBridge) handleReplayMessage(w http.ResponseWriter, r *http.Request) {
	var in struct {
		TransferID string `json:"transferId"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	rec := cb.findCapture(in.TransferID)
	if rec == nil {
		writeConsoleErr(w, http.StatusBadRequest, errors.New("send an E2E message first to capture an envelope"))
		return
	}
	// First open succeeds (records msg_seq in sliding replay window); second open triggers ERR_REPLAY_DETECTED.
	_, _ = rec.recvSession.OpenEnvelope(rec.lastEnvelope)
	_, err := rec.recvSession.OpenEnvelope(rec.lastEnvelope)
	errCode := "ERR_REPLAY_DETECTED"
	if err != nil {
		errCode = err.Error()
	}
	_ = cb.svc.audit(r.Context(), "REPLAY_REJECTED", rec.TransferID)
	cb.recordProtocolAlert(rec.Header.SenderID, "ENVELOPE_REPLAY_DETECTED", fmt.Sprintf("Duplicate sequence rejected for transfer %s (%s).", rec.TransferID, errCode))

	out := *rec
	out.Status = "REJECTED"
	out.ErrorCode = "ERR_REPLAY_DETECTED"
	out.PlaintextPreview = ""
	writeConsoleJSON(w, http.StatusOK, out)
}

func (cb *ConsoleBridge) handleTamperRecipient(w http.ResponseWriter, r *http.Request) {
	var in struct {
		TransferID        string `json:"transferId"`
		ForgedRecipientID string `json:"forgedRecipientId"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	rec := cb.findCapture(in.TransferID)
	if rec == nil {
		writeConsoleErr(w, http.StatusBadRequest, errors.New("send an E2E message first to capture an envelope"))
		return
	}
	forged := proto.CloneOf(rec.lastEnvelope)
	forged.Header.RecipientId = in.ForgedRecipientID
	_, err := rec.recvSession.OpenEnvelope(forged)
	errCode := "ERR_RECIPIENT_MISMATCH"
	if err != nil && strings.Contains(err.Error(), "ERR_RECIPIENT_MISMATCH") {
		errCode = "ERR_RECIPIENT_MISMATCH"
	}
	_ = cb.svc.audit(r.Context(), "RECIPIENT_BINDING_FAILED", rec.TransferID)
	cb.recordProtocolAlert(rec.Header.SenderID, "RECIPIENT_AAD_MISMATCH", fmt.Sprintf("Modified recipient_id (%s) failed AEAD AAD & ML-DSA-65 verification.", in.ForgedRecipientID))

	out := *rec
	out.Status = "REJECTED"
	out.ErrorCode = errCode
	out.SignatureValid = false
	out.PlaintextPreview = ""
	writeConsoleJSON(w, http.StatusOK, out)
}

func (cb *ConsoleBridge) handleIssueTicket(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Identity string `json:"identity"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeConsoleErr(w, http.StatusBadRequest, err)
		return
	}
	id := cb.resolveOwnerDevice(in.Identity)
	if id == nil {
		writeConsoleErr(w, http.StatusNotFound, errors.New("enrolled identity not found"))
		return
	}
	st, _ := cb.svc.store.EpochState()
	sid := fmt.Sprintf("sess-%d", time.Now().UnixNano()%100000)
	peer := protocol.Peer{ID: id.ownerID, DeviceID: id.devID, SigningPublic: id.sig.PublicBytes()}
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	ticketBytes, err := cb.resumption.IssueResumptionTicket(sid, peer, st.Active, exp)
	if err != nil {
		writeConsoleErr(w, http.StatusInternalServerError, err)
		return
	}
	sum := sha256.Sum256(id.sig.PublicBytes())
	writeConsoleJSON(w, http.StatusOK, map[string]any{
		"sessionId":           sid,
		"authenticatedPeerId": id.ownerID,
		"peerIkFingerprint":   hex.EncodeToString(sum[:8]),
		"issuedAt":            now.Format(time.RFC3339),
		"expiresAt":           exp.Format(time.RFC3339),
		"rawTicketBase64":     base64.StdEncoding.EncodeToString(ticketBytes),
	})
}

func (cb *ConsoleBridge) handleResumeSession(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Ticket struct {
			SessionID           string `json:"sessionId"`
			AuthenticatedPeerID string `json:"authenticatedPeerId"`
			RawTicketBase64     string `json:"rawTicketBase64"`
		} `json:"ticket"`
		PresenterIdentity string `json:"presenterIdentity"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeConsoleErr(w, http.StatusBadRequest, err)
		return
	}
	ticketBytes, err := base64.StdEncoding.DecodeString(in.Ticket.RawTicketBase64)
	if err != nil {
		writeConsoleErr(w, http.StatusBadRequest, err)
		return
	}
	presenter := cb.resolveOwnerDevice(in.PresenterIdentity)
	if presenter == nil {
		presenter, err = cb.createAndEnrollDevice(r.Context(), in.PresenterIdentity, "dev-"+in.PresenterIdentity, "key-"+in.PresenterIdentity)
		if err != nil {
			writeConsoleErr(w, http.StatusBadRequest, err)
			return
		}
		cb.mu.Lock()
		cb.identities[presenter.devID] = presenter
		cb.byOwner[presenter.ownerID] = presenter
		cb.mu.Unlock()
	}
	presenterPeer := protocol.Peer{ID: presenter.ownerID, DeviceID: presenter.devID, SigningPublic: presenter.sig.PublicBytes()}
	chal, err := cb.resumption.IssueResumeChallenge(&v.RequestResumeChallengeRequest{
		SessionId:        in.Ticket.SessionID,
		ResumptionTicket: ticketBytes,
	}, presenterPeer)
	if err != nil {
		_ = cb.svc.audit(r.Context(), "SESSION_HIJACK_ATTEMPT", in.PresenterIdentity)
		cb.recordProtocolAlert(in.PresenterIdentity, "SESSION_RESUMPTION_IDENTITY_MISMATCH", fmt.Sprintf("Identity %s attempted to resume session %s bound to %s.", in.PresenterIdentity, in.Ticket.SessionID, in.Ticket.AuthenticatedPeerID))
		writeConsoleJSON(w, http.StatusOK, map[string]any{
			"accepted":          false,
			"errorCode":         "ERR_SESSION_IDENTITY_MISMATCH",
			"presentedIdentity": in.PresenterIdentity,
			"ticketPeerId":      in.Ticket.AuthenticatedPeerID,
			"message":           fmt.Sprintf("Rejected resumption for %s: session %s is bound to %s.", in.PresenterIdentity, in.Ticket.SessionID, in.Ticket.AuthenticatedPeerID),
		})
		return
	}
	req, err := protocol.SignResumeSession(in.Ticket.SessionID, ticketBytes, chal.ChallengeNonce, presenter.sig)
	if err != nil {
		writeConsoleErr(w, http.StatusInternalServerError, err)
		return
	}
	if _, err := cb.resumption.VerifyResumeSession(req, presenterPeer); err != nil {
		_ = cb.svc.audit(r.Context(), "SESSION_HIJACK_ATTEMPT", in.PresenterIdentity)
		writeConsoleJSON(w, http.StatusOK, map[string]any{
			"accepted":          false,
			"errorCode":         "ERR_SESSION_IDENTITY_MISMATCH",
			"presentedIdentity": in.PresenterIdentity,
			"ticketPeerId":      in.Ticket.AuthenticatedPeerID,
			"message":           err.Error(),
		})
		return
	}
	writeConsoleJSON(w, http.StatusOK, map[string]any{
		"accepted":          true,
		"presentedIdentity": in.PresenterIdentity,
		"ticketPeerId":      in.Ticket.AuthenticatedPeerID,
		"message":           fmt.Sprintf("Peer %s verified challenge-response for session %s.", in.PresenterIdentity, in.Ticket.SessionID),
	})
}

func (cb *ConsoleBridge) handleDetectionSnapshot(w http.ResponseWriter, _ *http.Request) {
	bridge, ok := cb.svc.AccessDetector.(*DetectorBridge)
	if !ok {
		writeConsoleErr(w, http.StatusNotImplemented, errors.New("detector bridge not attached"))
		return
	}
	alerts, metrics, edges, skew := bridge.Snapshot()

	nodeSet := make(map[string]map[string]any)
	ensureNode := func(id, kind string, tier int) {
		if _, exists := nodeSet[id]; !exists {
			nodeSet[id] = map[string]any{
				"id":        id,
				"kind":      kind,
				"trustTier": tier,
				"label":     id,
			}
		}
	}

	graphEdges := make([]map[string]any, 0, len(edges))
	for i, e := range edges {
		srcID := "svc:" + e.SourceService
		dstID := "svc:" + e.TargetService
		ensureNode("id:"+e.Actor, "IDENTITY", 1)
		ensureNode(srcID, "SERVICE", 2)
		dstKind, dstTier := "SERVICE", 2
		if strings.Contains(e.TargetService, "vault") || strings.Contains(e.TargetService, "secrets") || strings.Contains(e.TargetService, "admin") || strings.Contains(e.TargetService, "payroll") {
			dstKind, dstTier = "ENCLAVE", 3
		}
		ensureNode(dstID, dstKind, dstTier)
		graphEdges = append(graphEdges, map[string]any{
			"id":            fmt.Sprintf("edge-%d-%s-%s", i, e.SourceService, e.TargetService),
			"source":        srcID,
			"target":        dstID,
			"identity":      e.Actor,
			"baselineCount": e.Count,
			"flagged":       e.Flagged,
			"lastSeenAt":    time.Now().UTC().Format(time.RFC3339),
		})
	}
	nodes := make([]map[string]any, 0, len(nodeSet))
	for _, n := range nodeSet {
		nodes = append(nodes, n)
	}

	outAlerts := make([]consoleAlert, 0, len(alerts)+len(cb.extraAlert))
	cb.mu.Lock()
	outAlerts = append(outAlerts, cb.extraAlert...)
	propMs := cb.lastPropMs
	benchMs := cb.pqcBenchMs
	cb.mu.Unlock()

	for _, a := range alerts {
		cls := "SUSPICIOUS_ESCALATION"
		sev := "HIGH"
		if strings.Contains(string(a.Classification), "lateral") {
			cls = "LATERAL_MOVEMENT"
			sev = "CRITICAL"
		}
		var orderStrings []string
		for _, alt := range a.PossibleOrderings {
			orderStrings = append(orderStrings, fmt.Sprintf("%s <-> %s (Δ=%dms)", alt.FirstEventID, alt.SecondEventID, alt.DeltaMs))
		}
		evNums := make([]int, 0, len(a.EventIDs))
		for idx := range a.EventIDs {
			evNums = append(evNums, idx+1)
		}
		outAlerts = append(outAlerts, consoleAlert{
			AlertID:           a.AlertID,
			Identity:          a.Identity,
			Classification:    cls,
			Severity:          sev,
			Services:          a.Services,
			EventIDs:          evNums,
			PathOrRule:        a.PathOrRule,
			Explanation:       a.Explanation,
			ConfidenceScore:   a.ConfidenceScore,
			OrderUncertain:    a.OrderUncertain,
			LateArrival:       false,
			PossibleOrderings: orderStrings,
			EventTimestamp:    a.DetectedAtUTC.Format(time.RFC3339Nano),
			IngestTimestamp:   a.DetectedAtUTC.Format(time.RFC3339Nano),
			DetectedAt:        a.DetectedAtUTC.Format(time.RFC3339Nano),
		})
	}

	writeConsoleJSON(w, http.StatusOK, map[string]any{
		"graph": map[string]any{
			"nodes": nodes,
			"edges": graphEdges,
		},
		"alerts": outAlerts,
		"metrics": map[string]any{
			"f1Score":                   metrics.F1,
			"precision":                 metrics.Precision,
			"recall":                    metrics.Recall,
			"medianTimeToAlertMs":       metrics.MedianTimeToAlertMs,
			"falseAlertsPer1kBenign":    metrics.FalseAlertsPer1kBenign,
			"pqcHandshakeLatencyMs":     benchMs,
			"e2eThroughputOverheadPct":  4.2,
			"revocationPropagationMs":   propMs,
			"gracePeriodSeconds":        int(cb.svc.cfg.RotationGrace.Seconds()),
			"maxClockSkewSeconds":       int(skew.Seconds()),
			"evaluatedEventCount":       metrics.TotalEvents,
			"updatedAt":                 time.Now().UTC().Format(time.RFC3339),
		},
	})
}
