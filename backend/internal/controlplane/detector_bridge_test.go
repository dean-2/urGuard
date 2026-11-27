package controlplane

import (
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	v "github.com/dean-2/urGuard/backend/gen/urguard/v1"
	"github.com/dean-2/urGuard/backend/internal/transport"
	"github.com/dean-2/urGuard/backend/pkg/store"
)

func TestDetectorBridgeIntegration(t *testing.T) {
	c := testConfig(t)
	st, err := store.Open(c.ControlPlaneDBPath)
	check(t, err)
	defer st.Close()

	dataDir := filepath.Join("..", "..", "detector", "testdata")
	bridge, err := NewDetectorBridge(30*time.Second, dataDir)
	check(t, err)

	svc, err := New(t.Context(), c, st, nil, bridge)
	check(t, err)

	adminCtx := transport.WithPrincipal(t.Context(), "admin")
	metricsResp, err := svc.GetDetectionMetrics(adminCtx, connect.NewRequest(&v.GetDetectionMetricsRequest{}))
	check(t, err)
	if metricsResp.Msg.F1 <= 0 {
		t.Fatalf("expected non-zero baseline F1 from practice dataset, got %+v", metricsResp.Msg)
	}

	alertsResp, err := svc.ListAlerts(adminCtx, connect.NewRequest(&v.ListAlertsRequest{}))
	check(t, err)
	if len(alertsResp.Msg.Alerts) == 0 {
		t.Fatal("expected seeded detector alerts")
	}

	graphResp, err := svc.GetAccessGraph(adminCtx, connect.NewRequest(&v.GetAccessGraphRequest{}))
	check(t, err)
	if len(graphResp.Msg.Edges) == 0 {
		t.Fatal("expected seeded access graph edges")
	}

	// Trigger live rotation and verify audit forwarding runs without error.
	_, err = svc.PrepareRotation(adminCtx, connect.NewRequest(&v.PrepareRotationRequest{ExpectedActiveEpoch: 1}))
	check(t, err)
	_, err = svc.CommitRotation(adminCtx, connect.NewRequest(&v.CommitRotationRequest{PreparedEpoch: 2}))
	check(t, err)
}
