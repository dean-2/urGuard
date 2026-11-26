package config

import (
	"strings"
	"testing"
	"time"
)

func settings(values map[string]string) (Config, error) {
	return load(func(key string) (string, bool) { v, ok := values[key]; return v, ok })
}

func TestDefaults(t *testing.T) {
	c, err := settings(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !c.ControlPlaneGRPCTLS || c.RotationGrace != 30*time.Second || c.CRLHeartbeat != time.Second || c.CheckpointInterval != 25 || c.MaxClockSkew != 30*time.Second || len(c.NodeURLs) != 3 || c.BackupPassphrase != "" {
		t.Fatal("unexpected defaults")
	}
}

func TestOverrides(t *testing.T) {
	c, err := settings(map[string]string{
		"URGUARD_NODE_ID": "node-2", "URGUARD_NODE_ADDR": "[::1]:8082",
		"URGUARD_CP_GRPC_TLS": "false", "URGUARD_MAX_CLOCK_SKEW_SEC": "60",
		"URGUARD_ROTATION_GRACE_SEC": "0", "URGUARD_CRL_HEARTBEAT_MS": "200",
		"URGUARD_CHECKPOINT_INTERVAL": "8", "URGUARD_BACKUP_PASSPHRASE": " test value ",
		"URGUARD_NODE_URLS": "http://node-1:8081, https://[::1]:8082",
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.NodeID != "node-2" || c.ControlPlaneGRPCTLS || c.MaxClockSkew != time.Minute || c.RotationGrace != 0 || c.CRLHeartbeat != 200*time.Millisecond || c.CheckpointInterval != 8 || c.BackupPassphrase != " test value " || len(c.NodeURLs) != 2 || c.NodeURLs[1] != "https://[::1]:8082" {
		t.Fatal("overrides were not applied")
	}
}

func TestInvalidSettings(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"NODE_ID", " "}, {"CP_DB_PATH", ""}, {"NODE_DB_PATH", " "}, {"CP_ADDR", "localhost"},
		{"NODE_ADDR", ":65536"}, {"NODE_ADDR", ":0"}, {"CP_GRPC_TLS", "maybe"},
		{"ROTATION_GRACE_SEC", "-1"}, {"ROTATION_GRACE_SEC", "9223372036854775807"},
		{"CRL_HEARTBEAT_MS", "0"}, {"MAX_CLOCK_SKEW_SEC", "1.5"},
		{"CHECKPOINT_INTERVAL", "0"}, {"CHECKPOINT_INTERVAL", "4294967296"},
		{"CONTROLPLANE_URL", "https://user:password@host"}, {"CONTROLPLANE_URL", "https://host:70000"},
		{"NODE_URLS", "https://one,"}, {"NODE_URLS", "ftp://node"}, {"NODE_URLS", "node:8081"},
	} {
		key := "URGUARD_" + tc.key
		_, err := settings(map[string]string{key: tc.value})
		if err == nil || !strings.Contains(err.Error(), key) {
			t.Errorf("%s: expected setting-specific error", key)
		}
	}
}
