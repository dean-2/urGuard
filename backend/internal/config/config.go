// Package config reads the runtime settings shared by the control plane and nodes.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ControlPlaneAddr                               string
	ControlPlaneDBPath                             string
	ControlPlaneGRPCTLS                            bool
	RotationGrace                                  time.Duration
	CRLHeartbeat                                   time.Duration
	CheckpointInterval                             uint32
	MaxClockSkew                                   time.Duration
	NodeID                                         string
	NodeAddr                                       string
	NodeDBPath                                     string
	ControlPlaneURL                                string
	NodeURLs                                       []string
	BackupPassphrase                               string
	WitnessURL, WitnessDBPath, AuthorityPublicFile string
	TLSCert, TLSKey, TLSCA                         string
	RequiredNodes                                  []string
	// Local h2c credentials indexed by principal (admin, controlplane, node:<id>, device:<id>).
	Tokens map[string]string
}

// Load reads environment variables. An unset variable uses its documented default.
func Load() (Config, error)        { return load(os.LookupEnv) }
func LoadFromEnv() (Config, error) { return Load() }

func load(lookup func(string) (string, bool)) (Config, error) {
	get := func(key, fallback string) string {
		if v, ok := lookup("URGUARD_" + key); ok {
			return v
		}
		return fallback
	}
	c := Config{
		ControlPlaneAddr:   get("CP_ADDR", "127.0.0.1:8080"),
		ControlPlaneDBPath: get("CP_DB_PATH", "controlplane.bbolt"),
		NodeID:             get("NODE_ID", "node-1"),
		NodeAddr:           get("NODE_ADDR", "127.0.0.1:8081"),
		NodeDBPath:         get("NODE_DB_PATH", "node-1.bbolt"),
		ControlPlaneURL:    get("CONTROLPLANE_URL", "https://127.0.0.1:8080"),
		BackupPassphrase:   get("BACKUP_PASSPHRASE", ""),
	}
	var err error
	c.WitnessURL = get("WITNESS_URL", "")
	c.WitnessDBPath = get("WITNESS_DB_PATH", c.NodeDBPath+".witness")
	c.AuthorityPublicFile = get("AUTHORITY_PUBLIC_FILE", "authority.pub")
	c.TLSCert = get("TLS_CERT_FILE", "")
	c.TLSKey = get("TLS_KEY_FILE", "")
	c.TLSCA = get("TLS_CA_FILE", "")
	if c.WitnessURL != "" && !validEndpoint(c.WitnessURL) {
		return Config{}, fmt.Errorf("invalid URGUARD_WITNESS_URL")
	}
	seen := map[string]bool{}
	for _, name := range strings.Split(get("REQUIRED_NODES", "node-1,node-2,node-3"), ",") {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			return Config{}, fmt.Errorf("invalid URGUARD_REQUIRED_NODES")
		}
		seen[name] = true
		c.RequiredNodes = append(c.RequiredNodes, name)
	}
	if err := json.Unmarshal([]byte(get("LOCAL_TOKENS", "{}")), &c.Tokens); err != nil {
		return Config{}, fmt.Errorf("invalid URGUARD_LOCAL_TOKENS")
	}
	clear(seen)
	for name, token := range c.Tokens {
		if name == "" || len(token) < 32 || seen[token] {
			return Config{}, fmt.Errorf("local credentials require distinct tokens of at least 32 bytes")
		}
		seen[token] = true
	}
	c.ControlPlaneGRPCTLS, err = strconv.ParseBool(get("CP_GRPC_TLS", "true"))
	if err != nil {
		return Config{}, fmt.Errorf("URGUARD_CP_GRPC_TLS must be a boolean")
	}

	for key, value := range map[string]string{"CP_DB_PATH": c.ControlPlaneDBPath, "NODE_ID": c.NodeID, "NODE_DB_PATH": c.NodeDBPath} {
		if strings.TrimSpace(value) == "" {
			return Config{}, fmt.Errorf("URGUARD_%s must have a value", key)
		}
	}
	for key, addr := range map[string]string{"CP_ADDR": c.ControlPlaneAddr, "NODE_ADDR": c.NodeAddr} {
		_, port, splitErr := net.SplitHostPort(addr)
		if splitErr != nil || !validPort(port) {
			return Config{}, fmt.Errorf("URGUARD_%s requires a listen address with port 1-65535", key)
		}
	}

	for _, setting := range []struct {
		key, fallback string
		unit          time.Duration
		min           int64
		dest          *time.Duration
	}{
		{"ROTATION_GRACE_SEC", "30", time.Second, 0, &c.RotationGrace},
		{"CRL_HEARTBEAT_MS", "1000", time.Millisecond, 1, &c.CRLHeartbeat},
		{"MAX_CLOCK_SKEW_SEC", "30", time.Second, 0, &c.MaxClockSkew},
	} {
		n, err := strconv.ParseInt(get(setting.key, setting.fallback), 10, 64)
		if err != nil || n < setting.min || n > (1<<63-1)/int64(setting.unit) {
			return Config{}, fmt.Errorf("URGUARD_%s is outside the supported duration range", setting.key)
		}
		*setting.dest = time.Duration(n) * setting.unit
	}
	count, err := strconv.ParseUint(get("CHECKPOINT_INTERVAL", "25"), 10, 32)
	if err != nil || count == 0 {
		return Config{}, fmt.Errorf("URGUARD_CHECKPOINT_INTERVAL requires a positive 32-bit integer")
	}
	c.CheckpointInterval = uint32(count)

	if !validEndpoint(c.ControlPlaneURL) {
		return Config{}, fmt.Errorf("URGUARD_CONTROLPLANE_URL requires an absolute HTTP(S) service URL")
	}
	for _, item := range strings.Split(get("NODE_URLS", "https://127.0.0.1:8081,https://127.0.0.1:8082,https://127.0.0.1:8083"), ",") {
		endpoint := strings.TrimSpace(item)
		if !validEndpoint(endpoint) {
			return Config{}, fmt.Errorf("URGUARD_NODE_URLS contains an invalid service URL")
		}
		c.NodeURLs = append(c.NodeURLs, endpoint)
	}
	return c, nil
}

func validPort(port string) bool {
	n, err := strconv.ParseUint(port, 10, 16)
	return err == nil && n != 0
}

func validEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") || strings.HasSuffix(u.Host, ":") {
		return false
	}
	return u.Port() == "" || validPort(u.Port())
}
