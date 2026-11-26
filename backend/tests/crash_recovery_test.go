package tests

import (
	"bytes"
	"connectrpc.com/connect"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	v "github.com/dean-2/urGuard/backend/gen/urguard/v1"
	rpc "github.com/dean-2/urGuard/backend/gen/urguard/v1/urguardv1connect"
	"github.com/dean-2/urGuard/backend/pkg/store"
	bolt "go.etcd.io/bbolt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type child struct {
	cmd  *exec.Cmd
	done chan struct{}
	log  string
	err  error
}

func launch(t *testing.T, bin string, env []string) *child {
	t.Helper()
	log, e := os.CreateTemp(t.TempDir(), "service-*.log")
	check(t, e)
	cmd := exec.Command(bin)
	cmd.Env = env
	cmd.Stdout = log
	cmd.Stderr = log
	e = cmd.Start()
	log.Close()
	check(t, e)
	p := &child{cmd: cmd, done: make(chan struct{}), log: log.Name()}
	go func() { p.err = cmd.Wait(); close(p.done) }()
	t.Cleanup(func() { p.kill() })
	return p
}
func (p *child) kill() {
	select {
	case <-p.done:
		return
	default:
		_ = p.cmd.Process.Kill()
		<-p.done
	}
}
func TestSubprocessCrashRecoveryAndRollback(t *testing.T) {
	dir := t.TempDir()
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	binaries := map[string]string{}
	for _, name := range []string{"controlplane", "node"} {
		bin := filepath.Join(dir, name+suffix)
		cmd := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "./cmd/"+name)
		cmd.Dir = ".."
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("build %s: %v\n%s", name, e, out)
		}
		binaries[name] = bin
	}
	c := settings(t)
	c.RequiredNodes = []string{"node-1"}
	c.NodeID = "node-1"
	c.AuthorityPublicFile = filepath.Join(dir, "authority.pub")
	c.NodeDBPath = filepath.Join(dir, "node.db")
	c.WitnessDBPath = filepath.Join(dir, "witness.db")
	st, e := store.Open(c.ControlPlaneDBPath)
	check(t, e)
	pin, e := st.AuthorityPublicKey()
	check(t, e)
	check(t, st.Close())
	check(t, os.WriteFile(c.AuthorityPublicFile, pin, 0600))
	a, e := net.Listen("tcp4", "127.0.0.1:0")
	check(t, e)
	b, e := net.Listen("tcp4", "127.0.0.1:0")
	check(t, e)
	c.NodeAddr = a.Addr().String()
	c.ControlPlaneAddr = b.Addr().String()
	a.Close()
	b.Close()
	c.WitnessURL = "http://" + c.NodeAddr
	c.ControlPlaneURL = "http://" + c.ControlPlaneAddr
	tokens, e := json.Marshal(c.Tokens)
	check(t, e)
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(kv), "URGUARD_") {
			env = append(env, kv)
		}
	}
	for k, v := range map[string]string{"CP_GRPC_TLS": "false", "NODE_ID": "node-1", "REQUIRED_NODES": "node-1", "CP_ADDR": c.ControlPlaneAddr, "NODE_ADDR": c.NodeAddr, "CP_DB_PATH": c.ControlPlaneDBPath, "NODE_DB_PATH": c.NodeDBPath, "WITNESS_DB_PATH": c.WitnessDBPath, "WITNESS_URL": c.WitnessURL, "CONTROLPLANE_URL": c.ControlPlaneURL, "AUTHORITY_PUBLIC_FILE": c.AuthorityPublicFile, "LOCAL_TOKENS": string(tokens), "CHECKPOINT_INTERVAL": "2", "CRL_HEARTBEAT_MS": "50"} {
		env = append(env, "URGUARD_"+k+"="+v)
	}
	launch(t, binaries["node"], env)
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	w := rpc.NewAuditWitnessServiceClient(httpFor(t, c, "controlplane").Client, c.WitnessURL, connect.WithGRPC())
	until(t, func() bool {
		_, e := w.GetWitnessHead(ctx, connect.NewRequest(&v.GetWitnessHeadRequest{}))
		return e == nil
	})
	h := httpFor(t, c, "admin").Client
	cp := rpc.NewCryptoControlServiceClient(h, c.ControlPlaneURL, connect.WithGRPC())
	tele := rpc.NewTelemetryServiceClient(h, c.ControlPlaneURL, connect.WithGRPC())
	start := func() *child {
		p := launch(t, binaries["controlplane"], env)
		until(t, func() bool {
			select {
			case <-p.done:
				out, _ := os.ReadFile(p.log)
				t.Fatalf("startup failed: %s", out)
			default:
			}
			_, e := cp.GetEpochState(ctx, connect.NewRequest(&v.GetEpochStateRequest{}))
			return e == nil
		})
		return p
	}
	proc := start()
	device := makeID(t, "lost", "alice")
	enroll(t, cp, device)
	_, e = cp.RevokeDevice(ctx, connect.NewRequest(&v.RevokeDeviceRequest{DeviceId: "lost", Reason: "lost"}))
	check(t, e)
	status := func() {
		r, e := cp.GetRevocationStatus(ctx, connect.NewRequest(&v.GetRevocationStatusRequest{CrlEpoch: 1}))
		check(t, e)
		if r.Msg.Revocation.CrlEpoch != 1 || r.Msg.Revocation.RevokedDeviceId != "lost" {
			t.Fatal(r.Msg)
		}
	}
	status()
	// Copy the database with its process stopped; a live file copy could tear.
	proc.kill()
	snapshot, e := os.ReadFile(c.ControlPlaneDBPath)
	check(t, e)
	proc = start()
	prep := connect.NewRequest(&v.PrepareRotationRequest{ExpectedActiveEpoch: 1})
	r, e := cp.PrepareRotation(ctx, prep)
	check(t, e)
	if r.Msg.State.Phase != v.RotationPhase_ROTATION_PHASE_PREPARING {
		t.Fatal(r.Msg)
	}
	proc.kill()
	proc = start()
	state, e := cp.GetEpochState(ctx, connect.NewRequest(&v.GetEpochStateRequest{}))
	check(t, e)
	if state.Msg.State.ActiveEpoch != 1 || state.Msg.State.PreparedEpoch != 0 || state.Msg.State.Phase != v.RotationPhase_ROTATION_PHASE_IDLE {
		t.Fatal(state.Msg)
	}
	status()
	audit, e := tele.VerifyAuditChain(ctx, connect.NewRequest(&v.VerifyAuditChainRequest{}))
	check(t, e)
	if !audit.Msg.Valid {
		t.Fatal(audit.Msg)
	}
	_, e = cp.PrepareRotation(ctx, prep)
	check(t, e)
	commit, e := cp.CommitRotation(ctx, connect.NewRequest(&v.CommitRotationRequest{PreparedEpoch: 2}))
	check(t, e)
	if commit.Msg.State.ActiveEpoch != 2 {
		t.Fatal(commit.Msg)
	}
	proc.kill()
	check(t, os.WriteFile(c.ControlPlaneDBPath, snapshot, 0600))
	old := launch(t, binaries["controlplane"], env)
	select {
	case <-old.done:
	case <-time.After(10 * time.Second):
		t.Fatal("rolled-back process stayed alive")
	}
	out, e := os.ReadFile(old.log)
	check(t, e)
	if old.err == nil || !strings.Contains(string(out), "audit rollback") {
		t.Fatalf("wrong startup result %v: %s", old.err, out)
	}
	if _, e = cp.PrepareRotation(ctx, prep); e == nil {
		t.Fatal(fmt.Sprintf("rolled-back process %d accepted a write", old.cmd.Process.Pid))
	}
	// Independently verify that startup identifies the first edited event.
	db, e := bolt.Open(c.ControlPlaneDBPath, 0600, nil)
	check(t, e)
	e = db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("audit_events"))
		key := binary.BigEndian.AppendUint64(nil, 1)
		raw := bucket.Get(key)
		edited := bytes.Replace(raw, []byte("DEVICE_ENROLLED"), []byte("EDITED"), 1)
		if bytes.Equal(raw, edited) {
			return fmt.Errorf("expected an enrollment at sequence 1")
		}
		return bucket.Put(key, edited)
	})
	check(t, db.Close())
	check(t, e)
	damaged := launch(t, binaries["controlplane"], env)
	select {
	case <-damaged.done:
	case <-time.After(10 * time.Second):
		t.Fatal("started with damaged audit history")
	}
	out, e = os.ReadFile(damaged.log)
	check(t, e)
	if damaged.err == nil || !strings.Contains(string(out), "sequence 1: entry hash mismatch") {
		t.Fatalf("missing diagnostic: %s", out)
	}
}
