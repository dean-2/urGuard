package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"connectrpc.com/connect"
	rpc "github.com/dean-2/urGuard/backend/gen/urguard/v1/urguardv1connect"
	"github.com/dean-2/urGuard/backend/internal/config"
	"github.com/dean-2/urGuard/backend/internal/controlplane"
	"github.com/dean-2/urGuard/backend/internal/transport"
	"github.com/dean-2/urGuard/backend/pkg/store"
)

func run(ctx context.Context) error {
	c, err := config.LoadFromEnv()
	if err != nil {
		return err
	}
	h, err := transport.New(c, "controlplane")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(c.ControlPlaneDBPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	st, err := store.Open(c.ControlPlaneDBPath)
	if err != nil {
		return err
	}
	defer st.Close()
	pub, err := st.AuthorityPublicKey()
	if err != nil {
		return err
	}
	if dir := filepath.Dir(c.AuthorityPublicFile); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if err = writeOrCheckPin(c.AuthorityPublicFile, pub); err != nil {
		return err
	}
	det, err := controlplane.NewDetectorBridge(c.MaxClockSkew, controlplane.ResolveDetectorDataDir())
	if err != nil {
		return err
	}
	var w rpc.AuditWitnessServiceClient
	if c.WitnessURL != "" {
		w = rpc.NewAuditWitnessServiceClient(h.Client, c.WitnessURL, connect.WithGRPC())
	}
	s, err := openControlPlaneWithRetry(ctx, c, st, w, det)
	if err != nil {
		return err
	}
	s.SetHTTPClient(h.Client)
	worker, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); s.RetryPending(worker) }()
	defer func() { stop(); <-done }()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		_, _ = rw.Write([]byte("ok\n"))
	})
	s.Mount(mux)
	return h.Serve(ctx, c.ControlPlaneAddr, mux)
}

func openControlPlaneWithRetry(ctx context.Context, c config.Config, st *store.Store, w rpc.AuditWitnessServiceClient, det controlplane.AccessDetector) (*controlplane.Service, error) {
	deadline := time.Now().Add(30 * time.Second)
	for {
		startup, cancel := context.WithTimeout(ctx, 5*time.Second)
		s, err := controlplane.New(startup, c, st, w, det)
		cancel()
		if err == nil {
			return s, nil
		}
		// Never retry integrity, rollback, or witness conflict errors; fail closed immediately.
		code := connect.CodeOf(err)
		msg := strings.ToLower(err.Error())
		dialErr := strings.Contains(msg, "connection refused") || strings.Contains(msg, "connectex") || strings.Contains(msg, "no such host") || strings.Contains(msg, "eof")
		transient := w != nil && (code == connect.CodeUnavailable || code == connect.CodeDeadlineExceeded || dialErr) &&
			!strings.Contains(msg, "rollback") && !strings.Contains(msg, "conflict") && !strings.Contains(msg, "mismatch")
		if !transient || time.Now().After(deadline) || ctx.Err() != nil {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx); err != nil {
		log.Fatal(err)
	}
}

func writeOrCheckPin(path string, pub []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if errors.Is(err, os.ErrExist) {
		existing, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if !bytes.Equal(existing, pub) {
			return errors.New("configured authority pin mismatch")
		}
		return nil
	}
	if err != nil {
		return err
	}
	_, err = f.Write(pub)
	return errors.Join(err, f.Sync(), f.Close())
}
