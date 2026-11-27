package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	rpc "github.com/dean-2/urGuard/backend/gen/urguard/v1/urguardv1connect"
	"github.com/dean-2/urGuard/backend/internal/config"
	"github.com/dean-2/urGuard/backend/internal/node"
	"github.com/dean-2/urGuard/backend/internal/transport"
)

func waitForAuthorityPin(ctx context.Context, path string) ([]byte, error) {
	deadline := time.Now().Add(30 * time.Second)
	for {
		pub, err := os.ReadFile(path)
		if err == nil && len(pub) == mldsa65.PublicKeySize {
			return pub, nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return nil, err
			}
			return pub, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func run(ctx context.Context) error {
	c, err := config.LoadFromEnv()
	if err != nil {
		return err
	}
	h, err := transport.New(c, "node:"+c.NodeID)
	if err != nil {
		return err
	}
	for _, p := range []string{c.NodeDBPath, c.WitnessDBPath} {
		if dir := filepath.Dir(p); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return err
			}
		}
	}
	pub, err := waitForAuthorityPin(ctx, c.AuthorityPublicFile)
	if err != nil {
		return err
	}
	s, err := node.Open(c, pub)
	if err != nil {
		return err
	}
	defer s.Close()
	cp := rpc.NewCryptoControlServiceClient(h.Client, c.ControlPlaneURL, connect.WithGRPC())
	worker, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for worker.Err() == nil {
			if err := s.Sync(worker, cp); err != nil && worker.Err() == nil {
				log.Printf("control sync: %v", err)
			}
			select {
			case <-worker.Done():
				return
			case <-time.After(c.CRLHeartbeat):
			}
		}
	}()
	defer func() { stop(); <-done }()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		_, _ = rw.Write([]byte("ok\n"))
	})
	s.Mount(mux)
	return h.Serve(ctx, c.NodeAddr, mux)
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx); err != nil {
		log.Fatal(err)
	}
}
