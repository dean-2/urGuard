package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"connectrpc.com/connect"
	rpc "github.com/dean-2/urGuard/backend/gen/urguard/v1/urguardv1connect"
	"github.com/dean-2/urGuard/backend/internal/config"
	"github.com/dean-2/urGuard/backend/internal/node"
	"github.com/dean-2/urGuard/backend/internal/transport"
)

func run(ctx context.Context) error {
	c, err := config.LoadFromEnv()
	if err != nil {
		return err
	}
	h, err := transport.New(c, "node:"+c.NodeID)
	if err != nil {
		return err
	}
	pub, err := os.ReadFile(c.AuthorityPublicFile)
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
