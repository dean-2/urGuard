package main

import (
	"bytes"
	"context"
	"errors"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
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
	st, err := store.Open(c.ControlPlaneDBPath)
	if err != nil {
		return err
	}
	defer st.Close()
	pub, err := st.AuthorityPublicKey()
	if err != nil {
		return err
	}
	if err = writeOrCheckPin(c.AuthorityPublicFile, pub); err != nil {
		return err
	}
	var w rpc.AuditWitnessServiceClient
	if c.WitnessURL != "" {
		w = rpc.NewAuditWitnessServiceClient(h.Client, c.WitnessURL, connect.WithGRPC())
	}
	startup, cancel := context.WithTimeout(ctx, 15*time.Second)
	s, err := controlplane.New(startup, c, st, w, nil)
	cancel()
	if err != nil {
		return err
	}
	worker, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); s.RetryPending(worker) }()
	defer func() { stop(); <-done }()
	mux := http.NewServeMux()
	s.Mount(mux)
	return h.Serve(ctx, c.ControlPlaneAddr, mux)
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
