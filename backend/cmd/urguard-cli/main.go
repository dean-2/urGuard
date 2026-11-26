package main

import (
	"connectrpc.com/connect"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	v "github.com/dean-2/urGuard/backend/gen/urguard/v1"
	rpc "github.com/dean-2/urGuard/backend/gen/urguard/v1/urguardv1connect"
	"github.com/dean-2/urGuard/backend/internal/config"
	"github.com/dean-2/urGuard/backend/internal/transport"
	"github.com/dean-2/urGuard/backend/pkg/pqc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"os"
	"time"
)

func bench() error {
	id, e := pqc.GenerateIdentityKeyPair()
	if e != nil {
		return e
	}
	k, e := pqc.GenerateHybridKEMKeyPair()
	if e != nil {
		return e
	}
	defer k.Zeroize()
	pub := k.PublicKey()
	signPub := id.PublicBytes()
	msg := []byte("benchmark")
	totals := map[string]int64{}
	const rounds = 100
	for range rounds {
		start := time.Now()
		sig, e := id.Sign(nil, msg)
		totals["sign"] += time.Since(start).Nanoseconds()
		if e != nil {
			return e
		}
		start = time.Now()
		ok := pqc.VerifySignature(signPub, nil, msg, sig)
		totals["verify"] += time.Since(start).Nanoseconds()
		if !ok {
			return errors.New("verification failed")
		}
		start = time.Now()
		ct, s, e := pqc.EncapsulateHybrid(pub, msg)
		totals["encapsulate"] += time.Since(start).Nanoseconds()
		pqc.Zeroize(s)
		if e != nil {
			return e
		}
		start = time.Now()
		s, e = k.DecapsulateHybrid(ct, msg)
		totals["decapsulate"] += time.Since(start).Nanoseconds()
		pqc.Zeroize(s)
		if e != nil {
			return e
		}
	}
	for k, v := range totals {
		totals[k] = v / rounds
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"iterations": rounds, "mean_ns": totals})
}
func show[T any](r *connect.Response[T], err error) error {
	if err != nil {
		return err
	}
	b, err := protojson.Marshal(any(r.Msg).(proto.Message))
	if err == nil {
		_, err = fmt.Fprintln(os.Stdout, string(b))
	}
	return err
}
func run(args []string) error {
	const usage = "commands: epoch-state, prepare-rotation, commit-rotation, revoke --device ID --reason TEXT, revocation-status --crl-epoch N, export-backup --out PATH, restore-backup --in PATH, verify-audit, bench"
	if len(args) == 0 {
		return errors.New(usage)
	}
	cmd := args[0]
	f := flag.NewFlagSet(cmd, flag.ContinueOnError)
	var device, reason, path string
	var epoch uint64
	switch cmd {
	case "revoke":
		f.StringVar(&device, "device", "", "device ID")
		f.StringVar(&reason, "reason", "", "revocation reason")
	case "revocation-status":
		f.Uint64Var(&epoch, "crl-epoch", 0, "revocation epoch")
	case "export-backup":
		f.StringVar(&path, "out", "", "new backup file")
	case "restore-backup":
		f.StringVar(&path, "in", "", "backup file")
	case "verify-audit", "epoch-state", "prepare-rotation", "commit-rotation", "bench":
	default:
		return errors.New(usage)
	}
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New(usage)
	}
	if cmd == "bench" {
		return bench()
	}
	cfg, err := config.LoadFromEnv()
	if err != nil {
		return err
	}
	h, err := transport.New(cfg, "admin")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cp := rpc.NewCryptoControlServiceClient(h.Client, cfg.ControlPlaneURL, connect.WithGRPC())
	switch cmd {
	case "epoch-state", "prepare-rotation", "commit-rotation":
		r, err := cp.GetEpochState(ctx, connect.NewRequest(&v.GetEpochStateRequest{}))
		if err != nil {
			return err
		}
		switch cmd {
		case "prepare-rotation":
			return show(cp.PrepareRotation(ctx, connect.NewRequest(&v.PrepareRotationRequest{ExpectedActiveEpoch: r.Msg.State.ActiveEpoch})))
		case "commit-rotation":
			return show(cp.CommitRotation(ctx, connect.NewRequest(&v.CommitRotationRequest{PreparedEpoch: r.Msg.State.PreparedEpoch})))
		}
		return show(r, nil)
	case "revoke":
		if device == "" || reason == "" {
			return errors.New(usage)
		}
		return show(cp.RevokeDevice(ctx, connect.NewRequest(&v.RevokeDeviceRequest{DeviceId: device, Reason: reason})))
	case "revocation-status":
		if epoch == 0 {
			return errors.New(usage)
		}
		return show(cp.GetRevocationStatus(ctx, connect.NewRequest(&v.GetRevocationStatusRequest{CrlEpoch: epoch})))
	case "export-backup":
		if path == "" {
			return errors.New(usage)
		}
		r, e := cp.ExportBackup(ctx, connect.NewRequest(&v.ExportBackupRequest{}))
		if e != nil {
			return e
		}
		out, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		_, e = out.Write(r.Msg.Bundle)
		e = errors.Join(e, out.Close())
		if e != nil {
			os.Remove(path)
		}
		return e
	case "restore-backup":
		data, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		return show(cp.RestoreBackup(ctx, connect.NewRequest(&v.RestoreBackupRequest{Bundle: data})))
	default:
		t := rpc.NewTelemetryServiceClient(h.Client, cfg.ControlPlaneURL, connect.WithGRPC())
		r, e := t.VerifyAuditChain(ctx, connect.NewRequest(&v.VerifyAuditChainRequest{}))
		if err := show(r, e); err != nil {
			return err
		}
		if !r.Msg.Valid {
			return errors.New("invalid audit chain")
		}
		return nil
	}
}
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
