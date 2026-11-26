package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/urguard/backend/detector"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = os.Getenv("URGUARD_CONTROLPLANE_PORT")
	}
	if port == "" {
		port = "8080"
	}

	skewSec := 30
	if raw := os.Getenv("URGUARD_MAX_CLOCK_SKEW_SEC"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			skewSec = parsed
		}
	}

	telemetry := detector.NewTelemetryService(time.Duration(skewSec)*time.Second, nil)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"service": "controlplane",
		})
	})
	telemetry.RegisterRoutes(mux)

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("controlplane listening on :%s (max_clock_skew=%ds)", port, skewSec)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("controlplane server error: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}
