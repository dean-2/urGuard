FROM golang:1.24.2-alpine AS builder

WORKDIR /src

COPY backend/go.mod backend/go.sum ./
RUN go mod download

COPY backend/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/controlplane ./cmd/controlplane

# Build minimal static HTTP health probe so distroless runtime needs no shell or wget.
RUN printf 'package main\nimport ("net/http";"os";"time")\nfunc main() { c := &http.Client{Timeout: 2 * time.Second}; r, e := c.Get(os.Args[1]); if e != nil || r.StatusCode >= 400 { os.Exit(1) } }\n' > /tmp/healthcheck.go && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/healthcheck /tmp/healthcheck.go

FROM gcr.io/distroless/static-debian12:nonroot

USER nonroot:nonroot
WORKDIR /app

COPY --from=builder /out/controlplane /usr/local/bin/controlplane
COPY --from=builder /out/healthcheck /usr/local/bin/healthcheck

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
  CMD ["/usr/local/bin/healthcheck", "http://127.0.0.1:8080/healthz"]

ENTRYPOINT ["/usr/local/bin/controlplane"]
