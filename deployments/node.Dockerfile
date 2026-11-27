FROM golang:1.26-alpine AS builder

WORKDIR /src

COPY backend/go.mod backend/go.sum ./
RUN go mod download

COPY backend/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/node ./cmd/node

# Build minimal static HTTP/HTTPS(mTLS) health probe so distroless runtime needs no shell or wget.
RUN printf 'package main\nimport ("crypto/tls";"crypto/x509";"net/http";"os";"strings";"time")\nfunc main() {\n  u := os.Args[1]\n  tr := &http.Transport{}\n  if strings.HasPrefix(u, "https://") {\n    tc := &tls.Config{MinVersion: tls.VersionTLS13}\n    if ca, err := os.ReadFile(os.Getenv("URGUARD_TLS_CA_FILE")); err == nil {\n      pool := x509.NewCertPool(); pool.AppendCertsFromPEM(ca); tc.RootCAs = pool\n    }\n    if cert, err := tls.LoadX509KeyPair(os.Getenv("URGUARD_TLS_CERT_FILE"), os.Getenv("URGUARD_TLS_KEY_FILE")); err == nil {\n      tc.Certificates = []tls.Certificate{cert}\n    }\n    tr.TLSClientConfig = tc\n  }\n  c := &http.Client{Timeout: 3 * time.Second, Transport: tr}\n  r, e := c.Get(u); if e != nil || r.StatusCode >= 400 { os.Exit(1) }\n}\n' > /tmp/healthcheck.go && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/healthcheck /tmp/healthcheck.go

FROM gcr.io/distroless/static-debian12:nonroot

USER nonroot:nonroot
WORKDIR /app

COPY --from=builder /out/node /usr/local/bin/node
COPY --from=builder /out/healthcheck /usr/local/bin/healthcheck

EXPOSE 8081

HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=5 \
  CMD ["/usr/local/bin/healthcheck", "https://localhost:8081/healthz"]

ENTRYPOINT ["/usr/local/bin/node"]
