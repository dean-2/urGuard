// Package transport wires authenticated HTTP/2 for the control plane and relays.
package transport

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/dean-2/urGuard/backend/internal/config"
	"github.com/dean-2/urGuard/backend/pkg/pqc"
)

type principalKey struct{}

func Principal(ctx context.Context) string { p, _ := ctx.Value(principalKey{}).(string); return p }
func WithPrincipal(ctx context.Context, principal string) context.Context {
	return context.WithValue(ctx, principalKey{}, principal)
}
func loopback(host string) bool { return host == "localhost" || net.ParseIP(host).IsLoopback() }

type bearer struct {
	base  http.RoundTripper
	token string
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

type HTTP struct {
	Client    *http.Client
	serverTLS *tls.Config
	cfg       config.Config
}

func New(c config.Config, principal string) (*HTTP, error) {
	h := &HTTP{cfg: c}
	protocols := new(http.Protocols)
	tr := &http.Transport{Protocols: protocols}
	var rt http.RoundTripper = tr
	if c.ControlPlaneGRPCTLS {
		protocols.SetHTTP2(true)
		cert, err := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
		if err != nil {
			return nil, err
		}
		ca, err := os.ReadFile(c.TLSCA)
		if err != nil {
			return nil, err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			return nil, errors.New("invalid trust roots")
		}
		tr.TLSClientConfig = pqc.NewHybridTLSClientConfig("", roots, &cert)
		h.serverTLS = pqc.NewHybridTLSServerConfig(cert, roots)
	} else {
		protocols.SetUnencryptedHTTP2(true)
		if c.Tokens[principal] == "" {
			return nil, errors.New("local h2c requires a configured principal token")
		}
		rt = bearer{tr, c.Tokens[principal]}
	}
	for _, endpoint := range []string{c.ControlPlaneURL, c.WitnessURL} {
		if endpoint == "" {
			continue
		}
		u, err := url.Parse(endpoint)
		if err != nil || c.ControlPlaneGRPCTLS && u.Scheme != "https" || !c.ControlPlaneGRPCTLS && (u.Scheme != "http" || !loopback(u.Hostname())) {
			return nil, errors.New("endpoint incompatible with transport mode")
		}
	}
	h.Client = &http.Client{Transport: rt, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return h, nil
}

// Authenticate binds the verified transport identity to each RPC context.
func (h *HTTP) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		p := ""
		if h.serverTLS != nil {
			if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 {
				p = r.TLS.VerifiedChains[0][0].Subject.CommonName
			}
		} else if value, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
			for name, token := range h.cfg.Tokens {
				if subtle.ConstantTimeCompare([]byte(token), []byte(value)) == 1 {
					p = name
					break
				}
			}
		}
		if p == "" {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	})
}
func (h *HTTP) Serve(ctx context.Context, addr string, mux http.Handler) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	protocols := new(http.Protocols)
	if h.serverTLS == nil {
		if !loopback(host) {
			return errors.New("h2c listener must be loopback")
		}
		protocols.SetUnencryptedHTTP2(true)
		protocols.SetHTTP1(true)
	} else {
		protocols.SetHTTP2(true)
		protocols.SetHTTP1(true)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := http.Server{Handler: h.Authenticate(mux), Protocols: protocols, TLSConfig: h.serverTLS, ReadHeaderTimeout: 10 * time.Second, BaseContext: func(net.Listener) context.Context { return ctx }}
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if srv.Shutdown(stop) != nil {
			srv.Close()
		}
	}()
	if h.serverTLS != nil {
		err = srv.ServeTLS(ln, "", "")
	} else {
		err = srv.Serve(ln)
	}
	if errors.Is(err, http.ErrServerClosed) {
		<-done
		return nil
	}
	return err
}
