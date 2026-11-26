package pqc

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestIdentity(t *testing.T) {
	id, err := GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	seed := id.PrivateBytes()
	restored, err := ParseIdentityKeyPair(seed)
	if err != nil {
		t.Fatal(err)
	}
	Zeroize(seed)
	if !bytes.Equal(restored.PublicBytes(), id.PublicBytes()) {
		t.Fatal("public key changed on restore")
	}
	ctx, msg := []byte("audit-checkpoint"), []byte("entry hash")
	sig, err := restored.Sign(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}
	pub := id.PublicBytes()
	if !VerifySignature(pub, ctx, msg, sig) {
		t.Fatal("valid signature rejected")
	}
	if VerifySignature(pub, nil, msg, sig) || VerifySignature(pub, ctx, nil, sig) || VerifySignature(pub[:1], ctx, msg, sig) {
		t.Fatal("accepted invalid signature inputs")
	}
	sig[0] ^= 1
	if VerifySignature(pub, ctx, msg, sig) {
		t.Fatal("accepted modified signature")
	}
	if _, err := id.Sign(make([]byte, 256), msg); err == nil {
		t.Fatal("accepted oversized context")
	}
	if _, err := ParseIdentityKeyPair(seed[:1]); err == nil {
		t.Fatal("accepted short seed")
	}
}

func TestHybridKEM(t *testing.T) {
	k, err := GenerateHybridKEMKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	transcript := []byte("session transcript")
	pub := k.PublicKey()
	ct, want, err := EncapsulateHybrid(pub, transcript)
	if err != nil {
		t.Fatal(err)
	}
	got, err := k.DecapsulateHybrid(ct, transcript)
	if err != nil || len(got) != 32 || !bytes.Equal(want, got) {
		t.Fatal("session keys disagree", err)
	}
	other, err := k.DecapsulateHybrid(ct, nil)
	if err != nil || bytes.Equal(other, want) {
		t.Fatal("missing transcript binding", err)
	}
	ct.MLKEM768[0] ^= 1
	other, err = k.DecapsulateHybrid(ct, transcript)
	if err == nil && bytes.Equal(other, want) {
		t.Fatal("changed ciphertext yielded original key")
	}
	if _, err := k.DecapsulateHybrid(HybridCiphertext{ct.EphemeralX25519, nil}, transcript); err == nil {
		t.Fatal("accepted empty ML-KEM ciphertext")
	}
	pub.X25519 = make([]byte, 32)
	if _, _, err := EncapsulateHybrid(pub, transcript); err == nil {
		t.Fatal("accepted low-order X25519 key")
	}
	x, seed := k.xPrivate, k.kemSeed
	k.Zeroize()
	k.Zeroize()
	if !bytes.Equal(x, make([]byte, 32)) || !bytes.Equal(seed, make([]byte, 64)) {
		t.Fatal("private buffers retained data")
	}
	if _, err := k.DecapsulateHybrid(ct, transcript); err == nil {
		t.Fatal("used destroyed key")
	}
}

func TestAEADAndSubkeys(t *testing.T) {
	master := make([]byte, 32)
	rand.Read(master)
	key, err := DeriveSubkey(master, "messages")
	if err != nil {
		t.Fatal(err)
	}
	other, err := DeriveSubkey(master, "files")
	if err != nil || bytes.Equal(key, other) {
		t.Fatal("subkeys must differ by purpose", err)
	}
	msg, aad := []byte("hello"), []byte("recipient")
	nonce, ct, err := SealAEAD(key, msg, aad)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenAEAD(key, nonce, ct, aad)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatal("round trip failed", err)
	}
	if _, err := OpenAEAD(key, nonce, ct, nil); err == nil {
		t.Fatal("ignored AAD")
	}
	ct[0] ^= 1
	if _, err := OpenAEAD(key, nonce, ct, aad); err == nil {
		t.Fatal("accepted changed ciphertext")
	}
	if _, err := OpenAEAD(key, nil, ct, aad); err == nil {
		t.Fatal("accepted empty nonce")
	}
	if _, err := SealAEADWithNonce(key, nonce[:1], nil, nil); err == nil {
		t.Fatal("accepted short nonce")
	}
	if _, _, err := SealAEAD(key[:16], nil, nil); err == nil {
		t.Fatal("accepted AES-128 key")
	}
}

// Each peer trusts only the test certificate generated for its counterpart.
func certificate(t testing.TB, name string, usage x509.ExtKeyUsage) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{name},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{raw}, PrivateKey: private, Leaf: leaf}, roots
}

func handshake(server, client *tls.Config) (tls.ConnectionState, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer listener.Close()
	deadline := time.Now().Add(5 * time.Second)
	done := make(chan error, 1)
	go func() {
		a, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer a.Close()
		a.SetDeadline(deadline)
		conn := tls.Server(a, server)
		done <- conn.Handshake()
	}()
	b, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Until(deadline))
	if err != nil {
		return tls.ConnectionState{}, err
	}
	b.SetDeadline(deadline)
	conn := tls.Client(b, client)
	err = conn.Handshake()
	defer b.Close()
	serverErr := <-done
	if err != nil {
		return tls.ConnectionState{}, err
	}
	return conn.ConnectionState(), serverErr
}

func TestHybridTLS(t *testing.T) {
	cert, roots := certificate(t, "control.local", x509.ExtKeyUsageServerAuth)
	node, clients := certificate(t, "node.local", x509.ExtKeyUsageClientAuth)
	for _, mutual := range []bool{false, true} {
		server := NewHybridTLSServerConfig(cert, nil)
		client := NewHybridTLSClientConfig("control.local", roots, nil)
		if mutual {
			server = NewHybridTLSServerConfig(cert, clients)
			client = NewHybridTLSClientConfig("control.local", roots, &node)
		}
		state, err := handshake(server, client)
		if err != nil {
			t.Fatal(err)
		}
		if state.Version != tls.VersionTLS13 || state.CurveID != tls.X25519MLKEM768 || state.NegotiatedProtocol != "h2" {
			t.Fatal("unexpected negotiated transport")
		}
	}
	server := NewHybridTLSServerConfig(cert, clients)
	if _, err := handshake(server, NewHybridTLSClientConfig("control.local", roots, nil)); err == nil {
		t.Fatal("accepted unauthenticated node")
	}
	if _, err := handshake(server, NewHybridTLSClientConfig("wrong.local", roots, &node)); err == nil {
		t.Fatal("accepted wrong server identity")
	}
}

func BenchmarkHybridKEM(b *testing.B) {
	k, err := GenerateHybridKEMKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	defer k.Zeroize()
	pub := k.PublicKey()
	transcript := []byte("benchmark transcript")
	ct, _, err := EncapsulateHybrid(pub, transcript)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("Encapsulate", func(b *testing.B) {
		for b.Loop() {
			if _, _, err := EncapsulateHybrid(pub, transcript); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Decapsulate", func(b *testing.B) {
		for b.Loop() {
			if _, err := k.DecapsulateHybrid(ct, transcript); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkHybridTLSHandshake(b *testing.B) {
	cert, roots := certificate(b, "control.local", x509.ExtKeyUsageServerAuth)
	node, clients := certificate(b, "node.local", x509.ExtKeyUsageClientAuth)
	server := NewHybridTLSServerConfig(cert, clients)
	client := NewHybridTLSClientConfig("control.local", roots, &node)
	for b.Loop() {
		if _, err := handshake(server, client); err != nil {
			b.Fatal(err)
		}
	}
}
