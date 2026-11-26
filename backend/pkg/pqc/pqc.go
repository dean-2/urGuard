// Package pqc provides urGuard's identity, session key and transport primitives.
package pqc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"runtime"
	"slices"
	"sync"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Zeroize clears this slice in place. Callers own any other copies. Go crypto
// implementations may retain internal copies until garbage collection.
func Zeroize(buf []byte) {
	clear(buf)
	runtime.KeepAlive(buf)
}

type IdentityKeyPair struct {
	seed    [mldsa65.SeedSize]byte
	public  *mldsa65.PublicKey
	private *mldsa65.PrivateKey
}

func GenerateIdentityKeyPair() (*IdentityKeyPair, error) {
	var seed [mldsa65.SeedSize]byte
	defer Zeroize(seed[:])
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	return ParseIdentityKeyPair(seed[:])
}

// ParseIdentityKeyPair restores both keys from the serialized ML-DSA seed.
func ParseIdentityKeyPair(seed []byte) (*IdentityKeyPair, error) {
	if len(seed) != mldsa65.SeedSize {
		return nil, errors.New("invalid ML-DSA-65 seed length")
	}
	id := &IdentityKeyPair{}
	copy(id.seed[:], seed)
	id.public, id.private = mldsa65.NewKeyFromSeed(&id.seed)
	return id, nil
}

// PrivateBytes returns an independent copy of the secret identity seed.
func (id *IdentityKeyPair) PrivateBytes() []byte { return slices.Clone(id.seed[:]) }
func (id *IdentityKeyPair) PublicBytes() []byte  { return id.public.Bytes() }

func (id *IdentityKeyPair) Sign(context, message []byte) ([]byte, error) {
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(id.private, message, context, true, sig); err != nil {
		return nil, err
	}
	return sig, nil
}

func VerifySignature(public, context, message, signature []byte) bool {
	var key mldsa65.PublicKey
	return len(signature) == mldsa65.SignatureSize && key.UnmarshalBinary(public) == nil && mldsa65.Verify(&key, message, context, signature)
}

type HybridPublicKey struct {
	X25519   []byte
	MLKEM768 []byte
}

type HybridCiphertext struct {
	EphemeralX25519 []byte
	MLKEM768        []byte
}

// HybridKEMKeyPair owns the private seed material. Use it by pointer.
type HybridKEMKeyPair struct {
	mu       sync.RWMutex
	xPrivate []byte
	kemSeed  []byte
	public   HybridPublicKey
}

func GenerateHybridKEMKeyPair() (*HybridKEMKeyPair, error) {
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	kem, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	return &HybridKEMKeyPair{xPrivate: x.Bytes(), kemSeed: kem.Bytes(),
		public: HybridPublicKey{x.PublicKey().Bytes(), kem.EncapsulationKey().Bytes()}}, nil
}

func (k *HybridKEMKeyPair) PublicKey() HybridPublicKey {
	return HybridPublicKey{slices.Clone(k.public.X25519), slices.Clone(k.public.MLKEM768)}
}

// ParseHybridKEMKeyPair restores a persisted X25519 scalar and ML-KEM-768 seed.
// The returned key owns its buffers independently of the input.
func ParseHybridKEMKeyPair(scalar, seed []byte) (*HybridKEMKeyPair, error) {
	x, err := ecdh.X25519().NewPrivateKey(scalar)
	if err != nil {
		return nil, err
	}
	k, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return nil, err
	}
	return &HybridKEMKeyPair{xPrivate: slices.Clone(scalar), kemSeed: slices.Clone(seed),
		public: HybridPublicKey{x.PublicKey().Bytes(), k.EncapsulationKey().Bytes()}}, nil
}

func (k *HybridKEMKeyPair) Zeroize() {
	k.mu.Lock()
	defer k.mu.Unlock()
	Zeroize(k.xPrivate)
	Zeroize(k.kemSeed)
	k.xPrivate, k.kemSeed = nil, nil
}

func EncapsulateHybrid(peer HybridPublicKey, transcript []byte) (HybridCiphertext, []byte, error) {
	x, err := ecdh.X25519().NewPublicKey(peer.X25519)
	if err != nil {
		return HybridCiphertext{}, nil, err
	}
	kem, err := mlkem.NewEncapsulationKey768(peer.MLKEM768)
	if err != nil {
		return HybridCiphertext{}, nil, err
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return HybridCiphertext{}, nil, err
	}
	dh, err := ephemeral.ECDH(x)
	if err != nil {
		return HybridCiphertext{}, nil, err
	}
	defer Zeroize(dh)
	pq, ct := kem.Encapsulate()
	defer Zeroize(pq)
	out := HybridCiphertext{ephemeral.PublicKey().Bytes(), ct}
	key, err := hybridKey(dh, pq, peer, out, transcript)
	return out, key, err
}

func (k *HybridKEMKeyPair) DecapsulateHybrid(ct HybridCiphertext, transcript []byte) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if len(k.xPrivate) == 0 {
		return nil, errors.New("hybrid private key unavailable")
	}
	x, err := ecdh.X25519().NewPublicKey(ct.EphemeralX25519)
	if err != nil {
		return nil, err
	}
	private, err := ecdh.X25519().NewPrivateKey(k.xPrivate)
	if err != nil {
		return nil, err
	}
	dh, err := private.ECDH(x)
	if err != nil {
		return nil, err
	}
	defer Zeroize(dh)
	kem, err := mlkem.NewDecapsulationKey768(k.kemSeed)
	if err != nil {
		return nil, err
	}
	pq, err := kem.Decapsulate(ct.MLKEM768)
	if err != nil {
		return nil, err
	}
	defer Zeroize(pq)
	return hybridKey(dh, pq, k.public, ct, transcript)
}

func hybridKey(dh, pq []byte, peer HybridPublicKey, ct HybridCiphertext, transcript []byte) ([]byte, error) {
	// Every field preceding the caller's transcript has a fixed wire length.
	h := sha256.New()
	for _, field := range [][]byte{peer.X25519, peer.MLKEM768, ct.EphemeralX25519, ct.MLKEM768, transcript} {
		h.Write(field)
	}
	secrets := slices.Concat(dh, pq)
	defer Zeroize(secrets)
	return hkdf.Key(sha256.New, secrets, h.Sum(nil), "urguard/v1/hybrid-x25519-mlkem768", 32)
}

// DeriveSubkey derives a 256-bit key for a distinct application purpose.
func DeriveSubkey(master []byte, purpose string) ([]byte, error) {
	if len(master) != 32 || purpose == "" {
		return nil, errors.New("subkey requires a 32-byte master and a purpose")
	}
	return hkdf.Key(sha256.New, master, nil, "urguard/v1/subkey/"+purpose, 32)
}

func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("AES-256 requires a 32-byte key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// SealAEAD returns a random nonce and authenticated ciphertext. Use at most
// 2^32 random nonces per key.
func SealAEAD(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	nonce = make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext, err = SealAEADWithNonce(key, nonce, plaintext, aad)
	if err != nil {
		return nil, nil, err
	}
	return nonce, ciphertext, nil
}

// SealAEADWithNonce requires a unique 12-byte nonce for every use of a key.
func SealAEADWithNonce(key, nonce, plaintext, aad []byte) ([]byte, error) {
	a, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != a.NonceSize() {
		return nil, errors.New("invalid GCM nonce length")
	}
	return a.Seal(nil, nonce, plaintext, aad), nil
}

func OpenAEAD(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	a, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != a.NonceSize() {
		return nil, errors.New("invalid GCM nonce length")
	}
	return a.Open(nil, nonce, ciphertext, aad)
}

func hybridTLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, NextProtos: []string{"h2"}}
}

// NewHybridTLSServerConfig requires verified client certificates when clientCAs is supplied.
func NewHybridTLSServerConfig(cert tls.Certificate, clientCAs *x509.CertPool) *tls.Config {
	c := hybridTLSConfig()
	c.Certificates = []tls.Certificate{cert}
	if clientCAs != nil {
		c.ClientAuth = tls.RequireAndVerifyClientCert
		c.ClientCAs = clientCAs
	}
	return c
}

func NewHybridTLSClientConfig(serverName string, roots *x509.CertPool, cert *tls.Certificate) *tls.Config {
	c := hybridTLSConfig()
	c.ServerName, c.RootCAs = serverName, roots
	if cert != nil {
		c.Certificates = []tls.Certificate{*cert}
	}
	return c
}
