package ca

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// leafCacheCap bounds how many minted leaf certs we keep. Without a bound a
// transparent-mode client can walk distinct SNIs forever, forcing a fresh
// ECDSA keygen plus unbounded map growth per name (memory + CPU DoS). The cache
// is an LRU: once full, minting a new leaf evicts the least-recently-used one.
const leafCacheCap = 1024

// leafEntry is the value carried by each LRU list element. We keep host so an
// eviction from the back of the list can delete the matching map key.
type leafEntry struct {
	host string
	leaf *tls.Certificate
}

// CA is a machine-local certificate authority. Its private key never leaves the
// box (locked decision §12.3) — it is only ever used to mint short leaf certs
// on the fly for hosts the guard inspects.
type CA struct {
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	caPEM []byte

	mu sync.Mutex
	// leaves indexes SNI -> *list.Element for O(1) lookup; lru orders those
	// elements most-recently-used (front) to least (back). Both are guarded
	// by mu and stay in lock-step.
	leaves map[string]*list.Element
	lru    *list.List
	// leafCap is the LRU capacity; 0 means use leafCacheCap. It exists so tests
	// can drive eviction without minting thousands of real ECDSA leaves.
	leafCap int
}

// cap returns the effective LRU capacity. Callers hold c.mu.
func (c *CA) cap() int {
	if c.leafCap > 0 {
		return c.leafCap
	}
	return leafCacheCap
}

// newLeafCache builds an empty bounded leaf cache. Every CA constructor uses it
// so leaves/lru are never nil.
func newLeafCache() (map[string]*list.Element, *list.List) {
	return make(map[string]*list.Element), list.New()
}

func EnsureCA(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	if certPEM, err := os.ReadFile(certPath); err == nil {
		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		return load(certPEM, keyPEM)
	}

	cert, key, certPEM, keyPEM, err := generate()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	leaves, lru := newLeafCache()
	return &CA{cert: cert, key: key, caPEM: certPEM, leaves: leaves, lru: lru}, nil
}

func generate() (*x509.Certificate, *ecdsa.PrivateKey, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Aarvion Guard Local CA", Organization: []string{"Aarvion"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return cert, key, certPEM, keyPEM, nil
}

func load(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, fmt.Errorf("malformed CA material")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	leaves, lru := newLeafCache()
	return &CA{cert: cert, key: key, caPEM: certPEM, leaves: leaves, lru: lru}, nil
}

// CertPEM returns the CA cert to add to a trust store.
func (c *CA) CertPEM() []byte { return c.caPEM }

// GetCertificate mints (and caches) a leaf for the requested SNI, so it plugs
// straight into tls.Config.GetCertificate.
func (c *CA) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := hello.ServerName
	if host == "" {
		return nil, fmt.Errorf("no SNI on the connection")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.leaves[host]; ok {
		// Cache hit: promote to most-recently-used and hand back the leaf.
		c.lru.MoveToFront(el)
		return el.Value.(*leafEntry).leaf, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(0, 0, 90),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	leaf := &tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw},
		PrivateKey:  key,
	}
	// Insert at the front (most-recently-used) and evict from the back until we
	// are back within capacity.
	c.leaves[host] = c.lru.PushFront(&leafEntry{host: host, leaf: leaf})
	for c.lru.Len() > c.cap() {
		oldest := c.lru.Back()
		if oldest == nil {
			break
		}
		c.lru.Remove(oldest)
		delete(c.leaves, oldest.Value.(*leafEntry).host)
	}
	return leaf, nil
}
