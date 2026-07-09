package ca

import (
	"crypto/tls"
	"fmt"
	"testing"
)

// newTestCA builds an in-memory CA with a small LRU capacity so eviction is
// exercisable without minting thousands of real ECDSA leaves.
func newTestCA(t *testing.T, cap int) *CA {
	t.Helper()
	cert, key, certPEM, _, err := generate()
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	leaves, lru := newLeafCache()
	return &CA{cert: cert, key: key, caPEM: certPEM, leaves: leaves, lru: lru, leafCap: cap}
}

func getLeaf(t *testing.T, c *CA, host string) *tls.Certificate {
	t.Helper()
	leaf, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: host})
	if err != nil {
		t.Fatalf("GetCertificate(%q): %v", host, err)
	}
	return leaf
}

// Minting more distinct SNIs than the cap must never grow the cache past cap.
func TestLeafCacheBounded(t *testing.T) {
	const cap = 8
	c := newTestCA(t, cap)

	for i := 0; i < cap*4; i++ {
		getLeaf(t, c, fmt.Sprintf("host-%d.example", i))
	}

	c.mu.Lock()
	gotMap, gotList := len(c.leaves), c.lru.Len()
	c.mu.Unlock()
	if gotMap != cap || gotList != cap {
		t.Fatalf("cache size = (map %d, list %d), want %d for both", gotMap, gotList, cap)
	}
}

// A recently-used entry survives eviction while the genuinely-oldest one is
// dropped once we mint past capacity.
func TestLeafCacheLRUEviction(t *testing.T) {
	const cap = 3
	c := newTestCA(t, cap)

	// Fill the cache: oldest .. newest = a, b, c.
	getLeaf(t, c, "a")
	getLeaf(t, c, "b")
	getLeaf(t, c, "c")

	// Touch "a" so it becomes most-recently-used; "b" is now the oldest.
	getLeaf(t, c, "a")

	// Mint a fresh SNI, forcing exactly one eviction.
	getLeaf(t, c, "d")

	c.mu.Lock()
	_, hasA := c.leaves["a"]
	_, hasB := c.leaves["b"]
	_, hasC := c.leaves["c"]
	_, hasD := c.leaves["d"]
	size := c.lru.Len()
	c.mu.Unlock()

	if size != cap {
		t.Fatalf("cache size = %d, want %d", size, cap)
	}
	if hasB {
		t.Errorf("oldest entry %q should have been evicted", "b")
	}
	if !hasA || !hasC || !hasD {
		t.Errorf("survivors = a:%v c:%v d:%v, want all true", hasA, hasC, hasD)
	}
}

// A cached SNI returns the identical *tls.Certificate on repeat, so we do not
// re-mint (or re-run keygen) for a name already in the cache.
func TestLeafCacheHitReturnsSameCert(t *testing.T) {
	c := newTestCA(t, 4)

	first := getLeaf(t, c, "repeat.example")
	second := getLeaf(t, c, "repeat.example")
	if first != second {
		t.Fatalf("repeat GetCertificate returned different *tls.Certificate pointers")
	}
}

// An empty SNI is rejected rather than cached.
func TestGetCertificateNoSNI(t *testing.T) {
	c := newTestCA(t, 4)
	if _, err := c.GetCertificate(&tls.ClientHelloInfo{ServerName: ""}); err == nil {
		t.Fatal("expected error for empty SNI, got nil")
	}
}
