package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aarvion-ai/aarvion-guard/internal/ca"
	"github.com/aarvion-ai/aarvion-guard/internal/decisions"
	"github.com/aarvion-ai/aarvion-guard/internal/mitm"
	"github.com/aarvion-ai/aarvion-guard/internal/policy"
	"github.com/aarvion-ai/aarvion-guard/internal/ratelimit"
)

// fakeOPA denies write methods, allows the rest — the shape the real bundle uses.
func fakeOPA(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Input struct {
				Attributes struct {
					Request struct {
						HTTP struct {
							Method string `json:"method"`
						} `json:"http"`
					} `json:"request"`
				} `json:"attributes"`
			} `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		m := req.Input.Attributes.Request.HTTP.Method
		allowed := m == "GET" || m == "HEAD" || m == "CONNECT"
		resp := map[string]any{"result": map[string]any{"allowed": allowed}}
		if !allowed {
			resp["result"].(map[string]any)["http_status"] = 403
			resp["result"].(map[string]any)["headers"] = map[string]string{
				"x-policy-violated": "github_read_only_v4", "x-policy-reason": "write denied",
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func newGuard(t *testing.T, addr string, passthrough []string) (*decisions.Recorder, *ca.CA) {
	t.Helper()
	opa := fakeOPA(t)
	t.Cleanup(opa.Close)
	dir := t.TempDir()
	authority, err := ca.EnsureCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	pol := policy.New(strings.TrimPrefix(opa.URL, "http://"))
	rec := decisions.New("http://cp.invalid", "t", "e", "tok", "dp", "")
	srv := New(addr, authority, pol, rec, nil, passthrough, true, nil, mitm.Allowlist{}, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.ListenAndServe(ctx) }()
	waitListening(t, addr)
	return rec, authority
}

// newRateLimitedGuard starts a forward proxy whose OPA allows every request, so
// any deny observed comes purely from the injected rate limiter. Used to prove
// the ceiling denies over-limit egress while under-limit egress is governed
// normally, end-to-end through the real proxy handler.
func newRateLimitedGuard(t *testing.T, addr string, limiter *ratelimit.Limiter) *decisions.Recorder {
	t.Helper()
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"allowed": true}})
	}))
	t.Cleanup(opa.Close)
	dir := t.TempDir()
	authority, err := ca.EnsureCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	pol := policy.New(strings.TrimPrefix(opa.URL, "http://"))
	rec := decisions.New("http://cp.invalid", "t", "e", "tok", "dp", "")
	srv := New(addr, authority, pol, rec, nil, nil, true, limiter, mitm.Allowlist{}, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.ListenAndServe(ctx) }()
	waitListening(t, addr)
	return rec
}

// A host over its per-window ceiling gets a rate_limited 429 deny through the
// real forward-proxy handler, while a distinct under-limit host is governed
// normally (allowed → forwarded). The deny is recorded so it flows to the CP
// push and observability sinks.
func TestForwardHttpRateLimited(t *testing.T) {
	addr := "127.0.0.1:18906"
	// Ceiling of 1/min so the second request to the same host is over the limit.
	rec := newRateLimitedGuard(t, addr, ratelimit.New(1, time.Minute, nil))

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "upstream-ok")
	}))
	defer upstream.Close()

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	// First GET to the upstream host: under the ceiling, allowed, forwarded.
	resp1, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()
	if resp1.StatusCode != 200 || string(body1) != "upstream-ok" {
		t.Fatalf("first (under-limit) request: got %d %q, want 200 upstream-ok", resp1.StatusCode, body1)
	}

	// Second GET to the same host: over the ceiling → 429 rate_limited.
	resp2, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second (over-limit) request: got %d %q, want 429", resp2.StatusCode, body2)
	}
	if !strings.Contains(string(body2), "rate_limited") {
		t.Fatalf("over-limit body = %q, want rate_limited", body2)
	}
	if _, denies, _, _ := rec.Stats(); denies < 1 {
		t.Fatalf("rate-limited deny not recorded: denies=%d", denies)
	}
}

// With a nil limiter the proxy behaves exactly as before: repeated allowed
// requests to the same host are all forwarded, never rate-limited.
func TestForwardHttpNilLimiterUnchanged(t *testing.T) {
	addr := "127.0.0.1:18907"
	rec := newRateLimitedGuard(t, addr, nil)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	for i := 0; i < 5; i++ {
		resp, err := client.Get(upstream.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("nil limiter must never rate-limit (request %d got 429)", i+1)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("request %d: got %d, want 200", i+1, resp.StatusCode)
		}
	}
	if _, denies, _, _ := rec.Stats(); denies != 0 {
		t.Fatalf("nil limiter produced %d denies, want 0", denies)
	}
}

// newAllowlistGuard starts a forward proxy whose OPA allows every request, so any
// deny observed comes purely from the default-deny allowlist. Used to prove that
// enforce mode denies a novel host while an allowlisted host is forwarded,
// end-to-end through the real proxy handler.
func newAllowlistGuard(t *testing.T, addr string, allowlist mitm.Allowlist) *decisions.Recorder {
	t.Helper()
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"allowed": true}})
	}))
	t.Cleanup(opa.Close)
	dir := t.TempDir()
	authority, err := ca.EnsureCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	pol := policy.New(strings.TrimPrefix(opa.URL, "http://"))
	rec := decisions.New("http://cp.invalid", "t", "e", "tok", "dp", "")
	srv := New(addr, authority, pol, rec, nil, nil, true, nil, allowlist, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.ListenAndServe(ctx) }()
	waitListening(t, addr)
	return rec
}

// Enforce mode denies a novel (non-allowlisted, non-essential) host with a
// not_allowlisted 403 through the real forward-proxy handler, recorded as a deny;
// an allowlisted host is governed by OPA and forwarded. The allowlist is keyed on
// the proxied Host (127.0.0.1 for the httptest upstream), so listing that host
// lets the allowed request through while a bogus host is denied outright.
func TestForwardHttpAllowlistEnforce(t *testing.T) {
	addr := "127.0.0.1:18908"
	rec := newAllowlistGuard(t, addr, mitm.Allowlist{
		Mode:  mitm.AllowlistEnforce,
		Hosts: mitm.Essentials([]string{"127.0.0.1"}),
	})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "upstream-ok")
	}))
	defer upstream.Close()

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	// Allowlisted host (127.0.0.1 upstream): governed by OPA (allows) → forwarded.
	resp1, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()
	if resp1.StatusCode != 200 || string(body1) != "upstream-ok" {
		t.Fatalf("allowlisted host: got %d %q, want 200 upstream-ok", resp1.StatusCode, body1)
	}

	// Novel host: a plain (non-CONNECT) proxied request to a host not on the
	// allowlist. Denied 403 not_allowlisted before OPA or any upstream dial.
	req, _ := http.NewRequest(http.MethodGet, "http://novel.example.invalid/", nil)
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("novel host: got %d %q, want 403", resp2.StatusCode, body2)
	}
	if !strings.Contains(string(body2), "not_allowlisted") {
		t.Fatalf("novel-host body = %q, want not_allowlisted", body2)
	}
	if _, denies, _, _ := rec.Stats(); denies < 1 {
		t.Fatalf("allowlist deny not recorded: denies=%d", denies)
	}
}

// A disabled allowlist (off/empty mode) leaves the forward proxy behaving exactly
// as before: a host that would be "novel" under a gate is forwarded normally.
func TestForwardHttpAllowlistDisabledUnchanged(t *testing.T) {
	addr := "127.0.0.1:18909"
	rec := newAllowlistGuard(t, addr, mitm.Allowlist{}) // off

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("disabled allowlist: got %d, want 200 (unchanged behavior)", resp.StatusCode)
	}
	if _, denies, _, _ := rec.Stats(); denies != 0 {
		t.Fatalf("disabled allowlist produced %d denies, want 0", denies)
	}
}

// The money shot: a write over HTTPS through a CONNECT tunnel is MITM'd, its
// method is seen, and it is denied — the shell-bypass fix.
func TestConnectMitmDeniesHttpsWrite(t *testing.T) {
	addr := "127.0.0.1:18901"
	rec, authority := newGuard(t, addr, nil)

	// Open a CONNECT tunnel through the guard.
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Write([]byte("CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(raw)
	status, _ := br.ReadString('\n')
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT not established: %q", status)
	}
	for {
		line, _ := br.ReadString('\n')
		if line == "\r\n" || line == "" {
			break
		}
	}

	// TLS handshake inside the tunnel: the client trusts the guard's CA (as it
	// would after `guard init` installs it), so the MITM'd leaf validates.
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(authority.CertPEM())
	tlsConn := tls.Client(&connWrap{Conn: raw, r: br}, &tls.Config{ServerName: "api.github.com", RootCAs: pool})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake through MITM failed: %v", err)
	}

	// A DELETE (the gh-style write) must be denied by the guard.
	req, _ := http.NewRequest(http.MethodDelete, "https://api.github.com/repos/x/y/issues/17", nil)
	if err := req.Write(tlsConn); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("DELETE over MITM'd HTTPS: got %d, want 403", resp.StatusCode)
	}

	total, denies, _, _ := rec.Stats()
	if denies < 1 || total < 1 {
		t.Fatalf("deny not recorded: total=%d denies=%d", total, denies)
	}
}

// The host-binding fix: an agent CONNECTs to one authority, then sends an inner
// Host header for another to try to earn an allow (and audit entry) against the
// wrong destination. The guard must bind policy to the CONNECT authority and
// deny the mismatch outright — never evaluate the spoofed host.
func TestConnectMitmDeniesInnerHostMismatch(t *testing.T) {
	addr := "127.0.0.1:18904"
	rec, authority := newGuard(t, addr, nil)

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	// CONNECT to api.github.com — the trusted authority.
	if _, err := raw.Write([]byte("CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(raw)
	status, _ := br.ReadString('\n')
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT not established: %q", status)
	}
	for {
		line, _ := br.ReadString('\n')
		if line == "\r\n" || line == "" {
			break
		}
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(authority.CertPEM())
	// SNI matches the CONNECT authority (as a real client would send).
	tlsConn := tls.Client(&connWrap{Conn: raw, r: br}, &tls.Config{ServerName: "api.github.com", RootCAs: pool})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake through MITM failed: %v", err)
	}

	// A GET (normally allowed) but with the inner Host spoofed to a different
	// authority. Bind was to api.github.com, so this must be denied on mismatch,
	// not evaluated against api.anthropic.com.
	req, _ := http.NewRequest(http.MethodGet, "https://api.github.com/v1/messages", nil)
	req.Host = "api.anthropic.com"
	if err := req.Write(tlsConn); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("spoofed inner Host: got %d, want 403", resp.StatusCode)
	}
	if !strings.Contains(string(body), "host_mismatch") {
		t.Fatalf("spoofed inner Host: body %q, want host_mismatch reason", body)
	}
	// The recorded deny must be keyed to the trusted authority, never the spoof.
	if total, denies, _, _ := rec.Stats(); denies < 1 || total < 1 {
		t.Fatalf("host_mismatch deny not recorded: total=%d denies=%d", total, denies)
	}
}

// The matching case: same CONNECT authority, inner Host agrees, an allowed
// method (GET) governs normally and is forwarded — no host_mismatch, no deny.
// The upstream dial is expected to fail (no real api.github.com in the test), so
// the guard returns 502 AFTER allowing; the recorder proves the allow ran.
func TestConnectMitmAllowsMatchingInnerHost(t *testing.T) {
	addr := "127.0.0.1:18905"
	rec, authority := newGuard(t, addr, nil)

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	// CONNECT to api.github.com — the trusted authority.
	if _, err := raw.Write([]byte("CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(raw)
	status, _ := br.ReadString('\n')
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT not established: %q", status)
	}
	for {
		line, _ := br.ReadString('\n')
		if line == "\r\n" || line == "" {
			break
		}
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(authority.CertPEM())
	tlsConn := tls.Client(&connWrap{Conn: raw, r: br}, &tls.Config{ServerName: "api.github.com", RootCAs: pool})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake through MITM failed: %v", err)
	}

	// GET with inner Host matching the CONNECT authority: allowed, then forwarded.
	req, _ := http.NewRequest(http.MethodGet, "https://api.github.com/repos/x/y", nil)
	if err := req.Write(tlsConn); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// A matching, allowed request is NOT a 403: it either reaches upstream (200)
	// or fails the upstream dial (502). What it must never be is a policy 403.
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("matching inner Host GET was denied 403; want it allowed/forwarded")
	}
	if total, denies, _, _ := rec.Stats(); total < 1 || denies != 0 {
		t.Fatalf("matching request not recorded as allow: total=%d denies=%d", total, denies)
	}
}

func TestForwardHttpGoverns(t *testing.T) {
	addr := "127.0.0.1:18902"
	rec, _ := newGuard(t, addr, nil)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "upstream-ok")
	}))
	defer upstream.Close()

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "upstream-ok" {
		t.Fatalf("allowed GET: got %d %q", resp.StatusCode, body)
	}

	resp2, err := client.Post(upstream.URL, "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 403 {
		t.Fatalf("denied POST: got %d, want 403", resp2.StatusCode)
	}
	if total, denies, _, _ := rec.Stats(); total < 2 || denies < 1 {
		t.Fatalf("decisions not recorded: total=%d denies=%d", total, denies)
	}
}

// A passthrough (cert-pinned) host is tunneled raw — not MITM'd — so bytes
// flow through untouched after a host-level allow.
func TestPassthroughSplices(t *testing.T) {
	// Raw TCP echo server standing in for a cert-pinned upstream.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(c, c); c.Close() }(c)
		}
	}()
	upstreamHost, upstreamPort, _ := net.SplitHostPort(ln.Addr().String())

	addr := "127.0.0.1:18903"
	newGuard(t, addr, []string{upstreamHost})

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	target := net.JoinHostPort(upstreamHost, upstreamPort)
	if _, err := raw.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(raw)
	status, _ := br.ReadString('\n')
	if !strings.Contains(status, "200") {
		t.Fatalf("passthrough CONNECT not established: %q", status)
	}
	for {
		line, _ := br.ReadString('\n')
		if line == "\r\n" || line == "" {
			break
		}
	}
	// Raw bytes echo straight back — proof the guard spliced rather than MITM'd.
	if _, err := raw.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	raw.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("passthrough echo: got %q", buf)
	}
}

// connWrap lets the already-buffered CONNECT reader feed the TLS client.
type connWrap struct {
	net.Conn
	r *bufio.Reader
}

func (c *connWrap) Read(p []byte) (int, error) { return c.r.Read(p) }

func waitListening(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 50; i++ {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("guard never listened on %s", addr)
}
