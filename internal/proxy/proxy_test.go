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
	"github.com/aarvion-ai/aarvion-guard/internal/policy"
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
	rec := decisions.New("http://cp.invalid", "t", "e", "tok", "dp")
	srv := New(addr, authority, pol, rec, nil, passthrough, true)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.ListenAndServe(ctx) }()
	waitListening(t, addr)
	return rec, authority
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

	total, denies, _ := rec.Stats()
	if denies < 1 || total < 1 {
		t.Fatalf("deny not recorded: total=%d denies=%d", total, denies)
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
	if total, denies, _ := rec.Stats(); total < 2 || denies < 1 {
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
