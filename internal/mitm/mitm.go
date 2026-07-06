package mitm

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/aarvion-ai/aarvion-guard/internal/ca"
	"github.com/aarvion-ai/aarvion-guard/internal/decisions"
	"github.com/aarvion-ai/aarvion-guard/internal/policy"
)

// Deps is the shared body-level governance core used by both the forward proxy
// (inside a CONNECT tunnel) and the transparent server. It terminates TLS with
// the local CA so method/path/body are visible to policy, then streams allowed
// requests upstream.
type Deps struct {
	CA        *ca.CA
	Pol       *policy.Client
	Rec       *decisions.Recorder
	Essential map[string]bool
}

func Essentials(hosts []string) map[string]bool {
	set := map[string]bool{}
	for _, h := range hosts {
		set[strings.ToLower(h)] = true
	}
	return set
}

// ServeTLS terminates the client's TLS with a minted leaf, then governs each
// HTTP request over it, forwarding allowed ones to dialAddr (host:port). A
// non-nil return means the client rejected the MITM leaf (e.g. a cert-pinned
// client) — the caller can then fall back to passthrough.
func (d Deps) ServeTLS(client net.Conn, dialAddr string) error {
	tlsConn := tls.Server(client, &tls.Config{
		GetCertificate: d.CA.GetCertificate,
		NextProtos:     []string{"http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		client.Close()
		return err
	}
	transport := &http.Transport{
		DialContext:     dialTo(dialAddr),
		TLSClientConfig: &tls.Config{ServerName: tlsConn.ConnectionState().ServerName},
	}
	d.serve(tlsConn, "https", transport)
	return nil
}

// ServePlain governs cleartext HTTP arriving on a raw connection.
func (d Deps) ServePlain(conn net.Conn, dialAddr string) {
	d.serve(conn, "http", &http.Transport{DialContext: dialTo(dialAddr)})
}

// Decide evaluates OPA for one request, applying the fail-closed-with-essential
// posture when OPA can't be reached.
func (d Deps) Decide(method, host, path string) *policy.Decision {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dec, err := d.Pol.Eval(ctx, method, host, path, map[string]string{})
	if err == nil {
		return dec
	}
	if d.Essential[strings.ToLower(host)] {
		return &policy.Decision{Allowed: true, HTTPStatus: http.StatusOK, Reason: "opa_unavailable_essential", Enforced: true}
	}
	return &policy.Decision{Allowed: false, HTTPStatus: http.StatusServiceUnavailable, PolicyID: "guard", Reason: "policy_unavailable", Enforced: true}
}

func (d Deps) serve(conn net.Conn, scheme string, transport *http.Transport) {
	proxy := &httputil.ReverseProxy{
		Director:      func(*http.Request) {},
		Transport:     transport,
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		host := StripPort(r.Host)
		dec := d.Decide(r.Method, host, r.URL.Path)
		latency := int(time.Since(start).Milliseconds())
		if !dec.Allowed {
			d.Rec.Add(r.Method, host, r.URL.Path, "deny", dec.PolicyID, dec.Reason, "", dec.Enforced, latency)
			http.Error(w, dec.Reason, dec.HTTPStatus)
			return
		}
		d.Rec.Add(r.Method, host, r.URL.Path, "allow", "", "", dec.Redactions, dec.Enforced, latency)
		r.URL.Scheme = scheme
		r.URL.Host = r.Host
		proxy.ServeHTTP(w, r)
	})
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 20 * time.Second}
	_ = srv.Serve(&oneConnListener{conn: conn})
}

func dialTo(addr string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dr net.Dialer
		return dr.DialContext(ctx, "tcp", addr)
	}
}

func StripPort(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// oneConnListener feeds a single already-accepted connection to http.Server;
// the second Accept returns io.EOF so Serve exits while the connection keeps
// being served in the background.
type oneConnListener struct {
	conn net.Conn
	used bool
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	if l.used {
		return nil, io.EOF
	}
	l.used = true
	return l.conn, nil
}

func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }
