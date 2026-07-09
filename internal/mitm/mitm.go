package mitm

import (
	"bytes"
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

// maxBodyPeek bounds how much of a request body is buffered for policy
// inspection. The only body-level matcher is the GraphQL mutation name, whose
// payload is tiny; larger writes (git push, asset uploads) are governed by
// method+path and stream through without being fully buffered.
const maxBodyPeek = 1 << 20

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
//
// The policy host is bound to the trusted authority (the host of dialAddr, which
// comes from the CONNECT target or SO_ORIGINAL_DST — neither of which the agent
// can forge), NOT the inner request's Host header. If the TLS SNI is present it
// must match too: a client that resolved a different name than it CONNECTed to
// is refused so the audit log can't be split from the real destination.
func (d Deps) ServeTLS(client net.Conn, dialAddr string) error {
	tlsConn := tls.Server(client, &tls.Config{
		GetCertificate: d.CA.GetCertificate,
		NextProtos:     []string{"http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		client.Close()
		return err
	}
	authority := StripPort(dialAddr)
	if sni := tlsConn.ConnectionState().ServerName; sni != "" && !strings.EqualFold(sni, authority) {
		// SNI disagreeing with the CONNECT/original-dst authority means the client
		// is trying to reach a name other than the one we're governing on. Refuse.
		tlsConn.Close()
		return nil
	}
	transport := &http.Transport{
		DialContext:     dialTo(dialAddr),
		TLSClientConfig: &tls.Config{ServerName: tlsConn.ConnectionState().ServerName},
	}
	d.serve(tlsConn, "https", authority, transport)
	return nil
}

// ServePlain governs cleartext HTTP arriving on a raw connection. The policy
// host is bound to the trusted authority (host of dialAddr), not the inner
// request's Host header.
func (d Deps) ServePlain(conn net.Conn, dialAddr string) {
	d.serve(conn, "http", StripPort(dialAddr), &http.Transport{DialContext: dialTo(dialAddr)})
}

// Decide evaluates OPA for one request, applying the fail-closed-with-essential
// posture when OPA can't be reached.
func (d Deps) Decide(method, host, path, body string, headers map[string]string) *policy.Decision {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dec, err := d.Pol.Eval(ctx, method, host, path, body, headers)
	if err == nil {
		return dec
	}
	if d.Essential[strings.ToLower(host)] {
		return &policy.Decision{Allowed: true, HTTPStatus: http.StatusOK, Reason: "opa_unavailable_essential", Enforced: true}
	}
	return &policy.Decision{Allowed: false, HTTPStatus: http.StatusServiceUnavailable, PolicyID: "guard", Reason: "policy_unavailable", Enforced: true}
}

// serve governs every request on conn against authority, the TRUSTED
// destination host (from the CONNECT target or SO_ORIGINAL_DST). The inner
// request's Host header is agent-controlled and MUST NOT key the policy: an
// agent can CONNECT one host and send an inner Host for another to falsify the
// audit log. Requests whose inner Host disagrees with authority are denied.
func (d Deps) serve(conn net.Conn, scheme, authority string, transport *http.Transport) {
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
		// Govern and record against the trusted authority, never the inner Host.
		host := authority
		if inner := StripPort(r.Host); !strings.EqualFold(inner, authority) {
			// Inner Host doesn't match where the tunnel actually goes: refuse
			// rather than evaluate, so a spoofed Host can't earn an allow to the
			// wrong place or split the audit trail from the real destination.
			latency := int(time.Since(start).Milliseconds())
			d.Rec.Add(r.Method, host, r.URL.Path, "deny", "guard", "host_mismatch", "", true, latency)
			http.Error(w, "host_mismatch", http.StatusForbidden)
			return
		}
		dec := d.Decide(r.Method, host, r.URL.Path, PeekBody(r), HeaderMap(r))
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

// PeekBody buffers up to maxBodyPeek bytes of the request body for policy
// inspection and restores r.Body so the request forwards upstream unchanged.
// A body larger than the cap is not returned for inspection but still streams
// through intact.
func PeekBody(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	peek, _ := io.ReadAll(io.LimitReader(r.Body, maxBodyPeek))
	var overflow [1]byte
	n, _ := io.ReadFull(r.Body, overflow[:])
	if n == 0 {
		r.Body = io.NopCloser(bytes.NewReader(peek))
		return string(peek)
	}
	r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(peek), bytes.NewReader(overflow[:n]), r.Body))
	return ""
}

// HeaderMap flattens request headers into the lowercased, comma-joined shape the
// Envoy ext_authz input uses, so the same policy bundle sees the same headers on
// the guard as on the cloud data plane (needed e.g. for AWS's X-Amz-Target).
func HeaderMap(r *http.Request) map[string]string {
	out := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		out[strings.ToLower(k)] = strings.Join(v, ",")
	}
	return out
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
