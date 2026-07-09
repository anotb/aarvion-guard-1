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
	"github.com/aarvion-ai/aarvion-guard/internal/ratelimit"
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
	Essential EssentialSet

	// Limiter is an optional in-memory, per-host egress rate ceiling checked
	// BEFORE OPA (see Decide). A nil Limiter disables rate limiting entirely and
	// preserves the pre-feature behavior exactly.
	Limiter *ratelimit.Limiter

	// Allowlist is an optional default-deny egress gate keyed on destination
	// host, checked AFTER the rate limiter but BEFORE OPA (see Decide). Its zero
	// value (mode "") disables gating entirely and preserves the pre-feature
	// behavior exactly.
	Allowlist Allowlist
}

// Allowlist configures a default-deny egress posture: only approved (or
// essential) hosts may be reached; anything novel is denied — or, in observe
// mode, allowed but flagged so an operator sees what enforcement WOULD block.
// Hosts reuses EssentialSet so a "."-prefixed entry matches by host suffix, the
// same as essential_hosts.
type Allowlist struct {
	Mode  string // one of AllowlistOff, AllowlistObserve, AllowlistEnforce
	Hosts EssentialSet
}

// Allowlist modes. Off (or an empty mode) disables gating entirely.
const (
	AllowlistOff     = "off"
	AllowlistObserve = "observe"
	AllowlistEnforce = "enforce"
)

// EssentialSet matches hosts that stay reachable when OPA is down. A plain
// entry ("api.anthropic.com") matches only that exact host; an entry beginning
// with a dot (".openai.azure.com") matches any host ending in that suffix, so a
// whole provider domain can be covered without listing every subdomain.
type EssentialSet struct {
	exact    map[string]bool
	suffixes []string
}

func Essentials(hosts []string) EssentialSet {
	s := EssentialSet{exact: map[string]bool{}}
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if strings.HasPrefix(h, ".") {
			s.suffixes = append(s.suffixes, h)
			continue
		}
		s.exact[h] = true
	}
	return s
}

// Has reports whether host is essential, by exact match or by matching any
// registered suffix entry. host is compared case-insensitively.
func (s EssentialSet) Has(host string) bool {
	host = strings.ToLower(host)
	if s.exact[host] {
		return true
	}
	for _, suf := range s.suffixes {
		// suf is ".example.com"; match a subdomain ("x.example.com") and the
		// bare apex ("example.com"), but never a substring ("notexample.com").
		if strings.HasSuffix(host, suf) || host == suf[1:] {
			return true
		}
	}
	return false
}

// ServeTLS terminates the client's TLS with a minted leaf, then governs each
// HTTP request over it, forwarding allowed ones to dialAddr (host:port). A
// non-nil return means the client rejected the MITM leaf (e.g. a cert-pinned
// client) — the caller can then fall back to passthrough.
//
// The policy host is bound to a trusted destination, never the agent-controlled
// inner Host header. When dialAddr is a hostname (a forward-proxy CONNECT
// target) that name is authoritative and a disagreeing SNI is refused. When
// dialAddr is an IP literal (transparent original-dst, or a CONNECT to a bare
// IP) the SNI is the name the client intends: we govern on it, and upstream TLS
// verifies the origin cert against that same name, so a spoofed SNI aimed at a
// mismatched IP fails the handshake rather than earning a wrong-destination allow.
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
	sni := tlsConn.ConnectionState().ServerName
	governHost, denyMismatch, refuse := bindTLSHost(authority, sni)
	if refuse {
		// The client CONNECTed a hostname but asked (via SNI) for a different
		// one — governing would split the audit trail from the real destination.
		// Record it rather than dropping the connection silently.
		d.Rec.Add(http.MethodConnect, authority, "/", "deny", "guard", "sni_mismatch", "", true, 0)
		tlsConn.Close()
		return nil
	}
	transport := &http.Transport{
		DialContext:     dialTo(dialAddr),
		TLSClientConfig: &tls.Config{ServerName: sni},
	}
	d.serve(tlsConn, "https", governHost, denyMismatch, transport)
	return nil
}

// bindTLSHost derives the host to govern on from the trusted dial authority and
// the client-presented SNI. It returns that host, whether an inner-Host mismatch
// should be refused, and whether the whole connection must be refused (a
// hostname authority with a disagreeing SNI).
func bindTLSHost(authority, sni string) (governHost string, denyMismatch, refuse bool) {
	if net.ParseIP(authority) == nil {
		// Dialed by name: the authority is the trusted destination; a present SNI
		// must agree with it, and the inner Host must too.
		if sni != "" && !strings.EqualFold(sni, authority) {
			return "", false, true
		}
		return authority, true, false
	}
	// Dialed by IP (transparent original-dst / CONNECT to a literal IP): the SNI
	// names the destination. Govern on it (upstream cert verification backstops
	// an SNI/IP mismatch). SNI-less TLS falls back to the IP with no inner-Host
	// check, since there is no name to reconcile against.
	if sni != "" {
		return sni, true, false
	}
	return authority, false, false
}

// ServePlain governs cleartext HTTP arriving on a raw connection. When dialAddr
// is a hostname the policy host is bound to it (inner-Host mismatch refused);
// when it is an IP literal (transparent original-dst) there is no trusted name
// to bind to, so we govern on the request's own Host header (best effort — a
// cleartext transparent flow has no cert to reconcile the name against).
func (d Deps) ServePlain(conn net.Conn, dialAddr string) {
	authority := StripPort(dialAddr)
	transport := &http.Transport{DialContext: dialTo(dialAddr)}
	if net.ParseIP(authority) == nil {
		d.serve(conn, "http", authority, true, transport)
		return
	}
	d.serve(conn, "http", "", false, transport)
}

// Decide evaluates OPA for one request, applying the fail-closed-with-essential
// posture when OPA can't be reached.
//
// The rate-limit ceiling is checked FIRST, before any OPA call: if a limiter is
// configured and this host is over its per-window ceiling, the request is
// short-circuited to a deny (429, reason "rate_limited"). This runs entirely in
// memory, so a runaway loop is cut off cheaply without loading OPA, and — because
// it keys on host — it works in no-inspect mode too. A nil limiter skips this
// block entirely, preserving the exact prior behavior.
//
// The default-deny allowlist is checked SECOND, after the limiter but before
// OPA, and only when a mode is configured. A novel host (neither allowlisted nor
// essential) is denied outright in enforce mode (403, reason "not_allowlisted")
// without calling OPA; in observe mode it proceeds to OPA and, if OPA allows it,
// the returned decision's Reason is overwritten to "novel_host_observed" so the
// operator sees what enforcement WOULD block. An off/empty mode skips this block
// entirely, preserving the exact prior behavior.
func (d Deps) Decide(method, host, path, body string, headers map[string]string) *policy.Decision {
	if d.Limiter != nil && !d.Limiter.Allow(host, time.Now()) {
		return &policy.Decision{Allowed: false, HTTPStatus: http.StatusTooManyRequests, PolicyID: "guard", Reason: "rate_limited", Enforced: true}
	}
	novel := false
	switch d.Allowlist.Mode {
	case "", AllowlistOff:
		// No allowlist gating: today's implicit allow-with-denies posture.
	default:
		if !d.Allowlist.Hosts.Has(host) && !d.Essential.Has(host) {
			// Neither explicitly allowlisted nor essential → a novel host.
			if d.Allowlist.Mode == AllowlistEnforce {
				return &policy.Decision{Allowed: false, HTTPStatus: http.StatusForbidden, PolicyID: "guard", Reason: "not_allowlisted", Enforced: true}
			}
			// Observe mode: let OPA rule on it, but remember to flag it below.
			novel = true
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dec, err := d.Pol.Eval(ctx, method, host, path, body, headers)
	if err == nil {
		// In observe mode, a novel host that OPA allowed is flagged so the audit
		// shows what enforce mode WOULD have blocked. If OPA itself denied it, keep
		// OPA's reason — the operator already sees the deny.
		if novel && dec.Allowed {
			dec.Reason = "novel_host_observed"
		}
		return dec
	}
	if d.Essential.Has(host) {
		return &policy.Decision{Allowed: true, HTTPStatus: http.StatusOK, Reason: "opa_unavailable_essential", Enforced: true}
	}
	return &policy.Decision{Allowed: false, HTTPStatus: http.StatusServiceUnavailable, PolicyID: "guard", Reason: "policy_unavailable", Enforced: true}
}

// serve governs every request on conn. governHost is the trusted destination
// host to key policy and audit on (from a hostname CONNECT target or a validated
// SNI); when denyMismatch is set, a request whose agent-controlled inner Host
// disagrees is refused rather than evaluated, so a spoofed Host can't earn an
// allow to the wrong place or split the audit trail. governHost may be "" only
// when there is no trusted name to bind to (cleartext transparent flow to a bare
// IP), in which case we fall back to the request's own Host header.
func (d Deps) serve(conn net.Conn, scheme, governHost string, denyMismatch bool, transport *http.Transport) {
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
		host := governHost
		if host == "" {
			host = StripPort(r.Host)
		} else if denyMismatch && !strings.EqualFold(StripPort(r.Host), host) {
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
		// Pass dec.Reason on allows too (it's "" for a normal allow, but carries the
		// "novel_host_observed" marker in observe mode) so observe-mode markers
		// reach the audit / webhook / CP without changing normal allow rows.
		d.Rec.Add(r.Method, host, r.URL.Path, "allow", "", dec.Reason, dec.Redactions, dec.Enforced, latency)
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
