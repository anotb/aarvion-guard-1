package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aarvion-ai/aarvion-guard/internal/ca"
	"github.com/aarvion-ai/aarvion-guard/internal/decisions"
	"github.com/aarvion-ai/aarvion-guard/internal/mitm"
	"github.com/aarvion-ai/aarvion-guard/internal/policy"
)

// Server is the forward proxy: OpenClaw points HTTP(S)_PROXY at it. HTTPS is
// MITM'd inside the CONNECT tunnel (body-level governance) unless the host is
// on the passthrough list (cert-pinned), in which case it is spliced host-level.
// Plain HTTP is governed directly.
type Server struct {
	addr        string
	deps        mitm.Deps
	passthrough map[string]bool
	inspect     bool
	transport   *http.Transport

	mu      sync.Mutex
	learned map[string]bool
	blocked map[string]bool
}

func New(addr string, authority *ca.CA, pol *policy.Client, rec *decisions.Recorder, essential, passthrough []string, inspect bool) *Server {
	pt := map[string]bool{}
	for _, h := range passthrough {
		pt[strings.ToLower(h)] = true
	}
	return &Server{
		addr:        addr,
		deps:        mitm.Deps{CA: authority, Pol: pol, Rec: rec, Essential: mitm.Essentials(essential)},
		passthrough: pt,
		inspect:     inspect,
		transport:   &http.Transport{Proxy: nil},
		learned:     map[string]bool{},
		blocked:     map[string]bool{},
	}
}

func (s *Server) shouldSplice(host string) bool {
	if !s.inspect || s.passthrough[host] {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.learned[host]
}

// learn records a host whose client rejected the MITM leaf (cert-pinned), so
// future connections to it pass through instead of failing again.
func (s *Server) learn(host string) {
	s.mu.Lock()
	s.learned[host] = true
	s.mu.Unlock()
}

// block marks a governed host that rejected inspection so future connections
// fail closed rather than silently downgrading to a host-level tunnel (which
// would let writes slip past body/path policy).
func (s *Server) block(host string) {
	s.mu.Lock()
	s.blocked[host] = true
	s.mu.Unlock()
}

func (s *Server) isBlocked(host string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.blocked[host]
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{Addr: s.addr, Handler: http.HandlerFunc(s.handle)}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	s.handleHTTP(w, r)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := mitm.StripPort(r.Host)
	if s.isBlocked(host) {
		http.Error(w, "guard: inspection required for "+host, http.StatusForbidden)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	if s.shouldSplice(host) {
		s.splice(w, r, host, hj)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err := s.deps.ServeTLS(client, r.Host); err != nil {
		// A rejected leaf on an essential (LLM) or explicitly allowlisted host
		// falls back to a host-level tunnel so the agent keeps working. Any other
		// host fails closed: silently downgrading a governed host to host-level
		// would let writes bypass body/path policy.
		if s.deps.Essential.Has(host) || s.passthrough[host] {
			s.learn(host)
			fmt.Fprintf(os.Stderr, "[guard] %s rejected inspection (%v); passing it through (essential/allowlisted)\n", host, err)
		} else {
			s.block(host)
			fmt.Fprintf(os.Stderr, "[guard] %s rejected inspection (%v); BLOCKING — add it to passthrough_hosts to allow uninspected\n", host, err)
		}
	}
}

// splice handles a passthrough (cert-pinned) host: host-level allow/deny, then
// a raw byte tunnel with no inspection.
func (s *Server) splice(w http.ResponseWriter, r *http.Request, host string, hj http.Hijacker) {
	start := time.Now()
	d := s.deps.Decide(http.MethodConnect, host, "/", "", nil)
	latency := int(time.Since(start).Milliseconds())
	if !d.Allowed {
		s.deps.Rec.Add(http.MethodConnect, host, "/", "deny", d.PolicyID, d.Reason, "", d.Enforced, latency)
		http.Error(w, d.Reason, d.HTTPStatus)
		return
	}
	s.deps.Rec.Add(http.MethodConnect, host, "/", "allow", "", "", d.Redactions, d.Enforced, latency)
	upstream, err := net.DialTimeout("tcp", r.Host, 15*time.Second)
	if err != nil {
		http.Error(w, "upstream dial failed", http.StatusBadGateway)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go pipe(upstream, client)
	go pipe(client, upstream)
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() {
		http.Error(w, "this endpoint is a forward proxy", http.StatusBadRequest)
		return
	}
	start := time.Now()
	host := mitm.StripPort(r.Host)
	d := s.deps.Decide(r.Method, host, r.URL.Path, mitm.PeekBody(r), mitm.HeaderMap(r))
	latency := int(time.Since(start).Milliseconds())
	if !d.Allowed {
		s.deps.Rec.Add(r.Method, host, r.URL.Path, "deny", d.PolicyID, d.Reason, "", d.Enforced, latency)
		http.Error(w, d.Reason, d.HTTPStatus)
		return
	}
	s.deps.Rec.Add(r.Method, host, r.URL.Path, "allow", "", "", d.Redactions, d.Enforced, latency)

	r.RequestURI = ""
	resp, err := s.transport.RoundTrip(r)
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func pipe(dst, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	_, _ = io.Copy(dst, src)
}
