package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aarvion-ai/aarvion-guard/internal/decisions"
	"github.com/aarvion-ai/aarvion-guard/internal/policy"
)

// Server is the B0 forward proxy: OpenClaw points HTTP(S)_PROXY at it. HTTPS is
// governed at the host level via CONNECT; plain HTTP sees full method/path.
// Transparent, body-level interception is B1.
type Server struct {
	addr      string
	pol       *policy.Client
	rec       *decisions.Recorder
	essential map[string]bool
	transport *http.Transport
}

func New(addr string, pol *policy.Client, rec *decisions.Recorder, essential []string) *Server {
	set := map[string]bool{}
	for _, h := range essential {
		set[strings.ToLower(h)] = true
	}
	return &Server{
		addr:      addr,
		pol:       pol,
		rec:       rec,
		essential: set,
		transport: &http.Transport{Proxy: nil},
	}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{
		Addr:    s.addr,
		Handler: http.HandlerFunc(s.handle),
	}
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

// decide evaluates OPA, applying the fail-closed-with-essential posture when
// OPA can't be reached.
func (s *Server) decide(method, host, path string) *policy.Decision {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d, err := s.pol.Eval(ctx, method, host, path, map[string]string{})
	if err == nil {
		return d
	}
	if s.essential[strings.ToLower(host)] {
		return &policy.Decision{Allowed: true, HTTPStatus: http.StatusOK, Reason: "opa_unavailable_essential", Enforced: true}
	}
	return &policy.Decision{Allowed: false, HTTPStatus: http.StatusServiceUnavailable, PolicyID: "guard", Reason: "policy_unavailable", Enforced: true}
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host := stripPort(r.Host)
	d := s.decide(http.MethodConnect, host, "/")
	latency := int(time.Since(start).Milliseconds())

	if !d.Allowed {
		s.rec.Add(http.MethodConnect, host, "/", "deny", d.PolicyID, d.Reason, "", d.Enforced, latency)
		http.Error(w, d.Reason, d.HTTPStatus)
		return
	}
	s.rec.Add(http.MethodConnect, host, "/", "allow", "", "", d.Redactions, d.Enforced, latency)

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
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
	host := stripPort(r.Host)
	d := s.decide(r.Method, host, r.URL.Path)
	latency := int(time.Since(start).Milliseconds())

	if !d.Allowed {
		s.rec.Add(r.Method, host, r.URL.Path, "deny", d.PolicyID, d.Reason, "", d.Enforced, latency)
		http.Error(w, d.Reason, d.HTTPStatus)
		return
	}
	s.rec.Add(r.Method, host, r.URL.Path, "allow", "", "", d.Redactions, d.Enforced, latency)

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

func stripPort(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}
