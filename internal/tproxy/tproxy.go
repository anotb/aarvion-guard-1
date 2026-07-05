package tproxy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strings"
	"time"

	"github.com/aarvion-ai/aarvion-guard/internal/ca"
	"github.com/aarvion-ai/aarvion-guard/internal/decisions"
	"github.com/aarvion-ai/aarvion-guard/internal/policy"
)

// Server is the transparent interception front end. The kernel redirects the
// governed identity's TCP 80/443 here; each connection carries its original
// destination, which we recover and govern. 443 is MITM'd with the local CA so
// body-level packs apply; 80 is read directly. Cert-pinned host passthrough is
// a follow-on (needs pre-handshake SNI peek).
type Server struct {
	addr      string
	ca        *ca.CA
	pol       *policy.Client
	rec       *decisions.Recorder
	essential map[string]bool
	origDst   func(net.Conn) (netip.AddrPort, error)
}

func New(addr string, c *ca.CA, pol *policy.Client, rec *decisions.Recorder, essential []string, origDst func(net.Conn) (netip.AddrPort, error)) *Server {
	set := map[string]bool{}
	for _, h := range essential {
		set[strings.ToLower(h)] = true
	}
	return &Server{addr: addr, ca: c, pol: pol, rec: rec, essential: set, origDst: origDst}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	dst, err := s.origDst(conn)
	if err != nil {
		conn.Close()
		return
	}
	switch dst.Port() {
	case 443:
		s.handleTLS(conn, dst)
	default:
		s.handlePlain(conn, dst)
	}
}

func (s *Server) handleTLS(conn net.Conn, dst netip.AddrPort) {
	tlsConn := tls.Server(conn, &tls.Config{
		GetCertificate: s.ca.GetCertificate,
		NextProtos:     []string{"http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", dst.String())
		},
		TLSClientConfig: &tls.Config{ServerName: tlsConn.ConnectionState().ServerName},
	}
	s.serve(tlsConn, "https", transport)
}

func (s *Server) handlePlain(conn net.Conn, dst netip.AddrPort) {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", dst.String())
		},
	}
	s.serve(conn, "http", transport)
}

func (s *Server) serve(conn net.Conn, scheme string, transport *http.Transport) {
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
		host := stripPort(r.Host)
		d := s.decide(r.Method, host, r.URL.Path)
		latency := int(time.Since(start).Milliseconds())
		if !d.Allowed {
			s.rec.Add(r.Method, host, r.URL.Path, "deny", d.PolicyID, d.Reason, "", d.Enforced, latency)
			http.Error(w, d.Reason, d.HTTPStatus)
			return
		}
		s.rec.Add(r.Method, host, r.URL.Path, "allow", "", "", d.Redactions, d.Enforced, latency)
		r.URL.Scheme = scheme
		r.URL.Host = r.Host
		proxy.ServeHTTP(w, r)
	})

	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 20 * time.Second}
	_ = srv.Serve(&oneConnListener{conn: conn})
}

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

func stripPort(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// oneConnListener feeds a single already-accepted connection to http.Server.
// The second Accept returns io.EOF so Serve exits its loop while the connection
// keeps being served in the background.
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
