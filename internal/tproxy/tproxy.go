package tproxy

import (
	"context"
	"net"
	"net/netip"

	"github.com/aarvion-ai/aarvion-guard/internal/ca"
	"github.com/aarvion-ai/aarvion-guard/internal/decisions"
	"github.com/aarvion-ai/aarvion-guard/internal/mitm"
	"github.com/aarvion-ai/aarvion-guard/internal/policy"
	"github.com/aarvion-ai/aarvion-guard/internal/ratelimit"
)

// Server is the transparent interception front end. The kernel redirects the
// governed identity's TCP 80/443 here; each connection carries its original
// destination, which we recover and govern via the shared MITM core.
type Server struct {
	addr    string
	deps    mitm.Deps
	origDst func(net.Conn) (netip.AddrPort, error)
}

func New(addr string, c *ca.CA, pol *policy.Client, rec *decisions.Recorder, essential []string, origDst func(net.Conn) (netip.AddrPort, error), limiter *ratelimit.Limiter, allowlist mitm.Allowlist) *Server {
	return &Server{
		addr:    addr,
		deps:    mitm.Deps{CA: c, Pol: pol, Rec: rec, Essential: mitm.Essentials(essential), Limiter: limiter, Allowlist: allowlist},
		origDst: origDst,
	}
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
	if dst.Port() == 443 {
		_ = s.deps.ServeTLS(conn, dst.String())
		return
	}
	s.deps.ServePlain(conn, dst.String())
}
