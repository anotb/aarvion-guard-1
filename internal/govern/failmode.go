package govern

import (
	"net/http"
	"strings"

	"github.com/aarvion-ai/aarvion-guard/internal/policy"
)

// Per-surface fail postures, selectable via config. The default (empty string)
// is FailEssential: closed, except a read to an essential host. Never fail open
// by default.
const (
	FailClosed    = "closed"    // always deny
	FailOpen      = "open"      // always allow (opt-in, dangerous)
	FailEssential = "essential" // allow only a read to an essential host, else deny
)

// failMode produces the Decision to use when OPA can't be reached. It is the
// capability fail-mode: config-driven per surface, defaulting to fail-closed
// with an essential-host read as the only escape hatch.
func (s *Server) failMode(req *Request) *policy.Decision {
	mode := s.cfg.FailMode[req.Ctx.Surface]
	switch mode {
	case FailOpen:
		return allow("policy_unavailable_open")
	case FailClosed:
		return deny()
	}
	// Default / FailEssential: only a read to an essential host survives.
	h := req.Attributes.Request.HTTP
	if isRead(h.Method) && s.cfg.Essential.Has(h.Host) {
		return allow("policy_unavailable_essential")
	}
	return deny()
}

// isRead reports whether the HTTP method is a safe read, so an OPA outage can
// still let a read through to an essential host without opening writes.
func isRead(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func deny() *policy.Decision {
	return &policy.Decision{
		Allowed:    false,
		HTTPStatus: http.StatusServiceUnavailable,
		PolicyID:   "guard",
		Reason:     "policy_unavailable",
		Enforced:   true,
	}
}

func allow(reason string) *policy.Decision {
	return &policy.Decision{
		Allowed:    true,
		HTTPStatus: http.StatusOK,
		Reason:     reason,
		Enforced:   true,
	}
}
