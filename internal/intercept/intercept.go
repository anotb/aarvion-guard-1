package intercept

import (
	"errors"
	"net"
	"net/netip"
)

// ErrUnsupported is returned by New() on platforms where bypass-proof
// transparent interception is not available (currently macOS, which needs a
// NetworkExtension system extension — a separate track from this binary).
var ErrUnsupported = errors.New("transparent interception is not supported on this platform")

// Params configures the kernel redirect. Identity is a group (gid): OpenClaw
// runs in this group so the firewall matches its egress without changing any
// file ownership (locked decision §12.1). The guard and OPA are NOT in the
// group, so their own traffic is excluded automatically.
type Params struct {
	GID             int
	TransparentPort int
}

// Backend installs and removes the kernel redirect for one platform.
type Backend interface {
	Install(p Params) error
	Remove() error
	Name() string
}

// OriginalDst recovers the destination a redirected connection was aimed at
// before the kernel rewrote it. Implemented per-platform; the transparent
// server is otherwise platform-agnostic.
func OriginalDst(conn net.Conn) (netip.AddrPort, error) {
	return originalDst(conn)
}
