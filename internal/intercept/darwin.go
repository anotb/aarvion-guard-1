//go:build darwin

package intercept

import (
	"net"
	"net/netip"
)

// macOS cannot intercept its own local egress with pf alone (pf's rdr covers
// forwarded traffic, not locally-originated). Bypass-proof transparent mode on
// macOS requires a NETransparentProxyProvider system extension — a separate,
// signed track. Until that ships, the guard runs in forward-proxy mode here.
func New() Backend { return unsupported{} }

type unsupported struct{}

func (unsupported) Install(Params) error { return ErrUnsupported }
func (unsupported) Remove() error        { return nil }
func (unsupported) Name() string         { return "unsupported(macos)" }

func originalDst(net.Conn) (netip.AddrPort, error) {
	return netip.AddrPort{}, ErrUnsupported
}
