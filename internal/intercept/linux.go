//go:build linux

package intercept

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"syscall"
	"unsafe"
)

const (
	chainName    = "AARVION_GUARD"
	soOriginalDst = 80
	solIP         = 0
	solIPv6       = 41
)

func New() Backend { return &iptablesBackend{} }

type iptablesBackend struct{}

func (b *iptablesBackend) Name() string { return "iptables" }

func (b *iptablesBackend) Install(p Params) error {
	if p.GID <= 0 || p.TransparentPort <= 0 {
		return fmt.Errorf("intercept: GID and TransparentPort are required")
	}
	port := fmt.Sprintf("%d", p.TransparentPort)
	gid := fmt.Sprintf("%d", p.GID)

	for _, ipt := range []struct {
		bin  string
		lo   string
	}{{"iptables", "127.0.0.0/8"}, {"ip6tables", "::1/128"}} {
		mk := func(args ...string) error { return run(ipt.bin, args...) }
		// Fresh chain.
		_ = mk("-t", "nat", "-N", chainName)
		if err := mk("-t", "nat", "-F", chainName); err != nil {
			return err
		}
		// Never redirect loopback or the guard/OPA (they aren't in the group).
		if err := mk("-t", "nat", "-A", chainName, "-o", "lo", "-j", "RETURN"); err != nil {
			return err
		}
		if err := mk("-t", "nat", "-A", chainName, "-d", ipt.lo, "-j", "RETURN"); err != nil {
			return err
		}
		for _, dport := range []string{"80", "443"} {
			if err := mk("-t", "nat", "-A", chainName,
				"-p", "tcp", "-m", "owner", "--gid-owner", gid,
				"--dport", dport, "-j", "REDIRECT", "--to-ports", port); err != nil {
				return err
			}
		}
		// Hook once.
		if run(ipt.bin, "-t", "nat", "-C", "OUTPUT", "-j", chainName) != nil {
			if err := mk("-t", "nat", "-A", "OUTPUT", "-j", chainName); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *iptablesBackend) Remove() error {
	for _, bin := range []string{"iptables", "ip6tables"} {
		_ = run(bin, "-t", "nat", "-D", "OUTPUT", "-j", chainName)
		_ = run(bin, "-t", "nat", "-F", chainName)
		_ = run(bin, "-t", "nat", "-X", chainName)
	}
	return nil
}

func run(bin string, args ...string) error {
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %v: %s", bin, args, err, out)
	}
	return nil
}

func originalDst(conn net.Conn) (netip.AddrPort, error) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("intercept: not a TCP connection")
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}

	var result netip.AddrPort
	var innerErr error
	err = raw.Control(func(fd uintptr) {
		if ap, ok := getsockopt4(fd); ok {
			result = ap
			return
		}
		if ap, ok := getsockopt6(fd); ok {
			result = ap
			return
		}
		innerErr = fmt.Errorf("intercept: SO_ORIGINAL_DST unavailable")
	})
	if err != nil {
		return netip.AddrPort{}, err
	}
	return result, innerErr
}

func getsockopt4(fd uintptr) (netip.AddrPort, bool) {
	var sa syscall.RawSockaddrInet4
	size := uint32(unsafe.Sizeof(sa))
	if err := getsockopt(fd, solIP, soOriginalDst, unsafe.Pointer(&sa), &size); err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), ntohs(sa.Port)), true
}

func getsockopt6(fd uintptr) (netip.AddrPort, bool) {
	var sa syscall.RawSockaddrInet6
	size := uint32(unsafe.Sizeof(sa))
	if err := getsockopt(fd, solIPv6, soOriginalDst, unsafe.Pointer(&sa), &size); err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(netip.AddrFrom16(sa.Addr), ntohs(sa.Port)), true
}

// ntohs reads a network-order uint16 (as the kernel stores sin_port) into host
// order, independent of host endianness.
func ntohs(v uint16) uint16 {
	b := (*[2]byte)(unsafe.Pointer(&v))
	return uint16(b[0])<<8 | uint16(b[1])
}

func getsockopt(fd uintptr, level, name int, val unsafe.Pointer, size *uint32) error {
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT, fd, uintptr(level), uintptr(name),
		uintptr(val), uintptr(unsafe.Pointer(size)), 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}
