//go:build darwin

package govern

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// macOS exposes the peer's credentials via LOCAL_PEERCRED at the SOL_LOCAL
// level, returning a struct xucred. There is no syscall.GetsockoptXucred in the
// standard library, so we read it with a raw getsockopt (mirroring the
// SO_ORIGINAL_DST style in internal/intercept/linux.go) to avoid a new dep.
const (
	solLocal      = 0      // SOL_LOCAL
	localPeerCred = 0x0001 // LOCAL_PEERCRED
	xuMaxGroups   = 16     // NGROUPS
	xucredVersion = 0      // XUCRED_VERSION
	xucredMinSize = 8      // bytes covering Version(4) + UID(4)
)

// xucred mirrors darwin's struct xucred (sys/ucred.h): a version, the peer uid,
// a short group count, then a fixed group array. cr_uid is the field we want.
type xucred struct {
	Version uint32
	UID     uint32
	Ngroups int16
	Groups  [xuMaxGroups]uint32
}

// peerUID reads the connecting process's uid from the kernel via LOCAL_PEERCRED.
// The kernel sets this at connect time, so it cannot be forged by the peer.
func peerUID(conn net.Conn) (uint32, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("govern: not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}

	var uid uint32
	var innerErr error
	err = raw.Control(func(fd uintptr) {
		var xu xucred
		size := uint32(unsafe.Sizeof(xu))
		if e := getsockopt(fd, solLocal, localPeerCred, unsafe.Pointer(&xu), &size); e != nil {
			innerErr = e
			return
		}
		// A short read or version mismatch would leave xu.UID at its zero value
		// (root) and be silently accepted. Require the kernel to have populated at
		// least version+uid, with the expected version.
		if size < xucredMinSize || xu.Version != xucredVersion {
			innerErr = fmt.Errorf("govern: invalid xucred (size=%d version=%d)", size, xu.Version)
			return
		}
		uid = xu.UID
	})
	if err != nil {
		return 0, err
	}
	return uid, innerErr
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
