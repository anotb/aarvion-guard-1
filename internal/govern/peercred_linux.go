//go:build linux

package govern

import (
	"fmt"
	"net"
	"syscall"
)

// peerUID reads the connecting process's effective uid from the kernel via
// SO_PEERCRED. The value is set by the kernel at connect time and cannot be
// forged by the peer, so it is a trustworthy identity for a local socket.
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
		cred, e := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if e != nil {
			innerErr = e
			return
		}
		uid = cred.Uid
	})
	if err != nil {
		return 0, err
	}
	return uid, innerErr
}
