//go:build linux

package api

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

var errPeerCredUnsupported = errors.New("api: peer credentials unsupported")

// peerUID reads SO_PEERCRED. The kernel sets it at connect time and no
// userspace process can forge it.
func peerUID(c net.Conn) (uint32, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("api: not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var ucred *unix.Ucred
	var innerErr error
	if err := raw.Control(func(fd uintptr) {
		ucred, innerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if innerErr != nil {
		return 0, innerErr
	}
	return ucred.Uid, nil
}
