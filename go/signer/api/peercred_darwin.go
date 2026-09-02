//go:build darwin

package api

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

var errPeerCredUnsupported = errors.New("api: peer credentials unsupported")

// peerUID reads LOCAL_PEERCRED. This path serves development on macOS only.
func peerUID(c net.Conn) (uint32, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("api: not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var xu *unix.Xucred
	var innerErr error
	if err := raw.Control(func(fd uintptr) {
		xu, innerErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if innerErr != nil {
		return 0, innerErr
	}
	return xu.Uid, nil
}
