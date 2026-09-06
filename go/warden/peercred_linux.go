//go:build linux

package warden

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// PeerCred is the kernel's word on who is at the other end of a Unix socket:
// the connecting process's pid and uid, set at connect time and unforgeable by
// userspace. The warden trusts this, not anything the caller sends.
type PeerCred struct {
	PID uint32
	UID uint32
}

// ReadPeerCred reads SO_PEERCRED from a Unix connection.
func ReadPeerCred(c net.Conn) (PeerCred, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return PeerCred{}, errors.New("warden: not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return PeerCred{}, err
	}
	var ucred *unix.Ucred
	var innerErr error
	if err := raw.Control(func(fd uintptr) {
		ucred, innerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return PeerCred{}, err
	}
	if innerErr != nil {
		return PeerCred{}, innerErr
	}
	return PeerCred{PID: uint32(ucred.Pid), UID: ucred.Uid}, nil
}
