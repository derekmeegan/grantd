//go:build !linux

package warden

import (
	"errors"
	"net"
)

// PeerCred is unavailable off Linux. The warden only runs on Linux; this
// keeps the package building for tooling on other platforms.
type PeerCred struct {
	PID uint32
	UID uint32
}

func ReadPeerCred(net.Conn) (PeerCred, error) {
	return PeerCred{}, errors.New("warden: peer credentials are only available on Linux")
}
