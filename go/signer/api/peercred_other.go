//go:build !linux && !darwin

package api

import (
	"errors"
	"net"
)

var errPeerCredUnsupported = errors.New("api: peer credentials unsupported")

func peerUID(net.Conn) (uint32, error) { return 0, errPeerCredUnsupported }
