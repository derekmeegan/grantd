// Package api exposes the signer over two deliberately narrow Unix sockets.
//
// The split is the local privilege boundary. The owner socket can mint
// capabilities; the daemon socket cannot. A remote code execution bug in the
// network-facing daemon therefore does not hand the attacker an API that
// creates grants — the worst it can do is replay envelopes the signer would
// have rejected anyway.
package api

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// Listen creates a Unix socket with an exact mode, replacing any stale socket
// left behind by an unclean shutdown.
//
// The socket is created inside a temporary name and renamed into place so that
// there is no window in which it exists with the wrong permissions.
func Listen(path string, mode os.FileMode) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	// A leftover socket file is not a lock: if nothing is listening, it is
	// stale and must be removed, otherwise bind fails forever after a crash.
	if _, err := os.Stat(path); err == nil {
		if c, derr := net.Dial("unix", path); derr == nil {
			c.Close()
			return nil, fmt.Errorf("api: %s is already in use by a running signer", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}

	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	ln, err := net.Listen("unix", tmp)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		ln.Close()
		_ = os.Remove(tmp)
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		ln.Close()
		_ = os.Remove(tmp)
		return nil, err
	}
	if ul, ok := ln.(*net.UnixListener); ok {
		// We renamed the socket; Go would otherwise unlink the old name.
		ul.SetUnlinkOnClose(false)
	}
	return &namedListener{Listener: ln, path: path}, nil
}

type namedListener struct {
	net.Listener
	path string
}

func (l *namedListener) Close() error {
	err := l.Listener.Close()
	_ = os.Remove(l.path)
	return err
}

// PeerFilter wraps a listener so that connections from unexpected UIDs are
// closed immediately.
//
// Socket file permissions already enforce this. The peer-credential check is a
// second, independent mechanism, so that a misconfigured mode or an
// umask surprise during installation does not silently widen access.
type PeerFilter struct {
	net.Listener
	AllowedUIDs []uint32
	OnReject    func(uid uint32, err error)
}

func (p *PeerFilter) Accept() (net.Conn, error) {
	for {
		c, err := p.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uid, err := peerUID(c)
		if err != nil {
			// Platforms without peer credentials fall back to file permissions.
			if err == errPeerCredUnsupported {
				return c, nil
			}
			c.Close()
			if p.OnReject != nil {
				p.OnReject(0, err)
			}
			continue
		}
		if p.allowed(uid) {
			return c, nil
		}
		c.Close()
		if p.OnReject != nil {
			p.OnReject(uid, fmt.Errorf("uid %d is not permitted on this socket", uid))
		}
	}
}

func (p *PeerFilter) allowed(uid uint32) bool {
	if len(p.AllowedUIDs) == 0 {
		return true
	}
	for _, a := range p.AllowedUIDs {
		if a == uid {
			return true
		}
	}
	return false
}
