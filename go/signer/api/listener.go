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
	"syscall"
)

// Listen creates a Unix socket with an exact mode and owner, replacing any
// stale socket left behind by an unclean shutdown.
//
// The socket is created under a temporary name, given its mode and ownership,
// and only then renamed into place. There is therefore no window in which a
// listening socket exists with permissions wider than intended — which matters,
// because file permissions are the mechanism that keeps the daemon off the
// owner socket.
//
// uid and gid of -1 leave the current ownership alone.
func Listen(path string, mode os.FileMode, uid, gid int) (net.Listener, error) {
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
	if err := ensureOwnership(tmp, uid, gid); err != nil {
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

// ensureOwnership makes sure the socket has the requested uid/gid, preferring
// to verify rather than to change.
//
// The ordering matters more than it looks. The supported deployment puts each
// socket in a setgid directory, so the kernel already assigns the right group at
// creation and no chown is needed. Checking first means the common path never
// calls chown at all — which lets the signer's systemd unit deny @privileged
// outright.
//
// That is not a cosmetic difference. A denied syscall under seccomp raises
// SIGSYS and kills the process; it does not return EPERM. So a "try chown, fall
// back on failure" design does not degrade gracefully under a syscall filter,
// it dies. Checking first avoids the syscall instead of handling its failure.
func ensureOwnership(path string, uid, gid int) error {
	if uid < 0 && gid < 0 {
		return nil
	}
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return fmt.Errorf("api: stat %s: %w", path, err)
	}
	uidOK := uid < 0 || int(st.Uid) == uid
	gidOK := gid < 0 || int(st.Gid) == gid
	if uidOK && gidOK {
		return nil
	}

	// Ownership is wrong, so the deployment is not the supported one. Try to
	// correct it; if the syscall is unavailable this process is about to die,
	// which is the right outcome — serving a socket with the wrong owner would
	// silently remove the boundary between the daemon and the owner API.
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("api: %s has owner %d:%d, want %d:%d, and chown failed "+
			"(is its directory setgid to that group?): %w", path, st.Uid, st.Gid, uid, gid, err)
	}
	return nil
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
