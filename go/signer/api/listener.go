// Package api exposes the signer over two narrow Unix sockets. The owner
// socket can mint capabilities. The daemon socket cannot. This split is the
// local privilege boundary.
package api

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// Listen creates a Unix socket with an exact mode and owner. It replaces a
// stale socket left by an unclean shutdown.
//
// The socket is created under a temporary name, given its mode and owner,
// and then renamed into place. A listening socket with wide permissions never
// exists, not even briefly. A uid or gid of -1 keeps the current owner.
func Listen(path string, mode os.FileMode, uid, gid int) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	// If nothing listens on a leftover socket file, remove it. Otherwise bind
	// fails after every crash.
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
		// The socket was renamed. Stop Go from unlinking the old name.
		ul.SetUnlinkOnClose(false)
	}
	return &namedListener{Listener: ln, path: path}, nil
}

// ensureOwnership makes sure that the socket has the requested uid and gid.
// It checks first and calls chown only when the owner is wrong.
//
// The order matters. In the supported deployment each socket lives in a
// setgid directory, so the kernel assigns the right group and no chown is
// needed. The signer's systemd unit denies @privileged, and a denied syscall
// under seccomp kills the process with SIGSYS instead of returning EPERM.
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

	// The owner is wrong, so this is not the supported deployment. Try to
	// fix it. If seccomp kills the process here, that is the right outcome.
	// A socket with the wrong owner would remove the privilege boundary.
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

// PeerFilter closes connections from unexpected UIDs at once. Socket file
// permissions already enforce this. The peer-credential check is a second,
// independent mechanism.
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
			// A platform without peer credentials relies on file permissions.
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
