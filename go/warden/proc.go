// Package warden bounds how long a visitor may run.
//
// A certificate's expiry stops new connections; it does nothing to a session
// already open. The warden closes that gap with the kernel's own process
// accounting rather than by guessing from logs: every visitor connection is
// placed in a root-owned cgroup before the visitor's shell starts, and at the
// grant's deadline, or when the grant is revoked, that cgroup is emptied.
//
// It holds no keys. The signer tells it, over a root-only socket, when a
// grant ends. sshd tells it, through an AuthorizedPrincipalsCommand and a PAM
// session hook, which process belongs to which certificate. Nothing the
// visitor sends is consulted.
package warden

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Proc is what the warden needs to know about a process to trust it: who its
// parent is, whose it is, and when it started. The start time makes a pid
// mean one process: a recycled pid has a different one.
type Proc struct {
	PID       int
	PPID      int
	UID       int
	StartTime uint64 // clock ticks since boot, from /proc/PID/stat
	Exe       string // basename of the executable, "" if unreadable
	Cgroup    string // unified-hierarchy path, e.g. /user.slice/user-1000.slice/session-3.scope
}

// ProcFS is where the process table is read from. Tests point it elsewhere.
var ProcFS = "/proc"

// ErrNoProcess reports a pid with no live process.
var ErrNoProcess = errors.New("warden: no such process")

// ReadProc reads a process's identity from /proc.
func ReadProc(pid int) (Proc, error) {
	p := Proc{PID: pid}
	dir := filepath.Join(ProcFS, strconv.Itoa(pid))

	stat, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		if os.IsNotExist(err) {
			return p, ErrNoProcess
		}
		return p, err
	}
	// The command name is in parentheses and may itself contain spaces or
	// parentheses. Everything after the last ')' is space separated.
	i := strings.LastIndexByte(string(stat), ')')
	if i < 0 {
		return p, fmt.Errorf("warden: malformed %s/stat", dir)
	}
	fields := strings.Fields(string(stat[i+1:]))
	// fields[0] is state (field 3), so field N is fields[N-3].
	if len(fields) < 20 {
		return p, fmt.Errorf("warden: short %s/stat", dir)
	}
	if p.PPID, err = strconv.Atoi(fields[1]); err != nil {
		return p, fmt.Errorf("warden: ppid in %s/stat: %w", dir, err)
	}
	if p.StartTime, err = strconv.ParseUint(fields[19], 10, 64); err != nil {
		return p, fmt.Errorf("warden: starttime in %s/stat: %w", dir, err)
	}

	f, err := os.Open(filepath.Join(dir, "status"))
	if err != nil {
		return p, err
	}
	defer f.Close()
	p.UID = -1
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Uid:") {
			parts := strings.Fields(line[4:])
			if len(parts) > 0 {
				p.UID, _ = strconv.Atoi(parts[0])
			}
		}
	}
	if p.UID < 0 {
		return p, fmt.Errorf("warden: no Uid in %s/status", dir)
	}

	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		p.Exe = filepath.Base(strings.TrimSuffix(exe, " (deleted)"))
	}
	p.Cgroup, _ = readCgroup(filepath.Join(dir, "cgroup"))
	return p, nil
}

// readCgroup returns the unified-hierarchy path from a /proc/PID/cgroup file.
// On cgroup v2 there is exactly one line, "0::/path".
func readCgroup(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "0::") {
			return strings.TrimSpace(line[3:]), nil
		}
	}
	return "", errors.New("warden: no cgroup v2 entry")
}

// SameProcess reports whether a process read now is the one read earlier: the
// same pid, started at the same tick.
func (p Proc) SameProcess(other Proc) bool {
	return p.PID == other.PID && p.StartTime == other.StartTime
}

// IsSSHD reports whether the process looks like an OpenSSH server process.
// OpenSSH 9.8 split the per-connection process into sshd-session, so both
// names count. This is a sanity check on top of the parent relationship, not
// the authority for anything.
func (p Proc) IsSSHD() bool {
	return p.Exe == "sshd" || p.Exe == "sshd-session"
}
