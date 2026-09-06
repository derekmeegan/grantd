package warden

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// CgroupFS is the mount point of the unified cgroup hierarchy.
var CgroupFS = "/sys/fs/cgroup"

// Cgroup is one directory in the unified hierarchy, addressed by its path
// relative to the mount point, e.g. /grantd.slice/grantd-g_abc.slice.
type Cgroup struct {
	Path string
}

func (c Cgroup) dir() string { return filepath.Join(CgroupFS, c.Path) }

// Exists reports whether the cgroup directory is present.
func (c Cgroup) Exists() bool {
	st, err := os.Stat(c.dir())
	return err == nil && st.IsDir()
}

// Procs lists every pid in the cgroup and all of its descendants. A visitor
// cannot create sub-cgroups (the tree is root-owned and not delegated), but
// the walk is recursive anyway so nothing hides in one.
func (c Cgroup) Procs() ([]int, error) {
	var pids []int
	seen := map[int]bool{}
	err := filepath.WalkDir(c.dir(), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if !d.IsDir() {
			return nil
		}
		f, err := os.Open(filepath.Join(path, "cgroup.procs"))
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			pid, err := strconv.Atoi(strings.TrimSpace(sc.Text()))
			if err != nil || seen[pid] {
				continue
			}
			seen[pid] = true
			pids = append(pids, pid)
		}
		return nil
	})
	sort.Ints(pids)
	return pids, err
}

// Populated reports whether any process is alive anywhere in the subtree,
// from the kernel's cgroup.events rather than from a process listing, so a
// task that is still exiting counts.
func (c Cgroup) Populated() (bool, error) {
	b, err := os.ReadFile(filepath.Join(c.dir(), "cgroup.events"))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "populated ") {
			return strings.TrimSpace(line[len("populated "):]) == "1", nil
		}
	}
	return false, fmt.Errorf("warden: %s/cgroup.events has no populated line", c.Path)
}

// Signal sends sig to every process in the subtree. It is the polite step:
// a shell gets SIGTERM and a chance to exit. Processes that fork between the
// listing and the signal are caught by Kill, which is atomic.
func (c Cgroup) Signal(sig syscall.Signal) (int, error) {
	pids, err := c.Procs()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, pid := range pids {
		if err := syscall.Kill(pid, sig); err == nil {
			n++
		}
	}
	return n, nil
}

// Kill writes cgroup.kill, which makes the kernel SIGKILL every task in the
// subtree in one operation, including tasks forked while it runs. It needs
// Linux 5.14. Tasks in uninterruptible sleep die when they leave it.
func (c Cgroup) Kill() error {
	err := os.WriteFile(filepath.Join(c.dir(), "cgroup.kill"), []byte("1\n"), 0)
	if err != nil && os.IsNotExist(err) {
		if !c.Exists() {
			// Already gone: nothing to kill.
			return nil
		}
		return errors.New("warden: cgroup.kill is missing; the kernel is older than 5.14")
	}
	return err
}

// WaitEmpty polls until nothing is alive in the subtree, or the timeout
// passes. It returns the pids still present at the end.
func (c Cgroup) WaitEmpty(timeout time.Duration, tick time.Duration) ([]int, error) {
	deadline := time.Now().Add(timeout)
	for {
		populated, err := c.Populated()
		if err != nil {
			return nil, err
		}
		if !populated {
			return nil, nil
		}
		if time.Now().After(deadline) {
			pids, _ := c.Procs()
			return pids, nil
		}
		time.Sleep(tick)
	}
}

// Children lists the immediate sub-cgroups.
func (c Cgroup) Children() ([]Cgroup, error) {
	entries, err := os.ReadDir(c.dir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Cgroup
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, Cgroup{Path: filepath.Join(c.Path, e.Name())})
		}
	}
	return out, nil
}

// Name is the last path element, which for a cgroup systemd manages is the
// unit name.
func (c Cgroup) Name() string { return filepath.Base(c.Path) }

// HasCgroupKill reports whether this kernel offers cgroup.kill, checked on a
// cgroup that always exists once systemd is running.
func HasCgroupKill() bool {
	_, err := os.Stat(filepath.Join(CgroupFS, "init.scope", "cgroup.kill"))
	return err == nil
}

// IsUnified reports whether the cgroup mount is the v2 hierarchy.
func IsUnified() bool {
	_, err := os.Stat(filepath.Join(CgroupFS, "cgroup.controllers"))
	return err == nil
}
