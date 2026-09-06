package warden

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock is a settable wall clock. The monotonic deadline is separate and
// always real, which is the whole point of the clock-jump guard.
type fakeClock struct {
	mu   sync.Mutex
	unix int64
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Unix(c.unix, 0)
}
func (c *fakeClock) set(t int64) { c.mu.Lock(); c.unix = t; c.mu.Unlock() }
func (c *fakeClock) add(d int64) { c.mu.Lock(); c.unix += d; c.mu.Unlock() }

// fakeSigner is an in-memory GrantSource.
type fakeSigner struct {
	mu      sync.Mutex
	grants  map[string]GrantInfo
	down    bool
	unknown map[string]bool
}

func newFakeSigner() *fakeSigner {
	return &fakeSigner{grants: map[string]GrantInfo{}, unknown: map[string]bool{}}
}

func (f *fakeSigner) put(g GrantInfo) { f.mu.Lock(); f.grants[g.ID] = g; f.mu.Unlock() }

func (f *fakeSigner) Grant(_ context.Context, id string) (GrantInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return GrantInfo{}, fmt.Errorf("signer down")
	}
	if f.unknown[id] {
		return GrantInfo{}, ErrGrantUnknown
	}
	g, ok := f.grants[id]
	if !ok {
		return GrantInfo{}, ErrGrantUnknown
	}
	return g, nil
}

func (f *fakeSigner) Ping(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return fmt.Errorf("signer down")
	}
	return nil
}

// fakeSystemd emulates just enough of the service manager: it creates the
// cgroup directories systemd would create, places the pid, and marks the slice
// populated. Termination flips it back.
type fakeSystemd struct {
	mu       sync.Mutex
	cgroupFS string
	procFS   string
	calls    []string
}

func (s *fakeSystemd) record(f string, a ...any) {
	s.mu.Lock()
	s.calls = append(s.calls, fmt.Sprintf(f, a...))
	s.mu.Unlock()
}

func (s *fakeSystemd) StartSlice(_ context.Context, name, _ string) error {
	s.record("slice %s", name)
	dir := filepath.Join(s.cgroupFS, "grantd.slice", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	writeIfMissing(filepath.Join(dir, "cgroup.events"), "populated 0\n")
	writeIfMissing(filepath.Join(dir, "cgroup.kill"), "0\n")
	writeIfMissing(filepath.Join(dir, "cgroup.procs"), "")
	return nil
}

func (s *fakeSystemd) StartScope(_ context.Context, name, slice, _ string, pid int, _, _ time.Duration) error {
	s.record("scope %s in %s pid %d", name, slice, pid)
	sliceDir := filepath.Join(s.cgroupFS, "grantd.slice", slice)
	scopeDir := filepath.Join(sliceDir, name)
	if err := os.MkdirAll(scopeDir, 0o755); err != nil {
		return err
	}
	writeFile(filepath.Join(scopeDir, "cgroup.procs"), strconv.Itoa(pid)+"\n")
	writeFile(filepath.Join(scopeDir, "cgroup.kill"), "0\n")
	writeFile(filepath.Join(sliceDir, "cgroup.events"), "populated 1\n")
	writeFile(filepath.Join(sliceDir, "cgroup.kill"), "0\n")
	// The kernel moves the process; reflect that in its /proc entry.
	want := "/grantd.slice/" + slice + "/" + name
	setProcCgroup(s.procFS, pid, want)
	return nil
}

func (s *fakeSystemd) StopUnit(_ context.Context, name string) error {
	s.record("stop %s", name)
	if strings.HasSuffix(name, ".slice") {
		_ = os.RemoveAll(filepath.Join(s.cgroupFS, "grantd.slice", name))
	}
	return nil
}

// --- synthetic /proc and /sys/fs/cgroup ---

func writeFile(path, content string) {
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	_ = os.WriteFile(path, []byte(content), 0o644)
}

func writeIfMissing(path, content string) {
	if _, err := os.Stat(path); err == nil {
		return
	}
	writeFile(path, content)
}

// writeProc creates a synthetic /proc/<pid> that ReadProc can parse.
func writeProc(procFS string, pid, ppid, uid int, start uint64, exe, cgroup string) {
	dir := filepath.Join(procFS, strconv.Itoa(pid))
	_ = os.MkdirAll(dir, 0o755)
	// stat: "pid (comm) state ppid ..." with starttime at field 22 (index 19
	// after the ')').
	fields := make([]string, 22)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0] = "S"
	fields[1] = strconv.Itoa(ppid)
	fields[19] = strconv.FormatUint(start, 10)
	writeFile(filepath.Join(dir, "stat"),
		fmt.Sprintf("%d (%s) %s\n", pid, exe, strings.Join(fields, " ")))
	writeFile(filepath.Join(dir, "status"),
		fmt.Sprintf("Name:\t%s\nUid:\t%d\t%d\t%d\t%d\n", exe, uid, uid, uid, uid))
	setProcCgroup(procFS, pid, cgroup)
	// exe symlink whose basename is the process name.
	link := filepath.Join(dir, "exe")
	_ = os.Remove(link)
	_ = os.Symlink("/usr/sbin/"+exe, link)
}

func setProcCgroup(procFS string, pid int, cgroup string) {
	writeFile(filepath.Join(procFS, strconv.Itoa(pid), "cgroup"), "0::"+cgroup+"\n")
}

func markUnpopulated(cgroupFS, sliceUnit string) {
	dir := filepath.Join(cgroupFS, "grantd.slice", sliceUnit)
	writeFile(filepath.Join(dir, "cgroup.events"), "populated 0\n")
	writeFile(filepath.Join(dir, "cgroup.procs"), "")
	// empty the scopes too
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() {
			writeFile(filepath.Join(dir, e.Name(), "cgroup.procs"), "")
		}
	}
}

// testWarden wires a warden to synthetic filesystems and a fake clock.
type testWarden struct {
	w     *Warden
	sig   *fakeSigner
	sd    *fakeSystemd
	clock *fakeClock
	proc  string
	cg    string
}

func newTestWarden(t *testing.T, sshUser string, admitUID int) *testWarden {
	t.Helper()
	proc := t.TempDir()
	cg := t.TempDir()
	clock := &fakeClock{unix: 1_000_000}
	sig := newFakeSigner()
	sd := &fakeSystemd{cgroupFS: cg, procFS: proc}

	// Point the package globals at the synthetic trees for the test's duration.
	oldProc, oldCg := ProcFS, CgroupFS
	ProcFS, CgroupFS = proc, cg
	t.Cleanup(func() { ProcFS, CgroupFS = oldProc, oldCg })

	w := New(Config{
		SSHUser: sshUser, Signer: sig, Systemd: sd,
		StateFile: filepath.Join(t.TempDir(), "state.json"),
		AdmitUID:  admitUID, Now: clock.now,
		TermGrace: 0, KillWait: 0, Poll: time.Second, PendingTTL: time.Minute,
	})
	return &testWarden{w: w, sig: sig, sd: sd, clock: clock, proc: proc, cg: cg}
}

// connection sets up an sshd process and a caller child of it, returning both.
func (tw *testWarden) connection(t *testing.T, sshdPID, callerPID, callerUID int) (sshd, caller Proc) {
	t.Helper()
	writeProc(tw.proc, sshdPID, 1, 0, 111, "sshd", "/grantd-preattach")
	writeProc(tw.proc, callerPID, sshdPID, callerUID, 222, "grant-admit", "/grantd-preattach")
	s, err := ReadProc(sshdPID)
	if err != nil {
		t.Fatalf("read sshd proc: %v", err)
	}
	c, err := ReadProc(callerPID)
	if err != nil {
		t.Fatalf("read caller proc: %v", err)
	}
	return s, c
}
