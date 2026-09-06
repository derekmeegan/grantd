package warden

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"

	"github.com/derekmeegan/grantd/go/internal/protocol"
	"sync"
	"syscall"
	"time"
)

// Config wires a Warden to the machine.
type Config struct {
	// SSHUser is the enrolled account. Only its sessions are admitted.
	SSHUser string
	// Signer answers what a grant's state is. It is the deadline authority.
	Signer GrantSource
	// Systemd creates and stops the units that hold sessions.
	Systemd Systemd
	// Slice is the parent of every per-grant slice, e.g. "grantd.slice".
	// Resource limits for all visitors together live on it.
	Slice string
	// StateFile records sessions so a restart can find them again. It lives
	// on /run: a reboot ends every session anyway.
	StateFile string
	// AdmitUID is the account sshd runs the admission command as.
	AdmitUID int
	Log      *slog.Logger
	Now      func() time.Time

	// TermGrace is how long tasks get after SIGTERM before SIGKILL.
	TermGrace time.Duration
	// KillWait is how long to wait for the group to empty after SIGKILL
	// before reporting the termination incomplete and retrying.
	KillWait time.Duration
	// Poll is how often the signer is asked about every open grant, which
	// bounds how long a revocation takes to reach a running session.
	Poll time.Duration
	// BackstopSlack is added to the remaining lifetime for systemd's own
	// RuntimeMaxSec on each scope, so the two mechanisms do not race in the
	// normal case and systemd still ends the session if the warden is gone.
	BackstopSlack time.Duration
	// PendingTTL bounds the gap between sshd admitting a certificate and the
	// session hook attaching the process. LoginGraceTime is 120s by default.
	PendingTTL time.Duration
}

func (c *Config) defaults() {
	if c.Slice == "" {
		c.Slice = "grantd.slice"
	}
	if c.Log == nil {
		c.Log = slog.Default()
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.TermGrace == 0 {
		c.TermGrace = 5 * time.Second
	}
	if c.KillWait == 0 {
		c.KillWait = 10 * time.Second
	}
	if c.Poll == 0 {
		c.Poll = 2 * time.Second
	}
	if c.BackstopSlack == 0 {
		c.BackstopSlack = 15 * time.Second
	}
	if c.PendingTTL == 0 {
		c.PendingTTL = 3 * time.Minute
	}
}

// State is where a grant is in its life on this host.
type State string

const (
	// Open grants admit new sessions.
	Open State = "open"
	// Closing grants admit nothing; their tasks are being ended.
	Closing State = "closing"
	// Closed grants have no tasks left. They are forgotten shortly after.
	Closed State = "closed"
)

// Session is one SSH connection: the sshd process that owns it and the scope
// it was placed in before the visitor's shell started.
type Session struct {
	PID       int    `json:"pid"`
	StartTime uint64 `json:"start_time"`
	Scope     string `json:"scope"`
	Cgroup    string `json:"cgroup"`
	Since     int64  `json:"since"`
}

// Grant is a certificate's lifetime as seen on this host: one deadline, any
// number of connections, one cgroup subtree that holds them all.
type Grant struct {
	ID       string           `json:"grant_id"`
	Deadline int64            `json:"deadline"`
	State    State            `json:"state"`
	Reason   string           `json:"reason,omitempty"`
	Sessions map[int]*Session `json:"sessions"`
	// Remaining lists pids still alive after SIGKILL, which happens to tasks
	// in uninterruptible sleep. The warden keeps trying.
	Remaining []int `json:"remaining,omitempty"`

	deadlineMono time.Time
	termSent     bool
	closingSince time.Time
}

// A pending admission: sshd accepted a certificate on this connection, and
// the session hook has not yet attached the process. It lives for PendingTTL.
type pending struct {
	sshd     Proc
	grantID  string
	user     string
	deadline int64
	created  time.Time
}

// Warden is the supervisor. One per host.
type Warden struct {
	cfg Config

	mu      sync.Mutex
	grants  map[string]*Grant
	pending map[int]*pending
	ready   bool

	signerDownSince time.Time
}

// New builds a Warden. It does nothing until Reconcile and Run.
func New(cfg Config) *Warden {
	cfg.defaults()
	return &Warden{cfg: cfg, grants: map[string]*Grant{}, pending: map[int]*pending{}}
}

var (
	// ErrNotReady is returned before reconciliation has succeeded. Nothing
	// is admitted until the warden knows what it is already supervising.
	ErrNotReady = errors.New("warden: not reconciled yet; admission is closed")
	// ErrDenied wraps every refusal with its reason.
	ErrDenied = errors.New("warden: denied")
)

func denied(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrDenied, fmt.Sprintf(format, args...))
}

func (w *Warden) sliceUnit(grantID string) string {
	return fmt.Sprintf("%s-%s.slice", strings.TrimSuffix(w.cfg.Slice, ".slice"), grantID)
}

func (w *Warden) sliceCgroup(grantID string) Cgroup {
	return Cgroup{Path: "/" + w.cfg.Slice + "/" + w.sliceUnit(grantID)}
}

func (w *Warden) scopeUnit(grantID string, pid int) string {
	return fmt.Sprintf("%s-%s-%d.scope", strings.TrimSuffix(w.cfg.Slice, ".slice"), grantID, pid)
}

// sshdOf reads the caller and its parent, and checks the parent is the
// privileged per-connection sshd process. Both the admission command and the
// session hook are children of that process, which is what ties an admitted
// certificate to a session without trusting either program's word for it.
func sshdOf(caller Proc) (Proc, error) {
	parent, err := ReadProc(caller.PPID)
	if err != nil {
		return Proc{}, denied("caller's parent %d: %v", caller.PPID, err)
	}
	if parent.UID != 0 {
		return Proc{}, denied("caller's parent %d runs as uid %d, not root", parent.PID, parent.UID)
	}
	if !parent.IsSSHD() {
		return Proc{}, denied("caller's parent %d is %q, not sshd", parent.PID, parent.Exe)
	}
	return parent, nil
}

// checkGrant asks the signer and applies every admission rule. It returns
// the grant if a session may start under it right now.
func (w *Warden) checkGrant(ctx context.Context, grantID, user, serial string) (GrantInfo, error) {
	g, err := w.cfg.Signer.Grant(ctx, grantID)
	if errors.Is(err, ErrGrantUnknown) {
		return GrantInfo{}, denied("grant %s is unknown to the signer", grantID)
	}
	if err != nil {
		// Fail closed. A visitor whose signer is unreachable gets no session,
		// not an unbounded one.
		return GrantInfo{}, fmt.Errorf("%w: cannot verify grant %s: %v", ErrDenied, grantID, err)
	}
	now := w.cfg.Now().Unix()
	switch {
	case g.SSHUser != user:
		return GrantInfo{}, denied("grant %s is for %s, not %s", grantID, g.SSHUser, user)
	case g.RevokedAt != nil:
		return GrantInfo{}, denied("grant %s was revoked", grantID)
	case g.ExpiresAt <= now:
		return GrantInfo{}, denied("grant %s expired %ds ago", grantID, now-g.ExpiresAt)
	case g.RedeemedAt == nil:
		return GrantInfo{}, denied("grant %s has not been redeemed, so no certificate exists for it", grantID)
	case serial != "" && g.CertificateSerial != serial:
		return GrantInfo{}, denied("certificate serial %s is not the one issued for grant %s", serial, grantID)
	}
	return g, nil
}

// Admit is the AuthorizedPrincipalsCommand. sshd has verified the
// certificate's signature against the CA and hands over its key id and
// serial; the caller is a child of the per-connection sshd. If the grant is
// open, the enrolled principal is returned and a pending admission is
// recorded against that sshd process, for Attach to find. Otherwise nothing
// is returned and sshd refuses the certificate.
func (w *Warden) Admit(ctx context.Context, caller Proc, user, keyID, serial string) (string, error) {
	w.mu.Lock()
	ready := w.ready
	w.mu.Unlock()
	if !ready {
		return "", ErrNotReady
	}
	if caller.UID != w.cfg.AdmitUID {
		return "", denied("admission requested by uid %d, not %d", caller.UID, w.cfg.AdmitUID)
	}
	if user != w.cfg.SSHUser {
		return "", denied("login as %s; only %s is enrolled", user, w.cfg.SSHUser)
	}
	grantID, _, err := ParseKeyID(keyID)
	if err != nil {
		return "", denied("key id %q: %v", keyID, err)
	}
	if serial == "" {
		return "", denied("no certificate serial")
	}
	sshd, err := sshdOf(caller)
	if err != nil {
		return "", err
	}

	// The grant's state on this host first: a group that is closing takes
	// nobody new, whatever the signer's clock says.
	w.mu.Lock()
	if g, ok := w.grants[grantID]; ok && g.State != Open {
		w.mu.Unlock()
		return "", denied("grant %s is %s on this host", grantID, g.State)
	}
	w.mu.Unlock()

	info, err := w.checkGrant(ctx, grantID, user, serial)
	if err != nil {
		return "", err
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if g, ok := w.grants[grantID]; ok && g.State != Open {
		return "", denied("grant %s is %s on this host", grantID, g.State)
	}
	w.pending[sshd.PID] = &pending{sshd: sshd, grantID: grantID, user: user,
		deadline: info.ExpiresAt, created: w.cfg.Now()}
	w.cfg.Log.Info("admitted certificate", "grant", grantID, "sshd_pid", sshd.PID,
		"deadline_in", time.Duration(info.ExpiresAt-w.cfg.Now().Unix())*time.Second)
	return user, nil
}

// Attach is the PAM session hook. The caller is a child of the same sshd
// process that Admit recorded, running as root, before the visitor's shell
// exists. That process is moved into a scope of its own inside the grant's
// slice; the shell, and everything it ever starts, inherits the cgroup.
func (w *Warden) Attach(ctx context.Context, caller Proc, user string) error {
	w.mu.Lock()
	ready := w.ready
	w.mu.Unlock()
	if !ready {
		return ErrNotReady
	}
	if caller.UID != 0 {
		return denied("attach requested by uid %d, not root", caller.UID)
	}
	sshd, err := sshdOf(caller)
	if err != nil {
		return err
	}

	w.mu.Lock()
	p, ok := w.pending[sshd.PID]
	if ok {
		delete(w.pending, sshd.PID)
	}
	w.mu.Unlock()
	switch {
	case !ok:
		return denied("no admitted certificate for sshd pid %d; the connection did not authenticate with a grantd certificate", sshd.PID)
	case !p.sshd.SameProcess(sshd):
		return denied("sshd pid %d was recycled since the certificate was admitted", sshd.PID)
	case p.user != user:
		return denied("certificate was admitted for %s, session is for %s", p.user, user)
	case w.cfg.Now().Sub(p.created) > w.cfg.PendingTTL:
		return denied("admission for sshd pid %d is %s old", sshd.PID, w.cfg.Now().Sub(p.created).Round(time.Second))
	}

	// Ask again. Revocation between admission and attachment is a window of
	// milliseconds, and this closes it.
	info, err := w.checkGrant(ctx, p.grantID, user, "")
	if err != nil {
		return err
	}
	now := w.cfg.Now()
	remaining := time.Duration(info.ExpiresAt-now.Unix()) * time.Second
	if remaining <= 0 {
		return denied("grant %s has no time left", p.grantID)
	}

	w.mu.Lock()
	g, ok := w.grants[p.grantID]
	if ok && g.State != Open {
		w.mu.Unlock()
		return denied("grant %s is %s on this host", p.grantID, g.State)
	}
	if !ok {
		g = &Grant{ID: p.grantID, State: Open, Sessions: map[int]*Session{}}
		w.grants[p.grantID] = g
	}
	// The signer's deadline, every time. A reconnect does not move it. The
	// wall deadline is what the signer says; the monotonic one is anchored to
	// the real elapsed-time clock, not to cfg.Now(), so a wall-clock jump
	// cannot move it.
	g.Deadline = info.ExpiresAt
	g.deadlineMono = time.Now().Add(remaining)
	w.mu.Unlock()

	slice := w.sliceUnit(p.grantID)
	if err := w.cfg.Systemd.StartSlice(ctx, slice, "grantd grant "+p.grantID); err != nil {
		return fmt.Errorf("%w: cannot create %s: %v", ErrDenied, slice, err)
	}
	scope := w.scopeUnit(p.grantID, sshd.PID)
	if err := w.cfg.Systemd.StartScope(ctx, scope, slice, "grantd session under "+p.grantID,
		sshd.PID, remaining+w.cfg.BackstopSlack, w.cfg.TermGrace); err != nil {
		return fmt.Errorf("%w: cannot create %s: %v", ErrDenied, scope, err)
	}

	// Trust the kernel, not the job: read the process's cgroup back.
	want := w.sliceCgroup(p.grantID).Path + "/" + scope
	placed := false
	for i := 0; i < 60; i++ {
		cur, err := ReadProc(sshd.PID)
		if err != nil {
			break
		}
		if cur.Cgroup == want {
			placed = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !placed {
		_ = w.cfg.Systemd.StopUnit(ctx, scope)
		return denied("sshd pid %d did not land in %s", sshd.PID, want)
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if g.State != Open {
		// Terminated while the scope was being created. The scope is inside
		// the slice, so the termination already covers it; refuse anyway so
		// the hook ends the connection.
		return denied("grant %s closed while the session was attaching", p.grantID)
	}
	g.Sessions[sshd.PID] = &Session{PID: sshd.PID, StartTime: sshd.StartTime, Scope: scope,
		Cgroup: want, Since: now.Unix()}
	w.persistLocked()
	w.cfg.Log.Info("session attached", "grant", p.grantID, "sshd_pid", sshd.PID, "scope", scope,
		"sessions", len(g.Sessions), "deadline_in", remaining)
	return nil
}

// Run drives deadlines, revocation, and cleanup until ctx ends. It ticks once
// a second, so a deadline is enforced within a second of passing, and asks the
// signer about every open grant every Poll, which bounds revocation latency.
func (w *Warden) Run(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var lastPoll time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		w.enforceDeadlines()
		if time.Since(lastPoll) >= w.cfg.Poll {
			lastPoll = time.Now()
			w.pollSigner(ctx)
		}
		w.expirePending()
		w.pruneSessions()
		w.advanceClosing(ctx)
	}
}

// enforceDeadlines closes any open grant whose deadline has passed. It closes
// on the monotonic deadline OR the wall deadline, whichever fires first, so a
// wall-clock jump backwards cannot buy a visitor more time and a jump forwards
// only ends the session sooner.
func (w *Warden) enforceDeadlines() {
	now := w.cfg.Now().Unix()
	mono := time.Now()
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, g := range w.grants {
		if g.State != Open {
			continue
		}
		monoPassed := !g.deadlineMono.IsZero() && !mono.Before(g.deadlineMono)
		wallPassed := now >= g.Deadline
		if monoPassed || wallPassed {
			w.closeLocked(g, "deadline reached")
		}
	}
}

// pollSigner asks the signer about every open grant. Revocation and any
// shortening of the deadline take effect here. A grant the signer no longer
// knows is terminated: its authority cannot be verified. A transient signer
// error leaves running sessions alone — the systemd RuntimeMax backstop still
// bounds them — and only blocks new admission, which checkGrant handles.
func (w *Warden) pollSigner(ctx context.Context) {
	w.mu.Lock()
	ids := make([]string, 0, len(w.grants))
	for id, g := range w.grants {
		if g.State == Open {
			ids = append(ids, id)
		}
	}
	w.mu.Unlock()

	for _, id := range ids {
		info, err := w.cfg.Signer.Grant(ctx, id)
		w.mu.Lock()
		g, ok := w.grants[id]
		if !ok || g.State != Open {
			w.mu.Unlock()
			continue
		}
		switch {
		case errors.Is(err, ErrGrantUnknown):
			w.closeLocked(g, "signer no longer knows this grant")
		case err != nil:
			w.cfg.Log.Warn("signer poll failed", "grant", id, "err", err)
		case info.RevokedAt != nil:
			w.closeLocked(g, "revoked")
		case info.ExpiresAt <= w.cfg.Now().Unix():
			w.closeLocked(g, "expired")
		case info.ExpiresAt < g.Deadline:
			// The host's deadline can only shrink. It is never extended by a
			// later answer.
			g.Deadline = info.ExpiresAt
			g.deadlineMono = time.Now().Add(time.Duration(info.ExpiresAt-w.cfg.Now().Unix()) * time.Second)
			w.persistLocked()
		}
		w.mu.Unlock()
	}
}

// closeLocked moves a grant from Open to Closing. Admission is already refused
// for a non-open grant, so this is the "close admission before terminating"
// step. The terminating itself runs in advanceClosing.
func (w *Warden) closeLocked(g *Grant, reason string) {
	if g.State != Open {
		return
	}
	g.State = Closing
	g.Reason = reason
	g.termSent = false
	w.cfg.Log.Info("closing grant", "grant", g.ID, "reason", reason, "sessions", len(g.Sessions))
	w.persistLocked()
}

// advanceClosing terminates every closing grant a step further and forgets
// grants that have been closed and empty for a while.
func (w *Warden) advanceClosing(ctx context.Context) {
	w.mu.Lock()
	var closing []*Grant
	for _, g := range w.grants {
		if g.State == Closing {
			closing = append(closing, g)
		}
	}
	w.mu.Unlock()

	for _, g := range closing {
		w.terminate(ctx, g)
	}

	w.mu.Lock()
	for id, g := range w.grants {
		if g.State == Closed && time.Since(g.closingSince) > 30*time.Second {
			delete(w.grants, id)
		}
	}
	w.persistLocked()
	w.mu.Unlock()
}

// terminate advances one closing grant. On the first pass it SIGTERMs the
// whole subtree; once the grace period is up it SIGKILLs it atomically with
// cgroup.kill, which catches tasks that forked after the listing and takes
// effect on tasks in uninterruptible sleep as soon as they become killable.
// It reports what is left and finalizes only when the kernel says the group
// is empty. It is idempotent, so a later tick simply retries.
func (w *Warden) terminate(ctx context.Context, g *Grant) {
	cg := w.sliceCgroup(g.ID)

	w.mu.Lock()
	if !g.termSent {
		g.termSent = true
		g.closingSince = w.cfg.Now()
	}
	elapsed := w.cfg.Now().Sub(g.closingSince)
	w.mu.Unlock()

	if !cg.Exists() {
		// No cgroup was ever created (a grant closed before any session
		// attached), or it is already gone.
		w.finalize(ctx, g)
		return
	}

	if elapsed < w.cfg.TermGrace {
		if _, err := cg.Signal(syscall.SIGTERM); err != nil {
			w.cfg.Log.Warn("SIGTERM to grant group failed", "grant", g.ID, "err", err)
		}
	} else {
		if err := cg.Kill(); err != nil {
			w.cfg.Log.Error("cgroup.kill failed", "grant", g.ID, "err", err)
		}
	}

	populated, err := cg.Populated()
	if err != nil {
		w.cfg.Log.Error("cannot read grant group state", "grant", g.ID, "err", err)
		return
	}
	if !populated {
		w.finalize(ctx, g)
		return
	}

	pids, _ := cg.Procs()
	w.mu.Lock()
	g.Remaining = pids
	w.mu.Unlock()
	if elapsed >= w.cfg.TermGrace+w.cfg.KillWait {
		// Past the point everything should be gone. Almost always this is a
		// task in uninterruptible sleep (D state), e.g. blocked on NFS. Report
		// it and keep trying rather than declaring cleanup done.
		w.cfg.Log.Warn("grant group not empty after kill; retrying",
			"grant", g.ID, "remaining", pids, "elapsed", elapsed.Round(time.Second))
	}
}

// finalize stops the slice unit and marks the grant closed. It is only reached
// once the group is empty.
func (w *Warden) finalize(ctx context.Context, g *Grant) {
	if err := w.cfg.Systemd.StopUnit(ctx, w.sliceUnit(g.ID)); err != nil {
		w.cfg.Log.Warn("stopping grant slice failed", "grant", g.ID, "err", err)
	}
	w.mu.Lock()
	g.State = Closed
	g.Remaining = nil
	g.closingSince = w.cfg.Now()
	g.Sessions = map[int]*Session{}
	w.persistLocked()
	w.mu.Unlock()
	w.cfg.Log.Info("grant terminated; group empty", "grant", g.ID, "reason", g.Reason)
}

// expirePending drops admissions that were never attached. sshd's
// LoginGraceTime closes the connection anyway; this keeps the map bounded.
func (w *Warden) expirePending() {
	now := w.cfg.Now()
	w.mu.Lock()
	defer w.mu.Unlock()
	for pid, p := range w.pending {
		if now.Sub(p.created) > w.cfg.PendingTTL {
			delete(w.pending, pid)
		}
	}
}

// pruneSessions forgets sessions whose sshd process is gone, so the count and
// the state file reflect what is actually running. The cgroup still bounds
// anything left behind by a session that closed.
func (w *Warden) pruneSessions() {
	w.mu.Lock()
	defer w.mu.Unlock()
	changed := false
	for _, g := range w.grants {
		for pid, sess := range g.Sessions {
			cur, err := ReadProc(pid)
			if err != nil || cur.StartTime != sess.StartTime {
				delete(g.Sessions, pid)
				changed = true
			}
		}
	}
	if changed {
		w.persistLocked()
	}
}

// Reconcile rebuilds the warden's picture of what is running after a restart,
// then opens admission. It refuses to open until it can reach the signer and
// account for every grant slice already on the machine: a group whose
// authority the signer cannot confirm is scheduled for termination rather than
// left running. Until this returns nil, Admit and Attach fail closed.
func (w *Warden) Reconcile(ctx context.Context) error {
	if err := w.cfg.Signer.Ping(ctx); err != nil {
		return fmt.Errorf("warden: signer unreachable, refusing to open admission: %w", err)
	}

	loaded := w.loadState()

	// Every grant slice on disk, whether or not the state file knew about it.
	ids := map[string]bool{}
	for id := range loaded {
		ids[id] = true
	}
	for _, id := range w.discoverGrantIDs() {
		ids[id] = true
	}

	grants := map[string]*Grant{}
	now := w.cfg.Now()
	for id := range ids {
		g := loaded[id]
		if g == nil {
			g = &Grant{ID: id, State: Open, Sessions: map[int]*Session{}}
		}
		if g.Sessions == nil {
			g.Sessions = map[int]*Session{}
		}
		info, err := w.cfg.Signer.Grant(ctx, id)
		switch {
		case errors.Is(err, ErrGrantUnknown):
			g.State = Closing
			g.Reason = "unknown to the signer after restart"
			g.termSent = false
		case err != nil:
			// The signer answered Ping but not this. Do not trust an
			// unverifiable group.
			g.State = Closing
			g.Reason = "could not be verified after restart"
			g.termSent = false
		case info.RevokedAt != nil:
			g.State = Closing
			g.Reason = "revoked"
			g.termSent = false
		case info.ExpiresAt <= now.Unix():
			g.State = Closing
			g.Reason = "expired"
			g.termSent = false
		default:
			g.State = Open
			g.Deadline = info.ExpiresAt
			g.deadlineMono = time.Now().Add(time.Duration(info.ExpiresAt-now.Unix()) * time.Second)
			// Keep only sessions whose sshd process is still the same one.
			for pid, sess := range g.Sessions {
				cur, err := ReadProc(pid)
				if err != nil || cur.StartTime != sess.StartTime {
					delete(g.Sessions, pid)
				}
			}
		}
		grants[id] = g
	}

	w.mu.Lock()
	w.grants = grants
	w.ready = true
	w.persistLocked()
	w.mu.Unlock()
	w.cfg.Log.Info("reconciled", "grants", len(grants))
	return nil
}

// discoverGrantIDs reads the grant slices already present under the parent
// slice, so a restart adopts or terminates groups even if the state file was
// lost. /run is a tmpfs, so after a reboot there are none, which is correct:
// the sessions are gone too.
func (w *Warden) discoverGrantIDs() []string {
	parent := Cgroup{Path: "/" + w.cfg.Slice}
	children, err := parent.Children()
	if err != nil {
		return nil
	}
	prefix := strings.TrimSuffix(w.cfg.Slice, ".slice") + "-"
	var out []string
	for _, c := range children {
		name := c.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".slice") {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".slice")
		if protocol.ValidGrantID(id) {
			out = append(out, id)
		}
	}
	return out
}

// persistLocked writes the current grants to the state file, atomically. The
// caller holds w.mu.
func (w *Warden) persistLocked() {
	if w.cfg.StateFile == "" {
		return
	}
	grants := make([]*Grant, 0, len(w.grants))
	for _, g := range w.grants {
		grants = append(grants, g)
	}
	sort.Slice(grants, func(i, j int) bool { return grants[i].ID < grants[j].ID })
	data, err := json.MarshalIndent(struct {
		Grants []*Grant `json:"grants"`
	}{grants}, "", "  ")
	if err != nil {
		w.cfg.Log.Error("cannot marshal warden state", "err", err)
		return
	}
	tmp := w.cfg.StateFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		w.cfg.Log.Error("cannot write warden state", "err", err)
		return
	}
	if err := os.Rename(tmp, w.cfg.StateFile); err != nil {
		w.cfg.Log.Error("cannot replace warden state", "err", err)
	}
}

// loadState reads the state file. A missing or unreadable file is not an
// error: the machine may be starting fresh.
func (w *Warden) loadState() map[string]*Grant {
	out := map[string]*Grant{}
	if w.cfg.StateFile == "" {
		return out
	}
	data, err := os.ReadFile(w.cfg.StateFile)
	if err != nil {
		return out
	}
	var doc struct {
		Grants []*Grant `json:"grants"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		w.cfg.Log.Warn("ignoring unreadable warden state", "err", err)
		return out
	}
	for _, g := range doc.Grants {
		if g != nil && protocol.ValidGrantID(g.ID) {
			out[g.ID] = g
		}
	}
	return out
}

// Ready reports whether reconciliation has completed and admission is open.
func (w *Warden) Ready() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.ready
}

// setReady is for tests that exercise admission without a full reconcile.
func (w *Warden) setReady(v bool) {
	w.mu.Lock()
	w.ready = v
	w.mu.Unlock()
}

// grantSnapshot returns a copy of a grant's public state, for tests and the
// status route.
func (w *Warden) grantSnapshot(id string) (Grant, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	g, ok := w.grants[id]
	if !ok {
		return Grant{}, false
	}
	cp := *g
	cp.Sessions = map[int]*Session{}
	for k, v := range g.Sessions {
		s := *v
		cp.Sessions[k] = &s
	}
	return cp, true
}

// Snapshot returns every grant's public state, newest activity not ordered.
func (w *Warden) Snapshot() []Grant {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]Grant, 0, len(w.grants))
	for _, g := range w.grants {
		cp := *g
		cp.Sessions = map[int]*Session{}
		for k, v := range g.Sessions {
			s := *v
			cp.Sessions[k] = &s
		}
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
