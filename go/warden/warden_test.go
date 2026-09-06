package warden

import (
	"context"
	"errors"
	"testing"
	"time"
)

func ref(v int64) *int64 { return &v }

// openGrant is a redeemed, unexpired, unrevoked grant for the given user.
func openGrant(id, user string, expires int64) GrantInfo {
	return GrantInfo{ID: id, SSHUser: user, ExpiresAt: expires,
		RedeemedAt: ref(1), CertificateSerial: "42"}
}

const keyID = "grantd:g_aaaaaaaaaaaaaaaa:a_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const grantID = "g_aaaaaaaaaaaaaaaa"

func TestParseKeyID(t *testing.T) {
	g, a, err := ParseKeyID(keyID)
	if err != nil || g != grantID || a != "a_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("ParseKeyID = %q %q %v", g, a, err)
	}
	for _, bad := range []string{"", "grantd:g_bad:a_x", "notgrantd:g_aaaaaaaaaaaaaaaa:a_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"grantd:g_aaaaaaaaaaaaaaaa", "grantd:g_aaaaaaaaaaaaaaaa:notanagent"} {
		if _, _, err := ParseKeyID(bad); err == nil {
			t.Errorf("ParseKeyID(%q) accepted", bad)
		}
	}
}

func TestReadProc(t *testing.T) {
	dir := t.TempDir()
	old := ProcFS
	ProcFS = dir
	defer func() { ProcFS = old }()
	writeProc(dir, 4242, 7, 1000, 9999, "sshd", "/user.slice/session-3.scope")
	p, err := ReadProc(4242)
	if err != nil {
		t.Fatal(err)
	}
	if p.PPID != 7 || p.UID != 1000 || p.StartTime != 9999 || !p.IsSSHD() {
		t.Fatalf("got %+v", p)
	}
	if p.Cgroup != "/user.slice/session-3.scope" {
		t.Fatalf("cgroup %q", p.Cgroup)
	}
	if _, err := ReadProc(999999); !errors.Is(err, ErrNoProcess) {
		t.Fatalf("expected ErrNoProcess, got %v", err)
	}
}

func TestAdmitNotReady(t *testing.T) {
	tw := newTestWarden(t, "agentuser", 500)
	_, caller := tw.connection(t, 100, 101, 500)
	if _, err := tw.w.Admit(context.Background(), caller, "agentuser", keyID, "42"); !errors.Is(err, ErrNotReady) {
		t.Fatalf("expected ErrNotReady, got %v", err)
	}
}

func TestAdmitRules(t *testing.T) {
	tw := newTestWarden(t, "agentuser", 500)
	tw.w.setReady(true)
	tw.sig.put(openGrant(grantID, "agentuser", tw.clock.now().Unix()+300))
	ctx := context.Background()

	cases := []struct {
		name              string
		user, keyID, serl string
		callerUID         int
		wantOK            bool
	}{
		{"happy", "agentuser", keyID, "42", 500, true},
		{"wrong caller uid", "agentuser", keyID, "42", 501, false},
		{"wrong user", "root", keyID, "42", 500, false},
		{"bad key id", "agentuser", "grantd:bad:bad", "42", 500, false},
		{"no serial", "agentuser", keyID, "", 500, false},
		{"wrong serial", "agentuser", keyID, "99", 500, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, caller := tw.connection(t, 200, 201, c.callerUID)
			princ, err := tw.w.Admit(ctx, caller, c.user, c.keyID, c.serl)
			if c.wantOK {
				if err != nil || princ != "agentuser" {
					t.Fatalf("want ok, got %q %v", princ, err)
				}
			} else if err == nil {
				t.Fatalf("want denial, got principal %q", princ)
			}
		})
	}
}

func TestAdmitRevokedAndExpired(t *testing.T) {
	tw := newTestWarden(t, "agentuser", 500)
	tw.w.setReady(true)
	ctx := context.Background()
	now := tw.clock.now().Unix()

	revoked := openGrant(grantID, "agentuser", now+300)
	revoked.RevokedAt = ref(now - 1)
	tw.sig.put(revoked)
	_, caller := tw.connection(t, 300, 301, 500)
	if _, err := tw.w.Admit(ctx, caller, "agentuser", keyID, "42"); err == nil {
		t.Fatal("admitted a revoked grant")
	}

	expired := openGrant(grantID, "agentuser", now-1)
	tw.sig.put(expired)
	if _, err := tw.w.Admit(ctx, caller, "agentuser", keyID, "42"); err == nil {
		t.Fatal("admitted an expired grant")
	}
}

func TestAdmitSignerDownFailsClosed(t *testing.T) {
	tw := newTestWarden(t, "agentuser", 500)
	tw.w.setReady(true)
	tw.sig.put(openGrant(grantID, "agentuser", tw.clock.now().Unix()+300))
	tw.sig.mu.Lock()
	tw.sig.down = true
	tw.sig.mu.Unlock()
	_, caller := tw.connection(t, 400, 401, 500)
	if _, err := tw.w.Admit(context.Background(), caller, "agentuser", keyID, "42"); err == nil {
		t.Fatal("admitted while the signer was unreachable")
	}
}

// fullAttach admits and attaches one session, returning the sshd pid.
func fullAttach(t *testing.T, tw *testWarden, sshdPID, callerPID int) {
	t.Helper()
	ctx := context.Background()
	_, admitCaller := tw.connection(t, sshdPID, callerPID, tw.w.cfg.AdmitUID)
	if _, err := tw.w.Admit(ctx, admitCaller, "agentuser", keyID, "42"); err != nil {
		t.Fatalf("admit: %v", err)
	}
	// The PAM hook runs as root, a different child of the same sshd process.
	writeProc(tw.proc, callerPID+1, sshdPID, 0, 333, "grant-attach", "/grantd-preattach")
	attachCaller, err := ReadProc(callerPID + 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := tw.w.Attach(ctx, attachCaller, "agentuser"); err != nil {
		t.Fatalf("attach: %v", err)
	}
}

func TestAttachPlacesSession(t *testing.T) {
	tw := newTestWarden(t, "agentuser", 500)
	tw.w.setReady(true)
	tw.sig.put(openGrant(grantID, "agentuser", tw.clock.now().Unix()+300))
	fullAttach(t, tw, 500, 501)

	g, ok := tw.w.grantSnapshot(grantID)
	if !ok || g.State != Open || len(g.Sessions) != 1 {
		t.Fatalf("grant after attach: %+v ok=%v", g, ok)
	}
	if g.Deadline != tw.clock.now().Unix()+300 {
		t.Fatalf("deadline %d", g.Deadline)
	}
}

func TestAttachRequiresPriorAdmit(t *testing.T) {
	tw := newTestWarden(t, "agentuser", 500)
	tw.w.setReady(true)
	// A root child of an sshd process that never presented a grantd certificate.
	writeProc(tw.proc, 600, 1, 0, 111, "sshd", "/x")
	writeProc(tw.proc, 601, 600, 0, 222, "grant-attach", "/x")
	caller, _ := ReadProc(601)
	if err := tw.w.Attach(context.Background(), caller, "agentuser"); err == nil {
		t.Fatal("attached a session with no admitted certificate")
	}
}

func TestDeadlineEnforced(t *testing.T) {
	tw := newTestWarden(t, "agentuser", 500)
	tw.w.setReady(true)
	tw.sig.put(openGrant(grantID, "agentuser", tw.clock.now().Unix()+300))
	fullAttach(t, tw, 500, 501)

	tw.w.enforceDeadlines()
	if g, _ := tw.w.grantSnapshot(grantID); g.State != Open {
		t.Fatalf("closed early: %s", g.State)
	}
	// Wall clock passes the deadline.
	tw.clock.add(301)
	tw.w.enforceDeadlines()
	if g, _ := tw.w.grantSnapshot(grantID); g.State != Closing {
		t.Fatalf("not closing after deadline: %s", g.State)
	}
}

func TestClockJumpBackwardDoesNotExtend(t *testing.T) {
	tw := newTestWarden(t, "agentuser", 500)
	tw.w.setReady(true)
	tw.sig.put(openGrant(grantID, "agentuser", tw.clock.now().Unix()+300))
	fullAttach(t, tw, 500, 501)

	// Force the monotonic deadline into the past, then jump the wall clock far
	// backwards. The monotonic guard must still close the grant.
	tw.w.mu.Lock()
	tw.w.grants[grantID].deadlineMono = time.Now().Add(-time.Second)
	tw.w.mu.Unlock()
	tw.clock.set(1) // year 1970
	tw.w.enforceDeadlines()
	if g, _ := tw.w.grantSnapshot(grantID); g.State != Closing {
		t.Fatalf("clock jump extended the lifetime: %s", g.State)
	}
}

func TestRevocationClosesViaPoll(t *testing.T) {
	tw := newTestWarden(t, "agentuser", 500)
	tw.w.setReady(true)
	now := tw.clock.now().Unix()
	tw.sig.put(openGrant(grantID, "agentuser", now+300))
	fullAttach(t, tw, 500, 501)

	revoked := openGrant(grantID, "agentuser", now+300)
	revoked.RevokedAt = ref(now)
	tw.sig.put(revoked)
	tw.w.pollSigner(context.Background())
	g, _ := tw.w.grantSnapshot(grantID)
	if g.State != Closing || g.Reason != "revoked" {
		t.Fatalf("poll did not close on revoke: %s %q", g.State, g.Reason)
	}
}

func TestTerminateFinalizesWhenEmpty(t *testing.T) {
	tw := newTestWarden(t, "agentuser", 500)
	tw.w.setReady(true)
	tw.sig.put(openGrant(grantID, "agentuser", tw.clock.now().Unix()+300))
	fullAttach(t, tw, 500, 501)
	ctx := context.Background()

	// Close and take one termination step: the group is still populated.
	tw.w.mu.Lock()
	tw.w.closeLocked(tw.w.grants[grantID], "test")
	g := tw.w.grants[grantID]
	tw.w.mu.Unlock()
	tw.w.terminate(ctx, g)
	if s, _ := tw.w.grantSnapshot(grantID); s.State != Closing {
		t.Fatalf("finalized while still populated: %s", s.State)
	}

	// The group empties; the next step finalizes and stops the slice.
	markUnpopulated(tw.cg, tw.w.sliceUnit(grantID))
	tw.w.terminate(ctx, g)
	if s, _ := tw.w.grantSnapshot(grantID); s.State != Closed {
		t.Fatalf("not closed after group emptied: %s", s.State)
	}
	found := false
	for _, c := range tw.sd.calls {
		if c == "stop "+tw.w.sliceUnit(grantID) {
			found = true
		}
	}
	if !found {
		t.Fatalf("slice was not stopped; calls: %v", tw.sd.calls)
	}
}

func TestReconcileRefusesWhenSignerDown(t *testing.T) {
	tw := newTestWarden(t, "agentuser", 500)
	tw.sig.mu.Lock()
	tw.sig.down = true
	tw.sig.mu.Unlock()
	if err := tw.w.Reconcile(context.Background()); err == nil {
		t.Fatal("reconcile succeeded with the signer down")
	}
	if tw.w.Ready() {
		t.Fatal("admission opened despite reconcile failure")
	}
}

func TestReconcileTerminatesUnknownSlice(t *testing.T) {
	tw := newTestWarden(t, "agentuser", 500)
	// A grant slice exists on disk, but the signer has never heard of it.
	tw.sd.StartSlice(context.Background(), tw.w.sliceUnit(grantID), "")
	tw.sig.unknown[grantID] = true
	if err := tw.w.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !tw.w.Ready() {
		t.Fatal("admission not opened after reconcile")
	}
	g, ok := tw.w.grantSnapshot(grantID)
	if !ok || g.State != Closing {
		t.Fatalf("unknown slice not scheduled for termination: %+v ok=%v", g, ok)
	}
}

func TestReconcileAdoptsOpenGrant(t *testing.T) {
	tw := newTestWarden(t, "agentuser", 500)
	tw.w.setReady(true)
	tw.sig.put(openGrant(grantID, "agentuser", tw.clock.now().Unix()+300))
	fullAttach(t, tw, 500, 501)
	// A fresh warden over the same filesystems and state file: a restart.
	tw2 := &testWarden{
		w: New(Config{SSHUser: "agentuser", Signer: tw.sig, Systemd: tw.sd,
			StateFile: tw.w.cfg.StateFile, AdmitUID: 500, Now: tw.clock.now,
			TermGrace: 0, Poll: time.Second, PendingTTL: time.Minute}),
		sig: tw.sig, sd: tw.sd, clock: tw.clock, proc: tw.proc, cg: tw.cg,
	}
	if err := tw2.w.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	g, ok := tw2.w.grantSnapshot(grantID)
	if !ok || g.State != Open || len(g.Sessions) != 1 {
		t.Fatalf("open grant not adopted across restart: %+v ok=%v", g, ok)
	}
}
