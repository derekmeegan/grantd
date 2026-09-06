// Command grant-warden bounds how long a visitor may run.
//
// It runs as root, outside any visitor's cgroup, and holds no key material. It
// learns a grant's deadline from the signer over a read-only local socket, and
// it learns which process belongs to which certificate from two sshd hooks
// that call grant-admit. At the deadline, or on revocation, it empties the
// grant's root-owned cgroup.
//
// It refuses to start on a host that cannot enforce: cgroup v2 with
// cgroup.kill, and a systemd new enough to hold transient scopes. The
// installer must not fall back to the old best-effort reaper silently; that is
// the installer's job, and this binary simply exits non-zero here.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/derekmeegan/grantd/go/signer/api"
	"github.com/derekmeegan/grantd/go/warden"
)

func main() {
	fs := flag.NewFlagSet("grant-warden", flag.ExitOnError)
	admitSock := fs.String("admit-sock", env("GRANTD_ADMIT_SOCK", "/run/grantd/warden/admit.sock"),
		"socket the sshd hooks call")
	lifetimeSock := fs.String("lifetime-sock", env("GRANTD_LIFETIME_SOCK", "/run/grantd/lifetime/lifetime.sock"),
		"the signer's lifetime socket")
	stateFile := fs.String("state", env("GRANTD_WARDEN_STATE", "/run/grantd/warden/state.json"),
		"where open grants are recorded across a restart")
	sshUser := fs.String("ssh-user", os.Getenv("GRANTD_SSH_USER"), "the enrolled account")
	slice := fs.String("slice", "grantd.slice", "parent slice for every grant")
	admitUID := fs.Int("admit-uid", -1, "uid sshd runs the admission command as")
	admitGID := fs.Int("admit-gid", -1, "group that owns the admit socket")
	termGrace := fs.Duration("term-grace", 5*time.Second, "time after SIGTERM before SIGKILL")
	poll := fs.Duration("poll", 2*time.Second, "how often to re-check every open grant with the signer")
	killWait := fs.Duration("kill-wait", 10*time.Second, "how long to wait for a group to empty after SIGKILL")
	reconcileFor := fs.Duration("reconcile-timeout", 60*time.Second, "how long to wait for the signer at startup")
	_ = fs.Parse(os.Args[1:])

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if *sshUser == "" {
		die(log, "no --ssh-user")
	}
	if *admitUID < 0 {
		die(log, "no --admit-uid")
	}

	// Refuse enforcement on a host that cannot enforce. The installer detects
	// the same things and refuses to install; this is the runtime backstop.
	if !warden.IsUnified() {
		die(log, "cgroup v2 unified hierarchy is required")
	}
	if !warden.HasCgroupKill() {
		die(log, "cgroup.kill is required; the kernel is older than 5.14")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if v, err := warden.SystemdVersion(ctx); err != nil {
		die(log, "systemd is required: "+err.Error())
	} else if v < 244 {
		die(log, fmt.Sprintf("systemd %d is too old; 244+ is required for RuntimeMaxSec on transient scopes", v))
	}

	sysd := warden.BusctlSystemd{}
	// The parent slice carries the resource limits shared by every visitor;
	// the installer ships its unit. Make sure it exists before anything is
	// placed under it.
	if err := sysd.StartSlice(ctx, *slice, "grantd visitor containment"); err != nil {
		log.Warn("could not pre-create the parent slice", "err", err)
	}

	w := warden.New(warden.Config{
		SSHUser:   *sshUser,
		Signer:    warden.NewSignerClient(*lifetimeSock),
		Systemd:   sysd,
		Slice:     *slice,
		StateFile: *stateFile,
		AdmitUID:  *admitUID,
		Log:       log,
		TermGrace: *termGrace,
		KillWait:  *killWait,
		Poll:      *poll,
	})

	// Block admission until reconciliation succeeds. A signer that is briefly
	// unreachable at boot is retried; a signer that never comes is fatal, and
	// systemd restarts us.
	deadline := time.Now().Add(*reconcileFor)
	for {
		if err := w.Reconcile(ctx); err == nil {
			break
		} else if time.Now().After(deadline) {
			die(log, "could not reconcile before the deadline: "+err.Error())
		} else {
			log.Warn("waiting for the signer before opening admission", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}

	ln, err := api.Listen(*admitSock, 0o660, -1, *admitGID)
	if err != nil {
		die(log, "cannot listen on the admit socket: "+err.Error())
	}
	defer ln.Close()

	srv := &warden.AdmitServer{W: w, Log: log}
	go func() {
		if err := srv.Serve(ln); err != nil {
			log.Error("admit server stopped", "err", err)
		}
	}()

	log.Info("warden ready", "admit_sock", *admitSock, "ssh_user", *sshUser, "slice", *slice)
	w.Run(ctx)
	log.Info("warden stopped")
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func die(log *slog.Logger, msg string) {
	log.Error("grant-warden: " + msg)
	os.Exit(1)
}
