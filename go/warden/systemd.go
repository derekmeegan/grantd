package warden

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Systemd is the part of the service manager the warden uses: create a
// transient unit around an existing process, and stop one. Tests substitute
// a fake.
type Systemd interface {
	// StartScope puts pid into a new transient scope in slice. RuntimeMax is
	// the independent backstop: systemd itself stops the scope after that
	// long, whether or not the warden is alive to ask. stopTimeout bounds
	// how long systemd waits after SIGTERM before SIGKILL when it does.
	StartScope(ctx context.Context, name, slice, description string, pid int, runtimeMax, stopTimeout time.Duration) error
	// StartSlice creates a transient slice. It succeeds if the slice exists.
	StartSlice(ctx context.Context, name, description string) error
	// StopUnit stops a unit and its children. A unit that is not loaded is
	// not an error.
	StopUnit(ctx context.Context, name string) error
}

// BusctlSystemd talks to systemd over D-Bus with busctl and systemctl, which
// every systemd installation ships. It avoids a D-Bus library in a daemon
// whose whole job is to be small enough to read.
type BusctlSystemd struct{}

const (
	sdService = "org.freedesktop.systemd1"
	sdObject  = "/org/freedesktop/systemd1"
	sdManager = "org.freedesktop.systemd1.Manager"
)

func (BusctlSystemd) StartScope(ctx context.Context, name, slice, description string, pid int, runtimeMax, stopTimeout time.Duration) error {
	usec := func(d time.Duration) string { return strconv.FormatInt(int64(d/time.Microsecond), 10) }
	// StartTransientUnit(name, mode, properties, aux). Properties for a scope:
	// the pids it starts with, its slice, and the timers that end it without
	// anyone asking. CollectMode lets systemd forget a scope that hit its
	// RuntimeMax instead of leaving it in a failed state that needs a
	// reset-failed.
	args := []string{"--system", "call", sdService, sdObject, sdManager, "StartTransientUnit",
		"ssa(sv)a(sa(sv))", name, "fail",
		"6",
		"PIDs", "au", "1", strconv.Itoa(pid),
		"Slice", "s", slice,
		"Description", "s", description,
		"RuntimeMaxUSec", "t", usec(runtimeMax),
		"TimeoutStopUSec", "t", usec(stopTimeout),
		"CollectMode", "s", "inactive-or-failed",
		"0"}
	_, err := run(ctx, "busctl", args...)
	return err
}

func (BusctlSystemd) StartSlice(ctx context.Context, name, description string) error {
	args := []string{"--system", "call", sdService, sdObject, sdManager, "StartTransientUnit",
		"ssa(sv)a(sa(sv))", name, "fail",
		"2",
		"Description", "s", description,
		"CollectMode", "s", "inactive-or-failed",
		"0"}
	_, err := run(ctx, "busctl", args...)
	if err != nil {
		low := strings.ToLower(err.Error())
		// A slice that already exists, or is already running, is exactly what
		// we want. Only other failures matter.
		if strings.Contains(low, "already exists") || strings.Contains(low, "already active") ||
			strings.Contains(low, "file exists") {
			return nil
		}
	}
	return err
}

func (BusctlSystemd) StopUnit(ctx context.Context, name string) error {
	_, err := run(ctx, "systemctl", "stop", "--no-block", name)
	if err != nil && strings.Contains(err.Error(), "not loaded") {
		return nil
	}
	return err
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return out.String(), fmt.Errorf("%s %s: %s", name, args[0], msg)
	}
	return out.String(), nil
}

// SystemdVersion reports the running systemd's version number, or an error.
func SystemdVersion(ctx context.Context) (int, error) {
	out, err := run(ctx, "systemctl", "--version")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(strings.SplitN(out, "\n", 2)[0])
	if len(fields) < 2 {
		return 0, errors.New("warden: cannot parse systemctl --version")
	}
	// "systemd 255 (255.4-1ubuntu8)" — the number may carry a suffix on some
	// distributions, so keep the leading digits only.
	digits := strings.TrimRightFunc(fields[1], func(r rune) bool { return r < '0' || r > '9' })
	n, err := strconv.Atoi(digits)
	if err != nil {
		return 0, fmt.Errorf("warden: cannot parse systemd version %q", fields[1])
	}
	return n, nil
}
