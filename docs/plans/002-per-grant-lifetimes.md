# Plan 002 — Per-grant process lifetimes

Status: in progress. Branch: `main` (incremental, guarded by the `droplets`
workflow). This document is the design the implementation follows. It is
written to be read before the code.

## 0. What this replaces and why

Today a certificate's expiry stops new connections, and a polling reaper
(`install/reap-sessions.sh`, `grant-signer expired-grants`) closes sessions
that outlived their grant by matching sshd log lines to expired grant ids and
sending SIGTERM to the pids it finds. That is best-effort: it reads the
journal, matches on process name, and a determined visitor can outlive it with
`setsid`, `nohup`, a double-fork, or a process the journal never tied to the
grant.

This plan replaces it with kernel-enforced, per-grant containment: every
process of a grant lives in a root-owned cgroup v2 subtree it cannot leave, and
the deadline is enforced by emptying that subtree, not by guessing which pids
to signal.

### Scope of the guarantee

This bounds **execution**. It does not undo filesystem changes, copied
credentials, or external side effects a visitor caused while connected. It is
not a sandbox for arbitrary hostile code; it is a hard bound on how long a
visitor's processes may run. The documentation must say this plainly, and must
not advertise hard execution expiry until the admission boundary, the escape
controls, and the failure handling are implemented and tested.

## 1. Trust model (unchanged)

Preserved exactly:

- Grant secrets, the host identity key, and the SSH CA key stay on the host,
  owned by `grantsigner`, unreadable by the network daemon.
- Certificate issuance stays in the isolated signer.
- The coordination service and the network daemon (`grantd`) are untrusted.
- Single-use redemption and SSH host-key pinning are unchanged.

New, and consistent with the above:

- The lifetime supervisor (`grant-warden`) gets **no** access to any private
  key. It reads only the grant metadata it needs — expiry, revocation, the
  enrolled user, the issued serial — over a narrow, authenticated,
  **read-only** local socket the signer serves (`--lifetime-sock`). That socket
  exposes `GET /grants/{id}` and `GET /status` and nothing that mints, signs,
  redeems, or revokes.

## 2. Components

| Process | Runs as | Holds | Talks to |
|---|---|---|---|
| `grant-signer` | `grantsigner` | keys, grant DB | owner, daemon, **lifetime** sockets |
| `grantd` | `grantd` | nothing | coordination service, signer daemon socket |
| `grant-warden` | **root** | no keys | signer lifetime socket; admit socket; systemd |
| `grant-admit` | `grantadmit` (principals) / root (attach) | nothing | admit socket |

`grant-warden` is root because it must place processes into root-owned cgroups
and drive systemd, and it must be unwritable by visitors. It is a separate
identity and unit from `grantd`, which stays the untrusted, network-facing,
keyless daemon.

## 3. The OpenSSH integration

This is the part that must be designed before it is built, because a shell
wrapper alone misses subsystems, startup hooks, and forwarding.

### 3.1 Two hooks, one correlation

sshd, after it has cryptographically verified a certificate against
`TrustedUserCAKeys`, is asked twice about the connection by grantd:

1. **`AuthorizedPrincipalsCommand`** → `grant-admit principals %u %t %k`, run as
   `AuthorizedPrincipalsCommandUser grantadmit`, during authentication. It is
   invoked only for certificates. grantd reconstructs the authorized-keys line
   from the type (`%t`) and blob (`%k`), parses the certificate, and reads the
   **key id** (`grantd:<grant>:<agent>`) and **serial** straight from the bytes
   sshd verified. The grant identity therefore comes from the verified
   certificate, never from a client-supplied environment variable, command
   argument, or principal string. The warden checks the grant against the
   signer (redeemed, not expired, not revoked, right user, right serial) and,
   if it is open, returns the one enrolled principal and records a *pending
   admission* keyed by the per-connection sshd process. An empty answer refuses
   the certificate.

2. **PAM `session`** → `grant-admit attach`, run by `pam_exec` as **root**, at
   `session open`, before the visitor's shell, remote command, or subsystem
   starts. It asks the warden to place the session's sshd process into the
   grant's cgroup. If the warden refuses or is unreachable, `grant-admit`
   exits non-zero, PAM fails the session, and sshd closes the connection: no
   user code runs outside containment.

The correlation between the two is the **per-connection privileged sshd
process**. Under OpenSSH privilege separation, that process (the monitor;
`sshd-session` on 9.8+) is the one that forks both `grant-admit` invocations,
and it is the ancestor of the shell/command/subsystem it later starts. The
warden reads the caller's parent from `/proc` and the kernel's `SO_PEERCRED`
(not from anything the caller says), confirms the parent is a root sshd
process, and keys the pending admission by that parent's pid and start time.
`attach` places that same process into a fresh scope inside the grant's slice;
everything the session forks afterwards — including via `fork`, `exec`,
`nohup`, `setsid`, and double-forking — inherits the cgroup, because cgroup
membership is inherited at fork and the tree is not delegated to the visitor.

### 3.2 Why PAM session, not ForceCommand or a shell wrapper

`session open` runs as root, before user code, for **interactive shells,
remote commands (`exec`), and subsystems (`sftp`)** alike, when `UsePAM yes`
(the default on Debian/Ubuntu). A `ForceCommand` runs as the visitor (so it
cannot place itself into a root-owned cgroup) and does not cleanly cover
subsystems. A login-shell wrapper misses `exec` and `sftp` entirely. PAM
session is the single point that covers every session type before any user
code, as root.

### 3.3 Forwarding-only connections

grantd certificates already carry no `permit-port-forwarding`,
`permit-agent-forwarding`, or `permit-X11-forwarding` extension, so a visitor
cannot forward. A pure `ssh -N` connection opens no session channel, so no PAM
session and no shell run; it can only hold an authenticated TCP connection open
until `LoginGraceTime`/`ClientAliveInterval` or the certificate's own validity
ends it. It executes nothing. This is the "explicitly disable or
lifetime-bound forwarding-only connections" requirement: forwarding is denied
outright, and such a connection has no execution to contain.

### 3.4 What must be validated on real sshd (the droplets test)

The parent-pid correlation and the "placing the monitor cgroups the whole
session" property depend on sshd's process model, which the unit tests cannot
exercise. The `droplets` workflow validates them on Ubuntu 24.04 (OpenSSH 9.6,
systemd 255, cgroup v2, kernel 6.8), across interactive shells, remote
commands, and the sftp subsystem, and across `nohup`/`setsid`/double-fork. If a
supported OpenSSH version breaks the correlation, the fallback is to record the
connection 4-tuple at admission and match it at attach; the parent-pid scheme
is preferred because it needs nothing from the visitor side.

## 4. Admission ordering (no race with closing)

A grant on this host is `open`, `closing`, or `closed`. Admission is refused
for any non-open grant, and the state is flipped to `closing` **before** any
task is signalled, so a group that is being torn down cannot accept a new
session. Both `Admit` and `Attach` re-check the signer, and `Attach` re-checks
the host state under lock after the scope is created; a grant that closed while
a session was attaching refuses the session, and the scope — already inside the
slice — is covered by the same termination. Admission is closed entirely until
reconciliation has succeeded after a restart.

## 5. The supervisor

- Runs under a privileged service identity (`root`) separate from the visitor.
  Its binary, unit, socket, and state are unwritable by visitors (root-owned;
  socket dir `2750 root:grantadmit`; state on `/run`).
- Authenticates every local caller by `SO_PEERCRED` and `/proc` parentage.
  `principals` must come from `grantadmit`; `attach` must come from root. It
  accepts no pid, cgroup path, command, or deadline from a caller.
- Uses systemd and cgroup lifecycle as the enforcement authority — transient
  scopes and `cgroup.kill`/`cgroup.events` — never journal parsing or
  process-name matching.
- Reconciles after a restart: it blocks admission until the signer is
  reachable, adopts grant slices the signer still vouches for, recomputes their
  deadlines from the signer's authoritative `expires_at`, and terminates any
  grant slice whose authority it cannot confirm.
- Does not let its own failure leave execution unbounded: every session scope
  carries an independent `RuntimeMaxSec` backstop (remaining lifetime plus
  slack), so systemd ends the session at the deadline even if the warden is
  gone. `/run` is a tmpfs, so a reboot ends every session regardless.
- Applies visitor resource limits on the parent `grantd.slice`
  (`MemoryMax`, `TasksMax`, `CPUQuota`) so memory, process-count, or CPU
  exhaustion by one grant cannot deny the host or the supervisor. Disk is
  accounted separately and is out of scope for v1 (documented).

## 6. Expiry and revocation

- The host's authoritative deadline is the signer's `expires_at`. Reconnecting
  under the same certificate joins the existing grant deadline and containment;
  it does not extend anything.
- Admission is closed before the group is terminated.
- Termination empties the whole subtree: `SIGTERM`, then `cgroup.kill` after
  the grace period, which is atomic over the subtree and covers nested cgroups
  and tasks forked during teardown. The warden verifies the group is empty
  (`cgroup.events` `populated 0`) before reporting cleanup complete, and
  retries — reporting the remaining pids — for tasks in uninterruptible sleep.
- Deadlines are enforced on the monotonic clock as well as the wall clock, so a
  wall-clock change cannot silently extend a lifetime.
- Operator sessions and other grants are never in the termination target: only
  the one grant's slice is emptied.
- Documented latencies: deadline enforcement within ~1s of the deadline;
  revocation within the poll interval (default 2s) plus the grace period; the
  systemd backstop at the deadline plus slack.

## 7. Installation and compatibility

- Detect cgroup v2 with `cgroup.kill` (kernel ≥ 5.14), systemd ≥ 244, and the
  OpenSSH capabilities the hooks need. Refuse enforcement mode on a host that
  lacks them; never silently fall back to the old reaper.
- A dedicated enrolled visitor account remains an installation requirement, as
  before (`--ssh-user`, non-root). Cross-grant interference when grants share
  one Unix uid is bounded per grant by the cgroup, but shared credentials and
  files are not; this is documented as a limitation, and one uid per grant is
  not attempted in v1.
- Validate sshd configuration (`sshd -t`) before reload, preserve operator
  access, and keep installation and rollback transactional, exactly as the
  installer already does.
- Service restart and reboot restore enforcement safely: units are enabled,
  the warden reconciles before admitting, and `/run` state is rebuilt.

## 8. Certificate expiry vs. execution expiry vs. persistent effects

The documentation distinguishes three things, and promises only the first two:

1. **Certificate expiry** prevents new authentication with that certificate.
2. **Execution expiry** terminates every task inside the grant's containment
   boundary at the deadline or on revocation.
3. **Persistent effects** — file changes, disclosed secrets, external actions —
   are outside the expiry guarantee and remain after it.
