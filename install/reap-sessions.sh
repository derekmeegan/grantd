#!/bin/sh
#
# Close visitor sessions whose grant has expired.
#
# A certificate's expiry stops a new connection: sshd checks validity when it
# authenticates. It does nothing to a session that is already open, which then
# runs for as long as it likes — the deadline bounded when the visitor could
# start, not when they had to stop. That gap is what "thirty minutes" is
# usually read as promising, so this closes it.
#
# It is deliberately narrow. It only ever signals a process that sshd logged as
# authenticating with a grantd certificate, and only when the signer says that
# grant is done. A session with no grantd certificate is never touched, so an
# operator's own root session cannot be caught by it.
set -eu

LIBDIR=/usr/local/lib/grantd
CONFDIR=/etc/grantd
STATE_DB=/var/lib/grant-signer/state.db
SSH_USER="${1:-}"
[ -n "$SSH_USER" ] || { echo "usage: reap-sessions.sh SSH_USER" >&2; exit 2; }

EXPIRED="$(runuser -u grantsigner -- "$LIBDIR/grant-signer" expired-grants \
             --key-dir "$CONFDIR" --state "$STATE_DB" 2>/dev/null)" || exit 0
[ -n "$EXPIRED" ] || exit 0

# sshd logs the certificate's key id at authentication:
#   Accepted publickey for USER from ... ID grantd:g_xxx:a_yyy (serial N) CA ...
# That is the only place a session's pid and its grant appear together.
LOG="$(journalctl -u ssh -u ssh.socket -u sshd --since "-24 hours" --no-pager 2>/dev/null \
        | grep "Accepted publickey for $SSH_USER " | grep "ID grantd:" || true)"
[ -n "$LOG" ] || exit 0

for grant in $EXPIRED; do
  # Every pid that authenticated under this grant.
  pids="$(printf '%s\n' "$LOG" | grep "ID grantd:$grant:" \
            | sed -n 's/.*sshd\[\([0-9]*\)\].*/\1/p' | sort -u)"
  for pid in $pids; do
    [ -d "/proc/$pid" ] || continue
    # Guard against pid reuse. The process must still be the sshd session it
    # was: same command, same visiting account. Without this a recycled pid
    # belonging to something else could be signalled.
    [ "$(cat "/proc/$pid/comm" 2>/dev/null || true)" = "sshd" ] || continue
    tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q "$SSH_USER" || continue

    logger -t grantd-reaper "closing session pid $pid: grant $grant has expired"
    kill -TERM "$pid" 2>/dev/null || true
  done
done
