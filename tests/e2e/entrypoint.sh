#!/bin/bash
# Brings up a grantd host the way the installer does: keys owned by the signer
# account, sshd trusting the generated CA, and the daemon running unprivileged.
set -euo pipefail

# Two origins, because they are different things:
#   ORIGIN         where this machine dials out to reach the service
#   PUBLIC_ORIGIN  what a capability URL says, i.e. where the recipient goes
# In production they are the same string. Behind NAT or in a container they
# are not, and a URL with the machine's own view of the service is a link
# only this machine can follow.
ORIGIN="${GRANTD_ORIGIN:?GRANTD_ORIGIN is required}"
PUBLIC_ORIGIN="${GRANTD_PUBLIC_ORIGIN:-$ORIGIN}"
SSH_USER="${GRANTD_SSH_USER:-ubuntu}"
export GRANTD_OWNER_SOCK=/run/grantd/owner/owner.sock
ADVERTISE_HOST="${GRANTD_ADVERTISE_HOST:-127.0.0.1}"
ADVERTISE_PORT="${GRANTD_ADVERTISE_PORT:-2222}"

install -d -m 0700 -o grantsigner -g grantsigner /etc/grantd
install -d -m 0700 -o grantsigner -g grantsigner /var/lib/grant-signer
install -d -m 0755 -o root -g root /run/grantd
install -d -m 0755 /run/sshd

# Each socket lives in its own setgid directory. The kernel assigns the
# directory's group to the socket at creation, so the unprivileged signer
# never needs chown and is not a member of either group.
#
# The directory group also gates traversal. That is two independent gates:
# the directory, and the socket's own 0660 mode. The SO_PEERCRED uid check in
# the signer is a third.
install -d -m 2770 -o grantsigner -g "$SSH_USER" /run/grantd/owner
install -d -m 2770 -o grantsigner -g grantd /run/grantd/redeem

echo "==> enrolling"
setpriv --reuid=grantsigner --regid=grantsigner --clear-groups \
  /usr/local/bin/grant-signer init \
    --ssh-user "$SSH_USER" \
    --hostname "$ADVERTISE_HOST" \
    --port "$ADVERTISE_PORT" \
    --origin "$PUBLIC_ORIGIN"

# sshd must read the CA public key, and /etc/grantd is 0700 to the signer.
# Copy the public half out instead of loosening the directory.
install -m 0644 -o root -g root /etc/grantd/ssh_ca.pub /etc/ssh/grantd_user_ca.pub

cat > /etc/ssh/sshd_config.d/60-grantd.conf <<'CONF'
# Managed by grantd. Trust certificates issued by this host's own CA.
TrustedUserCAKeys /etc/ssh/grantd_user_ca.pub
CONF

echo "==> validating sshd configuration"
# Never reload sshd on a configuration that does not parse.
ssh-keygen -A >/dev/null
/usr/sbin/sshd -t

echo "==> starting sshd"
/usr/sbin/sshd -D -e &
SSHD_PID=$!

echo "==> starting signer"
setpriv --reuid=grantsigner --regid=grantsigner --clear-groups \
  /usr/local/bin/grant-signer serve \
    --owner-sock /run/grantd/owner/owner.sock \
    --daemon-sock /run/grantd/redeem/redeem.sock \
    --owner-uid "$(id -u "$SSH_USER")" \
    --owner-gid "$(getent group "$SSH_USER" | cut -d: -f3)" \
    --daemon-uid "$(id -u grantd)" \
    --daemon-gid "$(getent group grantd | cut -d: -f3)" &
SIGNER_PID=$!

for _ in $(seq 1 50); do
  [ -S /run/grantd/redeem/redeem.sock ] && break
  sleep 0.2
done

echo "==> socket permissions"
ls -ln /run/grantd/owner /run/grantd/redeem

echo "==> starting daemon"
setpriv --reuid=grantd --regid=grantd --clear-groups \
  /usr/local/bin/grantd --origin "$ORIGIN" \
    --signer-sock /run/grantd/redeem/redeem.sock &
DAEMON_PID=$!

echo "==> ready"
wait -n "$SSHD_PID" "$SIGNER_PID" "$DAEMON_PID"
