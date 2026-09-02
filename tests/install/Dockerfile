# A machine with real systemd, so the installer is tested the way it runs for
# real: units enabled, sshd reloaded through systemctl, and the sandboxing
# directives in the unit files applied.
FROM debian:bookworm-slim

ENV container=docker
# The build environment blocks outbound port 80, so apt uses HTTPS. The base
# image ships no CA bundle, so peer verification is off for the bootstrap
# fetch only. Package authenticity is still enforced by the Debian archive's
# GPG signatures. The override is removed once ca-certificates is installed.
RUN rm -f /etc/apt/sources.list.d/debian.sources \
 && printf 'deb https://deb.debian.org/debian bookworm main\ndeb https://deb.debian.org/debian bookworm-updates main\ndeb https://deb.debian.org/debian-security bookworm-security main\n' > /etc/apt/sources.list \
 && echo 'Acquire::https::Verify-Peer "false";' > /etc/apt/apt.conf.d/99grantd-bootstrap \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      systemd systemd-sysv openssh-server openssh-client ca-certificates \
      curl jq util-linux procps sudo dbus python3 coreutils \
 && rm -f /etc/apt/apt.conf.d/99grantd-bootstrap \
 && rm -rf /var/lib/apt/lists/*

# The account a visiting agent lands on.
RUN useradd -m -s /bin/bash ubuntu

# The installer refuses to run unless sshd_config Includes sshd_config.d.
# Assert it here, so an upstream change cannot turn this test green for the
# wrong reason.
RUN grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config \
 && mkdir -p /etc/ssh/sshd_config.d

RUN systemctl enable ssh

# Remove the units systemd cannot run in a container.
RUN find /etc/systemd/system /lib/systemd/system -path '*.wants/*' \
      \( -name '*getty*' -o -name '*udev*' -o -name '*journald-audit*' \) \
      -exec rm -f {} + 2>/dev/null || true

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
