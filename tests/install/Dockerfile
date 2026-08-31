# A machine with real systemd, so the installer is tested the way it will
# actually run: units enabled, sshd reloaded through systemctl, and the
# sandboxing directives in the unit files actually applied.
FROM debian:bookworm-slim

ENV container=docker
RUN rm -f /etc/apt/sources.list.d/debian.sources \
 && printf 'deb https://deb.debian.org/debian bookworm main\ndeb https://deb.debian.org/debian bookworm-updates main\ndeb https://deb.debian.org/debian-security bookworm-security main\n' > /etc/apt/sources.list \
 && echo 'Acquire::https::Verify-Peer "false";' > /etc/apt/apt.conf.d/99grantd-bootstrap \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      systemd systemd-sysv openssh-server openssh-client ca-certificates \
      curl jq util-linux procps sudo dbus \
 && rm -f /etc/apt/apt.conf.d/99grantd-bootstrap \
 && rm -rf /var/lib/apt/lists/*

# The account a visiting agent will land on.
RUN useradd -m -s /bin/bash ubuntu

# Debian's sshd_config already Includes sshd_config.d; assert it, because the
# installer refuses to run without it and a silent change upstream would turn
# this test green for the wrong reason.
RUN grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config \
 && mkdir -p /etc/ssh/sshd_config.d

RUN systemctl enable ssh

# Strip the units systemd cannot run in a container.
RUN find /etc/systemd/system /lib/systemd/system -path '*.wants/*' \
      \( -name '*getty*' -o -name '*udev*' -o -name '*journald-audit*' \) \
      -exec rm -f {} + 2>/dev/null || true

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
