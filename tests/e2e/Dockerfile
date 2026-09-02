# A realistic grantd host: real sshd, real user separation, real process
# split. The end-to-end test proves an actual SSH login, not a certificate
# that merely parses.
FROM debian:bookworm-slim

# The build environment blocks outbound port 80, so apt uses HTTPS. The base
# image ships no CA bundle, so peer verification is off for the bootstrap
# fetch only. Package authenticity is still enforced by the Debian archive's
# GPG signatures. The override is removed once ca-certificates is installed.
RUN rm -f /etc/apt/sources.list.d/debian.sources \
 && printf 'deb https://deb.debian.org/debian bookworm main\ndeb https://deb.debian.org/debian bookworm-updates main\ndeb https://deb.debian.org/debian-security bookworm-security main\n' > /etc/apt/sources.list \
 && echo 'Acquire::https::Verify-Peer "false";' > /etc/apt/apt.conf.d/99grantd-bootstrap \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      openssh-server openssh-client ca-certificates curl jq util-linux procps \
      python3 coreutils \
      gawk \
 && rm -f /etc/apt/apt.conf.d/99grantd-bootstrap \
 && rm -rf /var/lib/apt/lists/*

# Three accounts, three jobs:
#   ubuntu       the login account a visiting agent gets, and the grant owner
#   grantd       the network-facing daemon, which holds no key material
#   grantsigner  the trust root, which owns the keys
RUN useradd -m -s /bin/bash ubuntu \
 && useradd -r -M -s /usr/sbin/nologin grantd \
 && useradd -r -M -s /usr/sbin/nologin grantsigner

# gawk on purpose. Debian defaults to mawk, which is byte-oriented and hides
# a bug that appears on Ubuntu. GNU awk in a UTF-8 locale treats printf "%c"
# as a character, so byte 0xff becomes two bytes. With gawk, the container
# suite exercises the same awk the VM does.

# Only the two daemons are installed. There is no grantd client binary. The
# owner mints grants with curl over a Unix socket, and a visitor redeems with
# install/redeem.sh. If those paths work, the "no SDK required" claim holds.
COPY grantd grant-signer /usr/local/bin/
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY redeem.sh cbe-vectors.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/grantd /usr/local/bin/grant-signer \
      /usr/local/bin/redeem.sh /usr/local/bin/cbe-vectors.sh /usr/local/bin/entrypoint.sh

EXPOSE 22
CMD ["/usr/local/bin/entrypoint.sh"]
