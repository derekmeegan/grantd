# A realistic grantd host: real sshd, real user separation, real process split.
# The point of this image is that the end-to-end test proves an actual SSH
# login, not a certificate that merely parses.
FROM debian:bookworm-slim

# The build environment here blocks outbound port 80, so apt is pointed at
# HTTPS. debian:bookworm-slim ships no CA bundle, so TLS peer verification has
# to be relaxed for the bootstrap fetch only — package *authenticity* is still
# enforced the whole time by the Debian archive's GPG signatures, which is the
# property that actually matters. The override is removed as soon as
# ca-certificates is installed.
RUN rm -f /etc/apt/sources.list.d/debian.sources \
 && printf 'deb https://deb.debian.org/debian bookworm main\ndeb https://deb.debian.org/debian bookworm-updates main\ndeb https://deb.debian.org/debian-security bookworm-security main\n' > /etc/apt/sources.list \
 && echo 'Acquire::https::Verify-Peer "false";' > /etc/apt/apt.conf.d/99grantd-bootstrap \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      openssh-server openssh-client ca-certificates curl jq util-linux procps \
      python3 coreutils \
 && rm -f /etc/apt/apt.conf.d/99grantd-bootstrap \
 && rm -rf /var/lib/apt/lists/*

# Three accounts, three jobs:
#   ubuntu       the login account a visiting agent gets, and the grant owner
#   grantd       the network-facing daemon; holds no key material at all
#   grantsigner  the trust root; owns the keys, has no reason to touch a socket
RUN useradd -m -s /bin/bash ubuntu \
 && useradd -r -M -s /usr/sbin/nologin grantd \
 && useradd -r -M -s /usr/sbin/nologin grantsigner

# Only the two daemons are installed. There is deliberately no grantd client
# binary here: the owner mints grants with curl over a Unix socket, and a
# visitor redeems with install/redeem.sh, which is curl, openssl and ssh-keygen.
# If those paths work, the "no SDK required" claim is true rather than asserted.
COPY grantd grant-signer /usr/local/bin/
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY redeem.sh cbe-vectors.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/grantd /usr/local/bin/grant-signer \
      /usr/local/bin/redeem.sh /usr/local/bin/cbe-vectors.sh /usr/local/bin/entrypoint.sh

EXPOSE 22
CMD ["/usr/local/bin/entrypoint.sh"]
