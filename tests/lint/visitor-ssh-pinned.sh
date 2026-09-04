#!/bin/sh
# Fail if any visitor SSH invocation disables host key checking.
#
# A visiting agent verifies the host's signed record and pins the ssh host key
# it names. That is the only thing standing between the agent and a coordination
# service that would rather send it to a machine of its own — so an invocation
# that carries a grantd certificate *and* turns host key checking off has undone
# the entire mechanism, quietly, in one flag.
#
# It is an easy flag to reach for. It is what every one of these call sites used
# before host keys were published, because without a known_hosts entry ssh has
# nothing to compare against and stops to ask, which for an agent with no
# terminal reads as a hang. The fix is a pinned known_hosts, not a disabled
# check, and this script is what keeps the fix from being quietly reverted.
#
# The marker is CertificateFile=: that is what makes an invocation a *visitor*.
# Test scaffolding that reaches a machine some other way — provisioning a
# droplet, probing sshd as root before grantd is installed — is not a visitor
# and is deliberately left alone.
set -eu

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO"

TARGETS="tests install .github cloudflare/src/routes/docs.ts README.md protocol/v1.md"

fail=0
report() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; fail=1; }

# Shell and YAML wrap long ssh commands across continuation lines, so the lines
# are joined before matching: the certificate and the flag that undoes it are
# almost never on the same physical line.
scan() {
  find $TARGETS -type f \
    \( -name '*.sh' -o -name '*.yml' -o -name '*.yaml' -o -name '*.ts' -o -name '*.md' -o -name 'Dockerfile' \) \
    -not -path './tests/lint/*' -print 2>/dev/null | while read -r f; do
    # Join backslash continuations, then emit one logical line at a time with
    # its file name, so a match can be reported usefully.
    sed -e ':a' -e '/\\$/{N;s/\\\n//;ba' -e '}' "$f" | while IFS= read -r line; do
      case "$line" in
        *CertificateFile=*)
          case "$line" in
            *StrictHostKeyChecking=no*)
              report "$f: a grantd certificate is used with StrictHostKeyChecking=no"
              ;;
          esac
          case "$line" in
            *UserKnownHostsFile=/dev/null*)
              report "$f: a grantd certificate is used with UserKnownHostsFile=/dev/null"
              ;;
          esac
          ;;
      esac
    done
  done
}

# The subshell in the pipeline cannot set `fail` in the parent, so violations are
# counted from the output instead.
out="$(scan)"
if [ -n "$out" ]; then
  printf 'visitor ssh invocations must pin the host key:\n\n%s\n\n' "$out"
  printf 'Use the options install/redeem.sh prints:\n'
  printf '  -o UserKnownHostsFile=<dir>/known_hosts -o StrictHostKeyChecking=yes \\\n'
  printf '  -o HostKeyAlias=<host_id> -o HostKeyAlgorithms=ssh-ed25519\n'
  exit 1
fi

printf 'ok   every visitor ssh invocation pins the host key\n'
