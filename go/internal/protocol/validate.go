package protocol

import (
	"fmt"
	"regexp"
	"strings"
)

// usernameRe is the conservative subset of POSIX login names v1 will enroll.
var usernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// hostnameRe accepts DNS names and bare IPv4/IPv6 literals.
var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9._:\[\]-]{1,253}$`)

// ValidateSSHUser enforces the v1 rules for the login account. root is
// rejected because the enrolled account bounds what a visitor can do.
func ValidateSSHUser(u string) error {
	if u == "" {
		return fmt.Errorf("ssh_user is required")
	}
	if len(u) > MaxUsernameBytes {
		return fmt.Errorf("ssh_user exceeds %d bytes", MaxUsernameBytes)
	}
	if !usernameRe.MatchString(u) {
		return fmt.Errorf("ssh_user %q is not a valid login name", u)
	}
	if u == "root" {
		return fmt.Errorf("refusing to enroll root; choose an unprivileged account")
	}
	return nil
}

// ValidateHostname checks the address a visiting agent will dial.
func ValidateHostname(h string) error {
	if h == "" {
		return fmt.Errorf("hostname is required")
	}
	if len(h) > MaxHostnameBytes {
		return fmt.Errorf("hostname exceeds %d bytes", MaxHostnameBytes)
	}
	if !hostnameRe.MatchString(h) || strings.Contains(h, "..") {
		return fmt.Errorf("hostname %q is not a valid address", h)
	}
	return nil
}

// dnsSuffixRe is the suffix this client will build a host name under. It
// mirrors SUFFIX_RE in cloudflare/src/dns.ts: the two implementations must
// agree, or a host signs a name the service will not write.
var dnsSuffixRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// hostLabelRe is the base32 label a host id carries after its "h_" prefix.
var hostLabelRe = regexp.MustCompile(`^[a-z2-7]{32}$`)

// ValidateDNSSuffix checks a suffix host names may be built under.
func ValidateDNSSuffix(s string) error {
	if s == "" {
		return fmt.Errorf("dns suffix is required")
	}
	if !dnsSuffixRe.MatchString(strings.ToLower(s)) {
		return fmt.Errorf("dns suffix %q is not a valid domain name", s)
	}
	return nil
}

// HostDNSName derives the one name the coordination service will publish for
// a host. It is a pure function of the host id, which is a hash of the host's
// identity key, so a host cannot ask for any other name. This must match
// hostRecordName() in cloudflare/src/dns.ts.
func HostDNSName(hostID, suffix string) (string, error) {
	if err := ValidateDNSSuffix(suffix); err != nil {
		return "", err
	}
	label, ok := strings.CutPrefix(hostID, "h_")
	if !ok || !hostLabelRe.MatchString(label) {
		return "", fmt.Errorf("host id %q is malformed", hostID)
	}
	name := label + "." + strings.ToLower(suffix)
	if err := ValidateHostname(name); err != nil {
		return "", err
	}
	return name, nil
}

// ValidatePort checks an SSH port.
func ValidatePort(p uint64) error {
	if p == 0 || p > 65535 {
		return fmt.Errorf("ssh_port %d out of range", p)
	}
	return nil
}

// ValidateGrantWindow enforces the TTL bounds on a grant.
func ValidateGrantWindow(createdAt, expiresAt int64) error {
	if expiresAt <= createdAt {
		return fmt.Errorf("expires_at must be after created_at")
	}
	ttl := expiresAt - createdAt
	if ttl < MinGrantTTLSeconds {
		return fmt.Errorf("grant ttl %ds is below the %ds minimum", ttl, MinGrantTTLSeconds)
	}
	if ttl > MaxGrantTTLSeconds {
		return fmt.Errorf("grant ttl %ds exceeds the %ds maximum", ttl, MaxGrantTTLSeconds)
	}
	return nil
}

// WithinSkew reports whether a timestamp is inside the allowed window.
func WithinSkew(now, ts, skew int64) bool {
	d := now - ts
	if d < 0 {
		d = -d
	}
	return d <= skew
}
