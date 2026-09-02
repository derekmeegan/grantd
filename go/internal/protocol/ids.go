// Package protocol implements the grantd v1 wire protocol: identifiers,
// canonical messages, and the JSON envelopes that carry them. protocol/v1.md
// defines every byte, and protocol/test-vectors/ is the conformance suite.
package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
)

// Version is the only protocol version this implementation speaks.
const Version uint64 = 1

// Clock skew windows, in seconds (protocol/v1.md §2).
const (
	SkewRegistration int64 = 300
	SkewRedemption   int64 = 120
)

// Grant duration bounds (protocol/v1.md §4.3).
const (
	MinGrantTTLSeconds int64 = 60
	MaxGrantTTLSeconds int64 = 8 * 3600
	DefaultGrantTTL    int64 = 30 * 60
)

// NonceLen is the required length of every protocol nonce.
const NonceLen = 16

// SecretLen is the length of a grant secret in bytes.
const SecretLen = 32

// b32 is RFC 4648 base32 with the lowercase alphabet and no padding.
var b32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// B64 is base64url without padding, the only binary-in-JSON encoding v1 uses.
var B64 = base64.RawURLEncoding

var (
	hostIDRe  = regexp.MustCompile(`^h_[a-z2-7]{32}$`)
	agentIDRe = regexp.MustCompile(`^a_[a-z2-7]{32}$`)
	grantIDRe = regexp.MustCompile(`^g_[a-z2-7]{16}$`)
)

var (
	ErrBadPublicKey = errors.New("protocol: public key must be 32 raw ed25519 bytes")
	ErrIDMismatch   = errors.New("protocol: identifier does not match public key")
	ErrBadID        = errors.New("protocol: malformed identifier")
	ErrBadNonce     = errors.New("protocol: nonce must be 16 bytes")
)

// idMaterial is the first 20 bytes of SHA-256 over the raw public key. Those
// 20 bytes encode to exactly 32 base32 characters.
func idMaterial(pub ed25519.PublicKey) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, ErrBadPublicKey
	}
	sum := sha256.Sum256(pub)
	return sum[:20], nil
}

// HostID derives the self-certifying host identifier from a host identity
// public key.
func HostID(pub ed25519.PublicKey) (string, error) {
	m, err := idMaterial(pub)
	if err != nil {
		return "", err
	}
	return "h_" + b32.EncodeToString(m), nil
}

// AgentID derives the self-certifying agent identifier from an agent identity
// public key.
func AgentID(pub ed25519.PublicKey) (string, error) {
	m, err := idMaterial(pub)
	if err != nil {
		return "", err
	}
	return "a_" + b32.EncodeToString(m), nil
}

// CheckHostID makes sure that a claimed host_id is the ID of pub. Callers
// must do this before they trust any other field of a message.
func CheckHostID(id string, pub ed25519.PublicKey) error {
	want, err := HostID(pub)
	if err != nil {
		return err
	}
	if id != want {
		return ErrIDMismatch
	}
	return nil
}

// CheckAgentID makes sure that a claimed agent_id is the ID of pub.
func CheckAgentID(id string, pub ed25519.PublicKey) error {
	want, err := AgentID(pub)
	if err != nil {
		return err
	}
	if id != want {
		return ErrIDMismatch
	}
	return nil
}

// ValidHostID reports whether s is syntactically a host identifier.
func ValidHostID(s string) bool { return hostIDRe.MatchString(s) }

// ValidAgentID reports whether s is syntactically an agent identifier.
func ValidAgentID(s string) bool { return agentIDRe.MatchString(s) }

// ValidGrantID reports whether s is syntactically a grant identifier.
func ValidGrantID(s string) bool { return grantIDRe.MatchString(s) }

// NewGrantID returns a fresh random grant identifier.
func NewGrantID() (string, error) {
	var raw [10]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("protocol: grant id: %w", err)
	}
	return "g_" + b32.EncodeToString(raw[:]), nil
}

// NewGrantSecret returns a fresh 32-byte capability secret.
func NewGrantSecret() ([]byte, error) {
	s := make([]byte, SecretLen)
	if _, err := rand.Read(s); err != nil {
		return nil, fmt.Errorf("protocol: grant secret: %w", err)
	}
	return s, nil
}

// NewNonce returns a fresh 16-byte protocol nonce.
func NewNonce() ([]byte, error) {
	n := make([]byte, NonceLen)
	if _, err := rand.Read(n); err != nil {
		return nil, fmt.Errorf("protocol: nonce: %w", err)
	}
	return n, nil
}

// EncodeSecret renders a grant secret for the capability URL fragment.
func EncodeSecret(secret []byte) string { return B64.EncodeToString(secret) }

// DecodeSecret parses a capability URL fragment back into raw secret bytes.
func DecodeSecret(s string) ([]byte, error) {
	raw, err := B64.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("protocol: malformed secret: %w", err)
	}
	if len(raw) != SecretLen {
		return nil, fmt.Errorf("protocol: secret must be %d bytes, got %d", SecretLen, len(raw))
	}
	return raw, nil
}

// CapabilityURL builds the capability URL. The secret goes in the fragment,
// which HTTP clients do not send to the server.
func CapabilityURL(origin, hostID, grantID string, secret []byte) string {
	return fmt.Sprintf("%s/g/%s/%s#%s", origin, hostID, grantID, EncodeSecret(secret))
}
