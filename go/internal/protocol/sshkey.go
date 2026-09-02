package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

var (
	ErrSSHKeyFormat = errors.New("protocol: ssh public key must be exactly \"<type> <base64>\"")
	ErrSSHKeyType   = errors.New("protocol: only ssh-ed25519 public keys are accepted in v1")
	ErrSSHKeyLarge  = errors.New("protocol: ssh public key exceeds size limit")
)

// ParseSSHPublicKey parses an authorized_keys line under the strict v1 rules:
// exactly two space-separated fields, ssh-ed25519 only, no comment, no
// options, no extra whitespace.
//
// The line is not normalized. The MAC covers the exact bytes, so a variant
// that is "close enough" must be rejected.
func ParseSSHPublicKey(line string) (ssh.PublicKey, error) {
	if len(line) > MaxSSHPubKeyBytes {
		return nil, ErrSSHKeyLarge
	}
	if line != strings.TrimSpace(line) {
		return nil, ErrSSHKeyFormat
	}
	parts := strings.Split(line, " ")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, ErrSSHKeyFormat
	}
	if parts[0] != ssh.KeyAlgoED25519 {
		return nil, ErrSSHKeyType
	}
	blob, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("protocol: ssh public key body: %w", err)
	}
	key, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return nil, fmt.Errorf("protocol: ssh public key: %w", err)
	}
	if key.Type() != ssh.KeyAlgoED25519 {
		return nil, ErrSSHKeyType
	}
	// Reject non-canonical base64 and trailing bytes inside the blob.
	if base64.StdEncoding.EncodeToString(key.Marshal()) != parts[1] {
		return nil, ErrSSHKeyFormat
	}
	return key, nil
}

// SSHKeyFingerprint returns OpenSSH's SHA256:... fingerprint for a key line.
func SSHKeyFingerprint(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}
