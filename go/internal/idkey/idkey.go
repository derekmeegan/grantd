// Package idkey handles on-disk Ed25519 key material for the signer process.
//
// Every function here refuses to touch a key file whose permissions would let
// another account read it. That check is not decoration: the security argument
// for the whole product is that the network-facing daemon cannot read these
// bytes, and file mode is what enforces it.
package idkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

const (
	pemTypePrivate = "GRANTD PRIVATE KEY"
	// KeyFileMode is the only mode a private key file may have.
	KeyFileMode os.FileMode = 0o600
	// KeyDirMode is the only mode a key directory may have.
	KeyDirMode os.FileMode = 0o700
)

// Generate creates a fresh Ed25519 keypair.
func Generate() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// SavePrivate writes a private key with 0600 permissions, refusing to clobber
// an existing file.
func SavePrivate(path string, key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("idkey: bad private key size %d", len(key))
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("idkey: refusing to overwrite existing key at %s", path)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), KeyDirMode); err != nil {
		return err
	}
	block := &pem.Block{Type: pemTypePrivate, Bytes: key.Seed()}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, KeyFileMode)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := pem.Encode(f, block); err != nil {
		return err
	}
	return f.Sync()
}

// LoadPrivate reads a private key, first verifying that its mode is 0600.
func LoadPrivate(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("idkey: %s has mode %04o; private keys must not be group- or world-accessible", path, perm)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != pemTypePrivate {
		return nil, fmt.Errorf("idkey: %s is not a grantd private key", path)
	}
	if len(block.Bytes) != ed25519.SeedSize {
		return nil, fmt.Errorf("idkey: %s has a %d-byte seed, want %d", path, len(block.Bytes), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(block.Bytes), nil
}

// SavePublicSSH writes an Ed25519 public key in authorized_keys form, which is
// what sshd's TrustedUserCAKeys expects.
func SavePublicSSH(path string, pub ed25519.PublicKey, comment string) error {
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return err
	}
	line := string(ssh.MarshalAuthorizedKey(sshPub))
	if comment != "" {
		line = line[:len(line)-1] + " " + comment + "\n"
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(line), 0o644)
}

// PublicSSHLine renders an Ed25519 public key as a two-field authorized_keys
// line with no comment, which is the exact form the protocol signs.
func PublicSSHLine(pub ed25519.PublicKey) (string, error) {
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", err
	}
	line := string(ssh.MarshalAuthorizedKey(sshPub))
	return line[:len(line)-1], nil
}
