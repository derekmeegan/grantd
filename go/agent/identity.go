// Package agent implements the visiting side of grantd: the party that receives
// a capability URL and turns it into an SSH certificate.
//
// The agent's SSH private key is generated here and never leaves this process.
// The coordination service sees only the public half, and even that it cannot
// substitute, because the public half is covered by the grant MAC.
package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/derekmeegan/grantd/go/internal/idkey"
	"github.com/derekmeegan/grantd/go/internal/protocol"
	"golang.org/x/crypto/ssh"
)

// Identity is the agent's long-lived protocol identity. It is not a credential
// for any host: it exists so that redemptions can be attributed and rate
// limited, not so that they can be authorized.
type Identity struct {
	Key ed25519.PrivateKey
	ID  string
}

// NewIdentity generates a fresh agent identity.
func NewIdentity() (*Identity, error) {
	pub, priv, err := idkey.Generate()
	if err != nil {
		return nil, err
	}
	id, err := protocol.AgentID(pub)
	if err != nil {
		return nil, err
	}
	return &Identity{Key: priv, ID: id}, nil
}

// LoadIdentity reads an identity from disk, or generates and saves one if the
// file does not exist.
func LoadIdentity(path string) (*Identity, error) {
	key, err := idkey.LoadPrivate(path)
	if os.IsNotExist(err) {
		ident, gerr := NewIdentity()
		if gerr != nil {
			return nil, gerr
		}
		if serr := idkey.SavePrivate(path, ident.Key); serr != nil {
			return nil, serr
		}
		return ident, nil
	}
	if err != nil {
		return nil, err
	}
	id, err := protocol.AgentID(key.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	return &Identity{Key: key, ID: id}, nil
}

// PublicKey returns the raw identity public key.
func (i *Identity) PublicKey() ed25519.PublicKey { return i.Key.Public().(ed25519.PublicKey) }

// Sign produces an Ed25519 signature over canonical bytes.
func (i *Identity) Sign(msg []byte) []byte { return ed25519.Sign(i.Key, msg) }

// ------------------------------------------------------------- capability URL

// Capability is a parsed capability URL.
type Capability struct {
	Origin  string
	HostID  string
	GrantID string
	Secret  []byte
}

// ParseCapabilityURL splits a capability URL into its parts.
//
// The secret lives in the fragment precisely so that it is never sent to the
// coordination service; parsing it here, on the agent's own machine, is the
// only place it is ever read from the URL.
func ParseCapabilityURL(raw string) (Capability, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Capability{}, fmt.Errorf("agent: malformed capability url: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return Capability{}, fmt.Errorf("agent: capability url must be http(s)")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 3 || parts[0] != "g" {
		return Capability{}, fmt.Errorf("agent: capability url path must be /g/<host_id>/<grant_id>")
	}
	hostID, grantID := parts[1], parts[2]
	if !protocol.ValidHostID(hostID) {
		return Capability{}, fmt.Errorf("agent: malformed host id in capability url")
	}
	if !protocol.ValidGrantID(grantID) {
		return Capability{}, fmt.Errorf("agent: malformed grant id in capability url")
	}
	if u.Fragment == "" {
		return Capability{}, fmt.Errorf("agent: capability url has no secret fragment")
	}
	secret, err := protocol.DecodeSecret(u.Fragment)
	if err != nil {
		return Capability{}, err
	}
	origin := u.Scheme + "://" + u.Host
	return Capability{Origin: origin, HostID: hostID, GrantID: grantID, Secret: secret}, nil
}

// ------------------------------------------------------------------- SSH keys

// EphemeralSSHKey is a throwaway SSH keypair created for exactly one visit.
type EphemeralSSHKey struct {
	Private   ed25519.PrivateKey
	PublicSSH ssh.PublicKey
	// Line is the exact authorized_keys text that the redemption MAC covers.
	Line string
}

// NewEphemeralSSHKey generates the key the certificate will be issued over.
func NewEphemeralSSHKey() (*EphemeralSSHKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	return &EphemeralSSHKey{Private: priv, PublicSSH: sshPub, Line: line}, nil
}

// WriteOpenSSH writes the private key in OpenSSH format alongside its public
// key, with the permissions ssh(1) insists on.
func (k *EphemeralSSHKey) WriteOpenSSH(path string) error {
	block, err := ssh.MarshalPrivateKey(k.Private, "grantd ephemeral")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return err
	}
	return os.WriteFile(path+".pub", []byte(k.Line+"\n"), 0o644)
}

// Fingerprint returns the OpenSSH SHA256 fingerprint of the ephemeral key.
func (k *EphemeralSSHKey) Fingerprint() string { return protocol.SSHKeyFingerprint(k.PublicSSH) }

// ----------------------------------------------------------- proof of work

// SolvePow finds a nonce whose SHA-256 with the challenge prefix has at least
// difficultyBits leading zero bits.
//
// This is the part of Agent Captcha that actually costs an attacker something:
// a single registration is a second of CPU, a million of them are not.
func SolvePow(prefix []byte, difficultyBits int) (string, error) {
	if difficultyBits < 0 || difficultyBits > 32 {
		return "", fmt.Errorf("agent: unreasonable pow difficulty %d", difficultyBits)
	}
	var counter uint64
	buf := make([]byte, 0, len(prefix)+24)
	for {
		nonce := fmt.Sprintf("%d", counter)
		buf = buf[:0]
		buf = append(buf, prefix...)
		buf = append(buf, nonce...)
		if leadingZeroBits(sha256.Sum256(buf)) >= difficultyBits {
			return nonce, nil
		}
		counter++
		if counter > 1<<34 {
			return "", fmt.Errorf("agent: gave up solving proof of work")
		}
	}
}

// VerifyPow checks a proof-of-work solution.
func VerifyPow(prefix []byte, difficultyBits int, nonce string) bool {
	if len(nonce) == 0 || len(nonce) > protocol.MaxPowNonceBytes {
		return false
	}
	buf := append(append([]byte{}, prefix...), nonce...)
	return leadingZeroBits(sha256.Sum256(buf)) >= difficultyBits
}

func leadingZeroBits(sum [32]byte) int {
	hi := binary.BigEndian.Uint64(sum[:8])
	if hi == 0 {
		return 64
	}
	n := 0
	for i := 63; i >= 0; i-- {
		if hi&(1<<uint(i)) != 0 {
			break
		}
		n++
	}
	return n
}
