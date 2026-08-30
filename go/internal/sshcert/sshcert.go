// Package sshcert issues the short-lived OpenSSH user certificates that are the
// entire output of the system. Nothing here talks to the network; it runs only
// inside the signer process, which is the only process that can read the CA key.
package sshcert

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// ClockSkewBackdate is how far before "now" a certificate becomes valid, so
// that a host clock slightly ahead of the agent's does not produce a cert that
// is not yet valid at the moment it is used.
const ClockSkewBackdate = 30 * time.Second

// Request describes the certificate to issue. Note what is absent: the caller
// cannot choose the principal. It is supplied by the signer from its own
// enrollment record, never from the redemption request.
type Request struct {
	PublicKey ssh.PublicKey // the visiting agent's ephemeral key
	Principal string        // the enrolled ssh_user
	GrantID   string
	AgentID   string
	Serial    uint64
	ValidFrom time.Time
	ValidTo   time.Time
}

// NewSerial returns a random non-zero certificate serial.
func NewSerial() (uint64, error) {
	var b [8]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, fmt.Errorf("sshcert: serial: %w", err)
		}
		if v := binary.BigEndian.Uint64(b[:]); v != 0 {
			return v, nil
		}
	}
}

// KeyID is the certificate's human-readable audit label. It ties a live SSH
// session in the sshd log back to the exact grant and agent that produced it.
func KeyID(grantID, agentID string) string {
	return fmt.Sprintf("grantd:%s:%s", grantID, agentID)
}

// Issue signs a user certificate with the host's SSH CA.
//
// The extension set is deliberately minimal: an interactive shell, and nothing
// that turns the visiting agent's session into a network tunnel. V1 makes no
// claim to restrict what commands run inside that shell, but it does not have
// to hand out port forwarding to deliver a shell.
func Issue(ca ed25519.PrivateKey, req Request) (*ssh.Certificate, error) {
	if req.PublicKey == nil {
		return nil, fmt.Errorf("sshcert: missing public key")
	}
	if req.Principal == "" {
		return nil, fmt.Errorf("sshcert: missing principal")
	}
	if req.Principal == "root" {
		return nil, fmt.Errorf("sshcert: refusing to issue a certificate for root")
	}
	if !req.ValidTo.After(req.ValidFrom) {
		return nil, fmt.Errorf("sshcert: validity window is empty")
	}

	cert := &ssh.Certificate{
		Key:             req.PublicKey,
		Serial:          req.Serial,
		CertType:        ssh.UserCert,
		KeyId:           KeyID(req.GrantID, req.AgentID),
		ValidPrincipals: []string{req.Principal},
		ValidAfter:      uint64(req.ValidFrom.Unix()),
		ValidBefore:     uint64(req.ValidTo.Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions: map[string]string{
				"permit-pty":     "",
				"permit-user-rc": "",
			},
		},
	}

	signer, err := ssh.NewSignerFromKey(ca)
	if err != nil {
		return nil, fmt.Errorf("sshcert: ca signer: %w", err)
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, fmt.Errorf("sshcert: sign: %w", err)
	}
	return cert, nil
}

// Marshal renders a certificate as the single line an SSH client expects in a
// *-cert.pub file.
func Marshal(cert *ssh.Certificate) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
}
