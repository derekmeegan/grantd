// Package sshcert issues short-lived OpenSSH user certificates. It runs only
// inside the signer process.
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

// ClockSkewBackdate is how far before now a certificate becomes valid. It
// covers a host clock that runs ahead of the agent's clock.
const ClockSkewBackdate = 30 * time.Second

// Request describes the certificate to issue. The signer supplies the
// principal from its own records, never from the redemption request.
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

// KeyID is the certificate's audit label. It ties an sshd log line to the
// grant and agent that produced the session.
func KeyID(grantID, agentID string) string {
	return fmt.Sprintf("grantd:%s:%s", grantID, agentID)
}

// Issue signs a user certificate with the host's SSH CA. The extensions allow
// an interactive shell and nothing that turns the session into a tunnel.
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
