package agent

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/derekmeegan/grantd/go/internal/protocol"
	"golang.org/x/crypto/ssh"
)

// The coordination service is not trusted. It can return any hostname, port,
// user, or certificate in a redemption response. These checks bind the
// response to the host named in the capability URL.
//
// The host id is a hash of the host identity key, so the visitor can verify
// the host's signed registration with no other trust anchor. The registration
// names the host's SSH CA, and the certificate must come from that CA.

var (
	ErrHostRecordMismatch = errors.New("agent: host record does not belong to the host in the capability url")
	ErrHostRecordSig      = errors.New("agent: host registration signature does not verify")
	ErrResponseMismatch   = errors.New("agent: redemption response disagrees with the host's signed registration")
	ErrCertificate        = errors.New("agent: certificate is not acceptable")
)

// VerifiedHost is a host registration that passed VerifyHostRecord.
type VerifiedHost struct {
	Registration protocol.HostRegistration
	CAKey        ssh.PublicKey
}

// VerifyHostRecord makes sure that a public host record was signed by the
// host named by hostID. It returns the registration and the parsed CA key.
func VerifyHostRecord(hostID string, rec protocol.HostPublicRecord) (VerifiedHost, error) {
	reg := rec.Registration
	if reg.Version != protocol.Version {
		return VerifiedHost{}, fmt.Errorf("%w: protocol version %d", ErrHostRecordMismatch, reg.Version)
	}
	if reg.HostID != hostID || rec.HostID != hostID {
		return VerifiedHost{}, ErrHostRecordMismatch
	}
	if err := protocol.CheckHostID(hostID, reg.IdentityPublicKey); err != nil {
		return VerifiedHost{}, fmt.Errorf("%w: %v", ErrHostRecordMismatch, err)
	}
	msg, err := reg.Canonical()
	if err != nil {
		return VerifiedHost{}, fmt.Errorf("%w: %v", ErrHostRecordSig, err)
	}
	if !protocol.Verify(ed25519.PublicKey(reg.IdentityPublicKey), msg, rec.Signature) {
		return VerifiedHost{}, ErrHostRecordSig
	}
	if err := protocol.ValidateHostname(reg.Hostname); err != nil {
		return VerifiedHost{}, err
	}
	if err := protocol.ValidateSSHUser(reg.SSHUser); err != nil {
		return VerifiedHost{}, err
	}
	if err := protocol.ValidatePort(reg.SSHPort); err != nil {
		return VerifiedHost{}, err
	}
	ca, err := protocol.ParseSSHPublicKey(reg.SSHCAPublicKey)
	if err != nil {
		return VerifiedHost{}, err
	}
	return VerifiedHost{Registration: reg, CAKey: ca}, nil
}

// VerifyRedemption makes sure that a redemption response matches the verified
// host and that the certificate is valid for the visitor's own key. It returns
// the parsed certificate.
func VerifyRedemption(host VerifiedHost, resp protocol.RedemptionResponse, key *EphemeralSSHKey, now time.Time) (*ssh.Certificate, error) {
	reg := host.Registration
	if resp.Hostname != reg.Hostname || resp.Port != reg.SSHPort || resp.User != reg.SSHUser {
		return nil, ErrResponseMismatch
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Certificate))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertificate, err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("%w: not a certificate", ErrCertificate)
	}
	if cert.CertType != ssh.UserCert {
		return nil, fmt.Errorf("%w: not a user certificate", ErrCertificate)
	}
	if !bytes.Equal(cert.Key.Marshal(), key.PublicSSH.Marshal()) {
		return nil, fmt.Errorf("%w: issued for a different key", ErrCertificate)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != reg.SSHUser {
		return nil, fmt.Errorf("%w: principals %v, want [%s]", ErrCertificate, cert.ValidPrincipals, reg.SSHUser)
	}

	// CheckCert verifies the signature, the principal, and the validity
	// window. It does not check which CA signed, so do that here.
	if cert.SignatureKey == nil || !bytes.Equal(cert.SignatureKey.Marshal(), host.CAKey.Marshal()) {
		return nil, fmt.Errorf("%w: not signed by the host's CA", ErrCertificate)
	}
	checker := ssh.CertChecker{Clock: func() time.Time { return now }}
	if err := checker.CheckCert(reg.SSHUser, cert); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertificate, err)
	}
	return cert, nil
}
