package signer

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/derekmeegan/grantd/go/internal/protocol"
	"github.com/derekmeegan/grantd/go/internal/sshcert"
	"github.com/derekmeegan/grantd/go/signer/store"
)

// RedeemError carries a protocol error code out of the redemption path so the
// daemon can relay a precise code rather than a generic failure.
type RedeemError struct {
	Code    string
	Message string
}

func (e *RedeemError) Error() string { return e.Code + ": " + e.Message }

func redeemErr(code, format string, args ...any) *RedeemError {
	return &RedeemError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Redeem is the only function that can turn a network message into SSH
// access. It treats the daemon and the coordination service as hostile.
// The host ID is compared to our own, the agent ID is recomputed from the
// agent's key, the principal comes from local enrollment, and only a valid
// HMAC under the stored grant secret can authorize issuance.
func (s *Signer) Redeem(ctx context.Context, req protocol.RedemptionRequest) (protocol.RedemptionResponse, error) {
	now := s.now()
	nowSec := now.Unix()
	p := req.Payload

	// Cheap checks first. None of these write to the database.

	if p.Version != protocol.Version {
		return protocol.RedemptionResponse{}, redeemErr(protocol.ErrCodeUnsupportedVersion,
			"protocol version %d is not supported", p.Version)
	}

	h, err := s.store.Host(ctx)
	if err != nil {
		if errors.Is(err, store.ErrNoHost) {
			return protocol.RedemptionResponse{}, redeemErr(protocol.ErrCodeInternal, "host is not enrolled")
		}
		return protocol.RedemptionResponse{}, err
	}
	if p.HostID != h.HostID {
		// Refuse a redemption addressed to another machine. This stops the
		// service from replaying one host's traffic at another.
		return protocol.RedemptionResponse{}, redeemErr(protocol.ErrCodeIDMismatch,
			"redemption is addressed to a different host")
	}
	if !protocol.ValidGrantID(p.GrantID) {
		return protocol.RedemptionResponse{}, redeemErr(protocol.ErrCodeBadRequest, "malformed grant id")
	}
	if !protocol.WithinSkew(nowSec, p.Timestamp, protocol.SkewRedemption) {
		return protocol.RedemptionResponse{}, redeemErr(protocol.ErrCodeStaleTimestamp,
			"timestamp is outside the %ds window", protocol.SkewRedemption)
	}
	if len(p.Nonce) != protocol.NonceLen {
		return protocol.RedemptionResponse{}, redeemErr(protocol.ErrCodeBadRequest,
			"nonce must be %d bytes", protocol.NonceLen)
	}
	if len(p.AgentPublicKey) != ed25519.PublicKeySize {
		return protocol.RedemptionResponse{}, redeemErr(protocol.ErrCodeBadRequest,
			"agent public key must be %d bytes", ed25519.PublicKeySize)
	}
	// The agent ID is a hash of the agent's key. Recompute it.
	if err := protocol.CheckAgentID(p.AgentID, p.AgentPublicKey); err != nil {
		return protocol.RedemptionResponse{}, redeemErr(protocol.ErrCodeIDMismatch,
			"agent_id does not match agent_public_key")
	}

	sigMsg, err := p.CanonicalSig()
	if err != nil {
		return protocol.RedemptionResponse{}, redeemErr(protocol.ErrCodeBadRequest, "%v", err)
	}
	if !protocol.Verify(p.AgentPublicKey, sigMsg, req.AgentSignature) {
		return protocol.RedemptionResponse{}, redeemErr(protocol.ErrCodeBadSignature,
			"agent signature does not verify")
	}

	sshKey, err := protocol.ParseSSHPublicKey(p.SSHPublicKey)
	if err != nil {
		return protocol.RedemptionResponse{}, redeemErr(protocol.ErrCodeBadRequest, "%v", err)
	}
	keyFP := protocol.SSHKeyFingerprint(sshKey)

	// Replay check. Nonces live longer than the skew window, so a captured
	// envelope cannot be resent while it is still fresh.
	if err := s.store.RememberNonce(ctx, "redeem", p.Nonce, nowSec, NonceRetention); err != nil {
		if errors.Is(err, store.ErrNonceReplay) {
			return protocol.RedemptionResponse{}, redeemErr(protocol.ErrCodeReplayedNonce,
				"nonce has already been used")
		}
		return protocol.RedemptionResponse{}, err
	}

	// Lock the grant, verify the proof inside the transaction, and consume it
	// once.
	claim, err := s.store.ClaimGrant(ctx, p.GrantID, nowSec, p.AgentID, keyFP,
		func(secret []byte) (bool, error) { return p.VerifyProof(secret, req.Proof) })
	if err != nil {
		return protocol.RedemptionResponse{}, err
	}

	switch claim.Status {
	case store.ClaimNotFound:
		return protocol.RedemptionResponse{}, redeemErr(protocol.ErrCodeGrantNotFound, "no such grant")
	case store.ClaimRevoked:
		return protocol.RedemptionResponse{}, redeemErr(protocol.ErrCodeGrantRevoked, "grant was revoked")
	case store.ClaimExpired:
		return protocol.RedemptionResponse{}, redeemErr(protocol.ErrCodeGrantExpired, "grant has expired")
	case store.ClaimAlreadyRedeemed:
		return protocol.RedemptionResponse{}, redeemErr(protocol.ErrCodeAlreadyRedeemed,
			"grant has already been redeemed")
	case store.ClaimBadProof:
		return protocol.RedemptionResponse{}, redeemErr(protocol.ErrCodeBadProof,
			"redemption proof does not verify")
	case store.ClaimOK:
	default:
		return protocol.RedemptionResponse{}, redeemErr(protocol.ErrCodeInternal, "unknown claim status")
	}

	serial, err := sshcert.NewSerial()
	if err != nil {
		return protocol.RedemptionResponse{}, err
	}

	validFrom := now.Add(-sshcert.ClockSkewBackdate)
	validTo := time.Unix(claim.ExpiresAt, 0)

	// The principal comes from the local grant record, not from the request.
	cert, err := sshcert.Issue(s.ca, sshcert.Request{
		PublicKey: sshKey,
		Principal: claim.SSHUser,
		GrantID:   p.GrantID,
		AgentID:   p.AgentID,
		Serial:    serial,
		ValidFrom: validFrom,
		ValidTo:   validTo,
	})
	if err != nil {
		return protocol.RedemptionResponse{}, err
	}
	line := sshcert.Marshal(cert)

	if err := s.store.RecordCertificate(ctx, serial, p.GrantID, p.AgentID, keyFP, line,
		validFrom.Unix(), validTo.Unix(), nowSec); err != nil {
		return protocol.RedemptionResponse{}, err
	}

	return protocol.RedemptionResponse{
		Hostname:       h.Hostname,
		Port:           h.SSHPort,
		User:           claim.SSHUser,
		Certificate:    line,
		Serial:         serial,
		KeyID:          cert.KeyId,
		ValidBefore:    validTo.Unix(),
		ValidBeforeStr: validTo.UTC().Format(time.RFC3339),
	}, nil
}
