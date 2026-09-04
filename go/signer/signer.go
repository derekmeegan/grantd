// Package signer is the trust root. It is the only process that can read the
// host identity key and the SSH CA key, and the only place that decides to
// grant access.
//
// It has no network access. Every input arrives over a Unix socket, and the
// signer treats every input as hostile, including input from the host's own
// daemon.
package signer

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/derekmeegan/grantd/go/internal/idkey"
	"github.com/derekmeegan/grantd/go/internal/protocol"
	"github.com/derekmeegan/grantd/go/signer/store"
)

// MaxActiveGrants caps how many grants can be outstanding at once.
const MaxActiveGrants = 32

// NonceRetention is how long redemption nonces are remembered. It must exceed
// the redemption skew window.
const NonceRetention = 4 * protocol.SkewRedemption

// Config locates the signer's key material and state.
type Config struct {
	HostIdentityKeyPath string
	SSHCAKeyPath        string
	StatePath           string
	Origin              string // public origin used in capability URLs
}

// Signer holds the private keys and the authoritative state.
type Signer struct {
	cfg      Config
	identity ed25519.PrivateKey
	ca       ed25519.PrivateKey
	store    *store.Store
	now      func() time.Time
}

// Open loads existing key material and state.
func Open(cfg Config) (*Signer, error) {
	identity, err := idkey.LoadPrivate(cfg.HostIdentityKeyPath)
	if err != nil {
		return nil, fmt.Errorf("signer: host identity key: %w", err)
	}
	ca, err := idkey.LoadPrivate(cfg.SSHCAKeyPath)
	if err != nil {
		return nil, fmt.Errorf("signer: ssh ca key: %w", err)
	}
	st, err := store.Open(cfg.StatePath)
	if err != nil {
		return nil, fmt.Errorf("signer: state: %w", err)
	}
	return &Signer{cfg: cfg, identity: identity, ca: ca, store: st, now: time.Now}, nil
}

// SetClock replaces the signer's clock. Tests only.
func (s *Signer) SetClock(f func() time.Time) { s.now = f }

func (s *Signer) Close() error { return s.store.Close() }

// Store exposes the underlying state for status and tests.
func (s *Signer) Store() *store.Store { return s.store }

// HostID returns this machine's self-certifying identifier.
func (s *Signer) HostID() (string, error) {
	return protocol.HostID(s.identity.Public().(ed25519.PublicKey))
}

// IdentityPublicKey returns the raw host identity public key.
func (s *Signer) IdentityPublicKey() ed25519.PublicKey {
	return s.identity.Public().(ed25519.PublicKey)
}

// SSHCAPublicKeyLine returns the CA public key in authorized_keys form.
func (s *Signer) SSHCAPublicKeyLine() (string, error) {
	return idkey.PublicSSHLine(s.ca.Public().(ed25519.PublicKey))
}

// ------------------------------------------------------------------ enrollment

// Enroll writes the local enrollment record. It rejects root.
//
// sshHostKeyLine is this machine's sshd host key. It is required: a record
// without one gives a visitor nothing to pin, and a visitor that cannot pin is
// one the coordination service can point at a machine of its own. Refusing it
// here makes that record impossible to produce.
func (s *Signer) Enroll(ctx context.Context, sshUser, hostname string, port uint64, sshHostKeyLine string) error {
	if err := protocol.ValidateSSHUser(sshUser); err != nil {
		return err
	}
	if err := protocol.ValidateHostname(hostname); err != nil {
		return err
	}
	if err := protocol.ValidatePort(port); err != nil {
		return err
	}
	if sshHostKeyLine == "" {
		return fmt.Errorf("signer: an ssh host public key is required to enroll")
	}
	// Parsed, not normalized: the exact bytes are what the registration signs
	// and what a visitor pins. A comment or another key type is a rejection.
	if _, err := protocol.ParseSSHPublicKey(sshHostKeyLine); err != nil {
		return fmt.Errorf("signer: ssh host public key: %w", err)
	}
	hostID, err := s.HostID()
	if err != nil {
		return err
	}
	return s.store.SetHost(ctx, store.Host{
		HostID: hostID, SSHUser: sshUser, Hostname: hostname,
		SSHPort: port, CreatedAt: s.now().Unix(),
		SSHHostPublicKey: sshHostKeyLine,
	})
}

// Host returns the enrollment record.
func (s *Signer) Host(ctx context.Context) (store.Host, error) { return s.store.Host(ctx) }

// ------------------------------------------------------- signed public records

// HostRegistration builds and signs the host's public enrollment record.
func (s *Signer) HostRegistration(ctx context.Context) (protocol.HostRegisterRequest, error) {
	h, err := s.store.Host(ctx)
	if err != nil {
		return protocol.HostRegisterRequest{}, err
	}
	caLine, err := s.SSHCAPublicKeyLine()
	if err != nil {
		return protocol.HostRegisterRequest{}, err
	}
	// A registration without a host key would tell every visitor to connect
	// to an address with nothing to verify the machine against. Refuse to
	// produce one rather than publish a record that silently removes the
	// visitor's only protection.
	if h.SSHHostPublicKey == "" {
		return protocol.HostRegisterRequest{}, fmt.Errorf(
			"signer: this host has no ssh host key on record; re-run 'grant-signer init' to re-enroll")
	}
	nonce, err := protocol.NewNonce()
	if err != nil {
		return protocol.HostRegisterRequest{}, err
	}
	reg := protocol.HostRegistration{
		Version:           protocol.Version,
		HostID:            h.HostID,
		IdentityPublicKey: s.IdentityPublicKey(),
		SSHCAPublicKey:    caLine,
		SSHHostPublicKey:  h.SSHHostPublicKey,
		Hostname:          h.Hostname,
		SSHPort:           h.SSHPort,
		SSHUser:           h.SSHUser,
		Timestamp:         s.now().Unix(),
		Nonce:             nonce,
	}
	msg, err := reg.Canonical()
	if err != nil {
		return protocol.HostRegisterRequest{}, err
	}
	return protocol.HostRegisterRequest{
		Registration: reg,
		Signature:    ed25519.Sign(s.identity, msg),
	}, nil
}

// ConnectAuth is the set of headers that authenticate a rendezvous WebSocket
// upgrade. The daemon asks for these and never sees the key.
type ConnectAuth struct {
	HostID    string `json:"host_id"`
	Path      string `json:"path"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

// SignConnect signs a rendezvous upgrade for the given request path.
func (s *Signer) SignConnect(ctx context.Context, path string) (ConnectAuth, error) {
	h, err := s.store.Host(ctx)
	if err != nil {
		return ConnectAuth{}, err
	}
	nonce, err := protocol.NewNonce()
	if err != nil {
		return ConnectAuth{}, err
	}
	m := protocol.HostConnect{
		Version: protocol.Version, HostID: h.HostID, Path: path,
		Timestamp: s.now().Unix(), Nonce: nonce,
	}
	msg, err := m.Canonical()
	if err != nil {
		return ConnectAuth{}, err
	}
	return ConnectAuth{
		HostID:    m.HostID,
		Path:      m.Path,
		Timestamp: m.Timestamp,
		Nonce:     protocol.B64.EncodeToString(nonce),
		Signature: protocol.B64.EncodeToString(ed25519.Sign(s.identity, msg)),
	}, nil
}

// ---------------------------------------------------------------- grant issue

// NewGrant is what the owner receives after creating a grant. The secret and
// the capability URL are returned once, over the owner socket.
type NewGrant struct {
	GrantID       string                       `json:"grant_id"`
	ExpiresAt     int64                        `json:"expires_at"`
	CapabilityURL string                       `json:"capability_url"`
	Publish       protocol.GrantPublishRequest `json:"publish"`
}

var (
	// ErrTooManyGrants is returned when the active-grant cap is hit.
	ErrTooManyGrants = errors.New("signer: too many active grants")
	// ErrNoOrigin is returned when no public origin is configured.
	ErrNoOrigin = errors.New("signer: no public origin configured; set --origin at init")
)

// CreateGrant mints a capability: a random secret kept here, and signed public
// metadata that carries no trace of it.
func (s *Signer) CreateGrant(ctx context.Context, ttlSeconds int64) (NewGrant, error) {
	if !validOrigin(s.cfg.Origin) {
		return NewGrant{}, ErrNoOrigin
	}
	if ttlSeconds == 0 {
		ttlSeconds = protocol.DefaultGrantTTL
	}
	now := s.now().Unix()
	if err := protocol.ValidateGrantWindow(now, now+ttlSeconds); err != nil {
		return NewGrant{}, err
	}
	h, err := s.store.Host(ctx)
	if err != nil {
		return NewGrant{}, err
	}
	active, err := s.store.ActiveGrantCount(ctx, now)
	if err != nil {
		return NewGrant{}, err
	}
	if active >= MaxActiveGrants {
		return NewGrant{}, ErrTooManyGrants
	}

	grantID, err := protocol.NewGrantID()
	if err != nil {
		return NewGrant{}, err
	}
	secret, err := protocol.NewGrantSecret()
	if err != nil {
		return NewGrant{}, err
	}
	expiresAt := now + ttlSeconds

	if err := s.store.CreateGrant(ctx, store.Grant{
		ID: grantID, Secret: secret, SSHUser: h.SSHUser,
		CreatedAt: now, ExpiresAt: expiresAt,
	}); err != nil {
		return NewGrant{}, err
	}

	g := protocol.Grant{
		Version: protocol.Version, HostID: h.HostID, GrantID: grantID,
		SSHUser: h.SSHUser, CreatedAt: now, ExpiresAt: expiresAt,
	}
	msg, err := g.Canonical()
	if err != nil {
		return NewGrant{}, err
	}

	return NewGrant{
		GrantID:       grantID,
		ExpiresAt:     expiresAt,
		CapabilityURL: protocol.CapabilityURL(s.cfg.Origin, h.HostID, grantID, secret),
		Publish: protocol.GrantPublishRequest{
			Grant:     g,
			Signature: ed25519.Sign(s.identity, msg),
		},
	}, nil
}

func validOrigin(origin string) bool {
	return strings.HasPrefix(origin, "https://") || strings.HasPrefix(origin, "http://")
}

// PendingPublications returns signed public metadata for every grant the
// daemon still needs to publish.
func (s *Signer) PendingPublications(ctx context.Context) ([]protocol.GrantPublishRequest, error) {
	h, err := s.store.Host(ctx)
	if err != nil {
		return nil, err
	}
	pending, err := s.store.PendingPublications(ctx, s.now().Unix())
	if err != nil {
		return nil, err
	}
	out := make([]protocol.GrantPublishRequest, 0, len(pending))
	for _, g := range pending {
		msg := protocol.Grant{
			Version: protocol.Version, HostID: h.HostID, GrantID: g.ID,
			SSHUser: g.SSHUser, CreatedAt: g.CreatedAt, ExpiresAt: g.ExpiresAt,
		}
		canon, err := msg.Canonical()
		if err != nil {
			return nil, err
		}
		out = append(out, protocol.GrantPublishRequest{
			Grant:     msg,
			Signature: ed25519.Sign(s.identity, canon),
		})
	}
	return out, nil
}

// ListGrants returns local grant state without secrets.
func (s *Signer) ListGrants(ctx context.Context) ([]store.GrantView, error) {
	return s.store.ListGrants(ctx)
}

// RevokeGrant makes a grant unredeemable.
func (s *Signer) RevokeGrant(ctx context.Context, id string) error {
	if !protocol.ValidGrantID(id) {
		return fmt.Errorf("signer: malformed grant id")
	}
	return s.store.RevokeGrant(ctx, id, s.now().Unix())
}

// MarkPublished records a successful publish of grant metadata.
func (s *Signer) MarkPublished(ctx context.Context, id string) error {
	if !protocol.ValidGrantID(id) {
		return fmt.Errorf("signer: malformed grant id")
	}
	return s.store.MarkPublished(ctx, id, s.now().Unix())
}
