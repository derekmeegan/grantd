package protocol

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/derekmeegan/grantd/go/internal/canonical"
)

// Domain separation strings (protocol/v1.md §1.4). A signature produced under
// one context can never verify under another.
const (
	CtxHostRegister  = "grantd/v1/host-register"
	CtxHostConnect   = "grantd/v1/host-connect"
	CtxGrant         = "grantd/v1/grant"
	CtxRedemptionSig = "grantd/v1/redemption-agent-sig"
	CtxRedemptionMAC = "grantd/v1/redemption-proof"
	CtxAgentRegister = "grantd/v1/agent-register"
)

var (
	ErrBadVersion   = errors.New("protocol: unsupported version")
	ErrBadTimestamp = errors.New("protocol: timestamp out of range")
)

// u64 converts a protocol timestamp to the CBE U64 domain, rejecting negatives.
func u64(v int64) (uint64, error) {
	if v < 0 {
		return 0, ErrBadTimestamp
	}
	return uint64(v), nil
}

// ---------------------------------------------------------------- host register

// HostRegistration is the self-certifying enrollment record a host publishes.
// It carries only public information.
type HostRegistration struct {
	Version           uint64 `json:"version"`
	HostID            string `json:"host_id"`
	IdentityPublicKey []byte `json:"identity_public_key"`
	SSHCAPublicKey    string `json:"ssh_ca_public_key"`
	Hostname          string `json:"hostname"`
	SSHPort           uint64 `json:"ssh_port"`
	SSHUser           string `json:"ssh_user"`
	Timestamp         int64  `json:"timestamp"`
	Nonce             []byte `json:"nonce"`
}

func (m *HostRegistration) Canonical() ([]byte, error) {
	ts, err := u64(m.Timestamp)
	if err != nil {
		return nil, err
	}
	return canonical.Encode(CtxHostRegister, []canonical.Field{
		canonical.U("version", m.Version),
		canonical.S("host_id", m.HostID),
		canonical.B("identity_public_key", m.IdentityPublicKey),
		canonical.S("ssh_ca_public_key", m.SSHCAPublicKey),
		canonical.S("hostname", m.Hostname),
		canonical.U("ssh_port", m.SSHPort),
		canonical.S("ssh_user", m.SSHUser),
		canonical.U("timestamp", ts),
		canonical.B("nonce", m.Nonce),
	})
}

// ---------------------------------------------------------------- host connect

// HostConnect authenticates a rendezvous WebSocket upgrade.
type HostConnect struct {
	Version   uint64 `json:"version"`
	HostID    string `json:"host_id"`
	Path      string `json:"path"`
	Timestamp int64  `json:"timestamp"`
	Nonce     []byte `json:"nonce"`
}

func (m *HostConnect) Canonical() ([]byte, error) {
	ts, err := u64(m.Timestamp)
	if err != nil {
		return nil, err
	}
	return canonical.Encode(CtxHostConnect, []canonical.Field{
		canonical.U("version", m.Version),
		canonical.S("host_id", m.HostID),
		canonical.S("path", m.Path),
		canonical.U("timestamp", ts),
		canonical.B("nonce", m.Nonce),
	})
}

// ---------------------------------------------------------------------- grant

// Grant is the public grant metadata. It deliberately contains no secret and no
// derivative of the secret; this is the whole record the coordination service
// is ever given.
type Grant struct {
	Version   uint64 `json:"version"`
	HostID    string `json:"host_id"`
	GrantID   string `json:"grant_id"`
	SSHUser   string `json:"ssh_user"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
}

func (m *Grant) Canonical() ([]byte, error) {
	created, err := u64(m.CreatedAt)
	if err != nil {
		return nil, err
	}
	expires, err := u64(m.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return canonical.Encode(CtxGrant, []canonical.Field{
		canonical.U("version", m.Version),
		canonical.S("host_id", m.HostID),
		canonical.S("grant_id", m.GrantID),
		canonical.S("ssh_user", m.SSHUser),
		canonical.U("created_at", created),
		canonical.U("expires_at", expires),
	})
}

// ----------------------------------------------------------------- redemption

// RedemptionPayload is the statement a visiting agent makes: "this agent wants
// this SSH key certified under this grant on this host, now".
//
// It is covered by two independent proofs. The Ed25519 agent signature binds
// the statement to a registered identity. The HMAC proof, keyed by the grant
// secret, is the actual authorization. Only the second one can mint access,
// and only a party that holds the secret can produce it.
type RedemptionPayload struct {
	Version        uint64 `json:"version"`
	HostID         string `json:"host_id"`
	GrantID        string `json:"grant_id"`
	AgentID        string `json:"agent_id"`
	AgentPublicKey []byte `json:"agent_public_key"`
	SSHPublicKey   string `json:"ssh_public_key"`
	Timestamp      int64  `json:"timestamp"`
	Nonce          []byte `json:"nonce"`
}

func (m *RedemptionPayload) fields() ([]canonical.Field, error) {
	ts, err := u64(m.Timestamp)
	if err != nil {
		return nil, err
	}
	return []canonical.Field{
		canonical.U("version", m.Version),
		canonical.S("host_id", m.HostID),
		canonical.S("grant_id", m.GrantID),
		canonical.S("agent_id", m.AgentID),
		canonical.B("agent_public_key", m.AgentPublicKey),
		canonical.S("ssh_public_key", m.SSHPublicKey),
		canonical.U("timestamp", ts),
		canonical.B("nonce", m.Nonce),
	}, nil
}

// CanonicalSig returns the bytes the agent identity key signs.
func (m *RedemptionPayload) CanonicalSig() ([]byte, error) {
	f, err := m.fields()
	if err != nil {
		return nil, err
	}
	return canonical.Encode(CtxRedemptionSig, f)
}

// CanonicalMAC returns the bytes the grant secret authenticates.
func (m *RedemptionPayload) CanonicalMAC() ([]byte, error) {
	f, err := m.fields()
	if err != nil {
		return nil, err
	}
	return canonical.Encode(CtxRedemptionMAC, f)
}

// Proof computes HMAC-SHA256(grant_secret, CanonicalMAC()).
func (m *RedemptionPayload) Proof(secret []byte) ([]byte, error) {
	msg, err := m.CanonicalMAC()
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(msg)
	return mac.Sum(nil), nil
}

// VerifyProof checks a redemption proof in constant time.
func (m *RedemptionPayload) VerifyProof(secret, proof []byte) (bool, error) {
	want, err := m.Proof(secret)
	if err != nil {
		return false, err
	}
	return hmac.Equal(want, proof), nil
}

// ------------------------------------------------------------- agent register

// AgentRegistration enrolls an agent identity public key after the agent has
// solved an Agent Captcha challenge.
type AgentRegistration struct {
	Version     uint64 `json:"version"`
	AgentID     string `json:"agent_id"`
	PublicKey   []byte `json:"public_key"`
	ChallengeID string `json:"challenge_id"`
	PowNonce    string `json:"pow_nonce"`
	Timestamp   int64  `json:"timestamp"`
}

func (m *AgentRegistration) Canonical() ([]byte, error) {
	ts, err := u64(m.Timestamp)
	if err != nil {
		return nil, err
	}
	return canonical.Encode(CtxAgentRegister, []canonical.Field{
		canonical.U("version", m.Version),
		canonical.S("agent_id", m.AgentID),
		canonical.B("public_key", m.PublicKey),
		canonical.S("challenge_id", m.ChallengeID),
		canonical.S("pow_nonce", m.PowNonce),
		canonical.U("timestamp", ts),
	})
}

// -------------------------------------------------------------------- signing

// Signer is anything that can produce an Ed25519 signature over canonical
// bytes. The host daemon holds one that talks to the signer process over a Unix
// socket; it never holds the key itself.
type Signer interface {
	SignCanonical(msg []byte) ([]byte, error)
}

// KeySigner is the in-process Signer backed by an actual private key. Only the
// signer process and the visiting agent ever construct one.
type KeySigner struct{ Key ed25519.PrivateKey }

func (k KeySigner) SignCanonical(msg []byte) ([]byte, error) {
	if len(k.Key) != ed25519.PrivateKeySize {
		return nil, ErrBadPublicKey
	}
	return ed25519.Sign(k.Key, msg), nil
}

// Verify checks an Ed25519 signature over canonical bytes.
func Verify(pub ed25519.PublicKey, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

// -------------------------------------------------------------- JSON envelopes
//
// Binary fields travel as base64url without padding. Each message gets an
// explicit shadow struct rather than reflection so that the JSON shape is
// visible in the source and cannot drift from the spec silently.

func b64enc(b []byte) string { return B64.EncodeToString(b) }

func b64dec(field, s string) ([]byte, error) {
	raw, err := B64.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("protocol: %s: expected base64url without padding: %w", field, err)
	}
	return raw, nil
}

type hostRegistrationJSON struct {
	Version           uint64 `json:"version"`
	HostID            string `json:"host_id"`
	IdentityPublicKey string `json:"identity_public_key"`
	SSHCAPublicKey    string `json:"ssh_ca_public_key"`
	Hostname          string `json:"hostname"`
	SSHPort           uint64 `json:"ssh_port"`
	SSHUser           string `json:"ssh_user"`
	Timestamp         int64  `json:"timestamp"`
	Nonce             string `json:"nonce"`
}

func (m HostRegistration) MarshalJSON() ([]byte, error) {
	return json.Marshal(hostRegistrationJSON{
		Version: m.Version, HostID: m.HostID,
		IdentityPublicKey: b64enc(m.IdentityPublicKey),
		SSHCAPublicKey:    m.SSHCAPublicKey, Hostname: m.Hostname,
		SSHPort: m.SSHPort, SSHUser: m.SSHUser,
		Timestamp: m.Timestamp, Nonce: b64enc(m.Nonce),
	})
}

func (m *HostRegistration) UnmarshalJSON(data []byte) error {
	var j hostRegistrationJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	pk, err := b64dec("identity_public_key", j.IdentityPublicKey)
	if err != nil {
		return err
	}
	nonce, err := b64dec("nonce", j.Nonce)
	if err != nil {
		return err
	}
	*m = HostRegistration{
		Version: j.Version, HostID: j.HostID, IdentityPublicKey: pk,
		SSHCAPublicKey: j.SSHCAPublicKey, Hostname: j.Hostname,
		SSHPort: j.SSHPort, SSHUser: j.SSHUser,
		Timestamp: j.Timestamp, Nonce: nonce,
	}
	return nil
}

type hostConnectJSON struct {
	Version   uint64 `json:"version"`
	HostID    string `json:"host_id"`
	Path      string `json:"path"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
}

func (m HostConnect) MarshalJSON() ([]byte, error) {
	return json.Marshal(hostConnectJSON{
		Version: m.Version, HostID: m.HostID, Path: m.Path,
		Timestamp: m.Timestamp, Nonce: b64enc(m.Nonce),
	})
}

func (m *HostConnect) UnmarshalJSON(data []byte) error {
	var j hostConnectJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	nonce, err := b64dec("nonce", j.Nonce)
	if err != nil {
		return err
	}
	*m = HostConnect{Version: j.Version, HostID: j.HostID, Path: j.Path,
		Timestamp: j.Timestamp, Nonce: nonce}
	return nil
}

type redemptionPayloadJSON struct {
	Version        uint64 `json:"version"`
	HostID         string `json:"host_id"`
	GrantID        string `json:"grant_id"`
	AgentID        string `json:"agent_id"`
	AgentPublicKey string `json:"agent_public_key"`
	SSHPublicKey   string `json:"ssh_public_key"`
	Timestamp      int64  `json:"timestamp"`
	Nonce          string `json:"nonce"`
}

func (m RedemptionPayload) MarshalJSON() ([]byte, error) {
	return json.Marshal(redemptionPayloadJSON{
		Version: m.Version, HostID: m.HostID, GrantID: m.GrantID,
		AgentID: m.AgentID, AgentPublicKey: b64enc(m.AgentPublicKey),
		SSHPublicKey: m.SSHPublicKey, Timestamp: m.Timestamp,
		Nonce: b64enc(m.Nonce),
	})
}

func (m *RedemptionPayload) UnmarshalJSON(data []byte) error {
	var j redemptionPayloadJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	pk, err := b64dec("agent_public_key", j.AgentPublicKey)
	if err != nil {
		return err
	}
	nonce, err := b64dec("nonce", j.Nonce)
	if err != nil {
		return err
	}
	*m = RedemptionPayload{
		Version: j.Version, HostID: j.HostID, GrantID: j.GrantID,
		AgentID: j.AgentID, AgentPublicKey: pk, SSHPublicKey: j.SSHPublicKey,
		Timestamp: j.Timestamp, Nonce: nonce,
	}
	return nil
}

type agentRegistrationJSON struct {
	Version     uint64 `json:"version"`
	AgentID     string `json:"agent_id"`
	PublicKey   string `json:"public_key"`
	ChallengeID string `json:"challenge_id"`
	PowNonce    string `json:"pow_nonce"`
	Timestamp   int64  `json:"timestamp"`
}

func (m AgentRegistration) MarshalJSON() ([]byte, error) {
	return json.Marshal(agentRegistrationJSON{
		Version: m.Version, AgentID: m.AgentID, PublicKey: b64enc(m.PublicKey),
		ChallengeID: m.ChallengeID, PowNonce: m.PowNonce,
		Timestamp: m.Timestamp,
	})
}

func (m *AgentRegistration) UnmarshalJSON(data []byte) error {
	var j agentRegistrationJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	pk, err := b64dec("public_key", j.PublicKey)
	if err != nil {
		return err
	}
	*m = AgentRegistration{
		Version: j.Version, AgentID: j.AgentID, PublicKey: pk,
		ChallengeID: j.ChallengeID, PowNonce: j.PowNonce,
		Timestamp: j.Timestamp,
	}
	return nil
}
