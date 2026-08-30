// Package vectors_test checks this implementation against the normative
// cross-language fixtures in protocol/test-vectors/v1.json.
//
// The same file is consumed by the TypeScript test suite. If either
// implementation drifts, one of the two suites fails here rather than in
// production, where the symptom would be a certificate that silently does not
// verify.
package vectors_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/derekmeegan/grantd/go/internal/protocol"
)

type vector struct {
	Name          string          `json:"name"`
	Context       string          `json:"context"`
	Message       json.RawMessage `json:"message"`
	CanonicalHex  string          `json:"canonical_hex"`
	SignatureHex  string          `json:"signature_hex"`
	SigningKeyHex string          `json:"signing_key_seed_hex"`
	MacHex        string          `json:"mac_hex"`
	MacKeyHex     string          `json:"mac_key_hex"`
}

type bundle struct {
	Version     uint64            `json:"version"`
	Keys        map[string]string `json:"keys"`
	Identifiers map[string]string `json:"identifiers"`
	SSHKeys     map[string]string `json:"ssh_keys"`
	Capability  map[string]string `json:"capability"`
	Vectors     []vector          `json:"vectors"`
}

func load(t *testing.T) bundle {
	t.Helper()
	path := filepath.Join("..", "..", "..", "protocol", "test-vectors", "v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var b bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(b.Vectors) == 0 {
		t.Fatal("vector file contains no vectors")
	}
	return b
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// canonicalFor re-derives canonical bytes from the message in the vector, going
// through the same JSON parsing a real peer would.
func canonicalFor(t *testing.T, v vector) []byte {
	t.Helper()
	var (
		b   []byte
		err error
	)
	switch v.Context {
	case protocol.CtxHostRegister:
		var m protocol.HostRegistration
		decode(t, v.Message, &m)
		b, err = m.Canonical()
	case protocol.CtxHostConnect:
		var m protocol.HostConnect
		decode(t, v.Message, &m)
		b, err = m.Canonical()
	case protocol.CtxGrant:
		var m protocol.Grant
		decode(t, v.Message, &m)
		b, err = m.Canonical()
	case protocol.CtxRedemptionSig:
		var m protocol.RedemptionPayload
		decode(t, v.Message, &m)
		b, err = m.CanonicalSig()
	case protocol.CtxRedemptionMAC:
		var m protocol.RedemptionPayload
		decode(t, v.Message, &m)
		b, err = m.CanonicalMAC()
	case protocol.CtxAgentRegister:
		var m protocol.AgentRegistration
		decode(t, v.Message, &m)
		b, err = m.Canonical()
	default:
		t.Fatalf("vector %q has unknown context %q", v.Name, v.Context)
	}
	if err != nil {
		t.Fatalf("canonical encode %q: %v", v.Name, err)
	}
	return b
}

func decode(t *testing.T, raw json.RawMessage, v any) {
	t.Helper()
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("decode message: %v", err)
	}
}

func TestCanonicalBytesMatchVectors(t *testing.T) {
	b := load(t)
	for _, v := range b.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			got := hex.EncodeToString(canonicalFor(t, v))
			if got != v.CanonicalHex {
				t.Errorf("canonical bytes differ\n got: %s\nwant: %s", got, v.CanonicalHex)
			}
		})
	}
}

func TestSignaturesAndMacsMatchVectors(t *testing.T) {
	b := load(t)
	for _, v := range b.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			canon := canonicalFor(t, v)
			if v.SignatureHex != "" {
				key := ed25519.NewKeyFromSeed(mustHex(t, v.SigningKeyHex))
				got := hex.EncodeToString(ed25519.Sign(key, canon))
				if got != v.SignatureHex {
					t.Errorf("signature differs\n got: %s\nwant: %s", got, v.SignatureHex)
				}
				if !protocol.Verify(key.Public().(ed25519.PublicKey), canon, mustHex(t, v.SignatureHex)) {
					t.Error("vector signature does not verify against its own canonical bytes")
				}
			}
			if v.MacHex != "" {
				var m protocol.RedemptionPayload
				decode(t, v.Message, &m)
				proof, err := m.Proof(mustHex(t, v.MacKeyHex))
				if err != nil {
					t.Fatal(err)
				}
				if got := hex.EncodeToString(proof); got != v.MacHex {
					t.Errorf("mac differs\n got: %s\nwant: %s", got, v.MacHex)
				}
			}
		})
	}
}

func TestIdentifierDerivationMatchesVectors(t *testing.T) {
	b := load(t)
	hostPub := ed25519.PublicKey(mustHex(t, b.Keys["host_identity_pub_hex"]))
	agentPub := ed25519.PublicKey(mustHex(t, b.Keys["agent_identity_pub_hex"]))

	gotHost, err := protocol.HostID(hostPub)
	if err != nil {
		t.Fatal(err)
	}
	if gotHost != b.Identifiers["host_id"] {
		t.Errorf("host_id = %s, want %s", gotHost, b.Identifiers["host_id"])
	}
	gotAgent, err := protocol.AgentID(agentPub)
	if err != nil {
		t.Fatal(err)
	}
	if gotAgent != b.Identifiers["agent_id"] {
		t.Errorf("agent_id = %s, want %s", gotAgent, b.Identifiers["agent_id"])
	}
}

func TestCapabilityURLMatchesVectors(t *testing.T) {
	b := load(t)
	secret := mustHex(t, b.Keys["grant_secret_hex"])
	got := protocol.CapabilityURL(b.Capability["origin"], b.Identifiers["host_id"], b.Identifiers["grant_id"], secret)
	if got != b.Capability["capability_url"] {
		t.Errorf("capability url = %s, want %s", got, b.Capability["capability_url"])
	}
	if enc := protocol.EncodeSecret(secret); enc != b.Capability["secret_b64url"] {
		t.Errorf("secret encoding = %s, want %s", enc, b.Capability["secret_b64url"])
	}
}

// TestDistinctContextsProduceDistinctBytes is the property that makes domain
// separation worth having: the agent signature and the grant MAC cover the same
// eight fields, and must still be different objects.
func TestDistinctContextsProduceDistinctBytes(t *testing.T) {
	b := load(t)
	var sig, mac []byte
	for _, v := range b.Vectors {
		switch v.Context {
		case protocol.CtxRedemptionSig:
			sig = mustHex(t, v.CanonicalHex)
		case protocol.CtxRedemptionMAC:
			mac = mustHex(t, v.CanonicalHex)
		}
	}
	if sig == nil || mac == nil {
		t.Fatal("vector file is missing a redemption signature or proof vector")
	}
	if string(sig) == string(mac) {
		t.Fatal("redemption signature and proof canonicalize to identical bytes")
	}
}
