// Command protocol-vectors generates protocol/test-vectors/v1.json, the
// cross-language conformance fixtures. Every implementation must agree with
// this file on every byte. All key material here is public test data.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/derekmeegan/grantd/go/internal/protocol"
)

// Deterministic seeds so the vectors are reproducible.
var (
	hostSeed    = mustHex("0101010101010101010101010101010101010101010101010101010101010101")
	agentSeed   = mustHex("0202020202020202020202020202020202020202020202020202020202020202")
	caSeed      = mustHex("0303030303030303030303030303030303030303030303030303030303030303")
	hostSSHSeed = mustHex("0404040404040404040404040404040404040404040404040404040404040404")
	secret      = mustHex("a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90")
	nonceA      = mustHex("000102030405060708090a0b0c0d0e0f")
	nonceB      = mustHex("f0e0d0c0b0a090807060504030201000")
)

type vector struct {
	Name          string `json:"name"`
	Context       string `json:"context"`
	Message       any    `json:"message"`
	CanonicalHex  string `json:"canonical_hex"`
	SignatureHex  string `json:"signature_hex,omitempty"`
	SigningKeyHex string `json:"signing_key_seed_hex,omitempty"`
	MacHex        string `json:"mac_hex,omitempty"`
	MacKeyHex     string `json:"mac_key_hex,omitempty"`
}

type bundle struct {
	Description string            `json:"description"`
	Version     uint64            `json:"version"`
	Keys        map[string]string `json:"keys"`
	Identifiers map[string]string `json:"identifiers"`
	SSHKeys     map[string]string `json:"ssh_keys"`
	Capability  map[string]string `json:"capability"`
	Vectors     []vector          `json:"vectors"`
}

func main() {
	hostPriv := ed25519.NewKeyFromSeed(hostSeed)
	agentPriv := ed25519.NewKeyFromSeed(agentSeed)
	caPriv := ed25519.NewKeyFromSeed(caSeed)

	hostPub := hostPriv.Public().(ed25519.PublicKey)
	agentPub := agentPriv.Public().(ed25519.PublicKey)
	caPub := caPriv.Public().(ed25519.PublicKey)

	hostID := must(protocol.HostID(hostPub))
	agentID := must(protocol.AgentID(agentPub))
	const grantID = "g_abcdefghijklmnop"

	caLine := sshLine(caPub)
	agentSSHLine := sshLine(agentPub)
	// The host's sshd host key: what a visiting agent pins.
	hostSSHLine := sshLine(ed25519.NewKeyFromSeed(hostSSHSeed).Public().(ed25519.PublicKey))

	b := bundle{
		Description: "grantd v1 normative cross-language test vectors. All keys are public test data.",
		Version:     protocol.Version,
		Keys: map[string]string{
			"host_ssh_seed_hex":       hex.EncodeToString(hostSSHSeed),
			"host_identity_seed_hex":  hex.EncodeToString(hostSeed),
			"host_identity_pub_hex":   hex.EncodeToString(hostPub),
			"agent_identity_seed_hex": hex.EncodeToString(agentSeed),
			"agent_identity_pub_hex":  hex.EncodeToString(agentPub),
			"ssh_ca_seed_hex":         hex.EncodeToString(caSeed),
			"grant_secret_hex":        hex.EncodeToString(secret),
		},
		Identifiers: map[string]string{
			"host_id":  hostID,
			"agent_id": agentID,
			"grant_id": grantID,
		},
		SSHKeys: map[string]string{
			"ssh_ca_public_key":    caLine,
			"host_ssh_public_key":  hostSSHLine,
			"agent_ssh_public_key": agentSSHLine,
		},
		Capability: map[string]string{
			"origin":         "https://grantd.example.workers.dev",
			"secret_b64url":  protocol.EncodeSecret(secret),
			"capability_url": protocol.CapabilityURL("https://grantd.example.workers.dev", hostID, grantID, secret),
		},
	}

	reg := protocol.HostRegistration{
		Version: 1, HostID: hostID, IdentityPublicKey: hostPub,
		SSHCAPublicKey: caLine, SSHHostPublicKey: hostSSHLine,
		Hostname: "box.example.com",
		SSHPort:  22, SSHUser: "ubuntu", Timestamp: 1756598400, Nonce: nonceA,
	}
	b.Vectors = append(b.Vectors, signed("host_registration", protocol.CtxHostRegister, reg,
		must(reg.Canonical()), hostPriv, hostSeed))

	conn := protocol.HostConnect{
		Version: 1, HostID: hostID, Path: "/v1/hosts/" + hostID + "/connect",
		Timestamp: 1756598400, Nonce: nonceB,
	}
	b.Vectors = append(b.Vectors, signed("host_connect", protocol.CtxHostConnect, conn,
		must(conn.Canonical()), hostPriv, hostSeed))

	grant := protocol.Grant{
		Version: 1, HostID: hostID, GrantID: grantID, SSHUser: "ubuntu",
		CreatedAt: 1756598400, ExpiresAt: 1756600200,
	}
	b.Vectors = append(b.Vectors, signed("grant_metadata", protocol.CtxGrant, grant,
		must(grant.Canonical()), hostPriv, hostSeed))

	payload := protocol.RedemptionPayload{
		Version: 1, HostID: hostID, GrantID: grantID, AgentID: agentID,
		AgentPublicKey: agentPub, SSHPublicKey: agentSSHLine,
		Timestamp: 1756598460, Nonce: nonceA,
	}
	sigVec := signed("redemption_agent_signature", protocol.CtxRedemptionSig, payload,
		must(payload.CanonicalSig()), agentPriv, agentSeed)
	b.Vectors = append(b.Vectors, sigVec)

	macBytes := must(payload.CanonicalMAC())
	proof := must(payload.Proof(secret))
	b.Vectors = append(b.Vectors, vector{
		Name:         "redemption_proof",
		Context:      protocol.CtxRedemptionMAC,
		Message:      payload,
		CanonicalHex: hex.EncodeToString(macBytes),
		MacHex:       hex.EncodeToString(proof),
		MacKeyHex:    hex.EncodeToString(secret),
	})

	areg := protocol.AgentRegistration{
		Version: 1, AgentID: agentID, PublicKey: agentPub,
		ChallengeID: "c_0123456789abcdef", PowNonce: "31337",
		Timestamp: 1756598400,
	}
	b.Vectors = append(b.Vectors, signed("agent_registration", protocol.CtxAgentRegister, areg,
		must(areg.Canonical()), agentPriv, agentSeed))

	// Multi-byte UTF-8 and an empty value exercise the length prefixes.
	unicodeGrant := protocol.Grant{
		Version: 1, HostID: hostID, GrantID: grantID, SSHUser: "ubuntu",
		CreatedAt: 0, ExpiresAt: 1,
	}
	b.Vectors = append(b.Vectors, signed("grant_metadata_edge_values", protocol.CtxGrant, unicodeGrant,
		must(unicodeGrant.Canonical()), hostPriv, hostSeed))

	unicodeReg := protocol.HostRegistration{
		Version: 1, HostID: hostID, IdentityPublicKey: hostPub,
		SSHCAPublicKey: caLine, SSHHostPublicKey: hostSSHLine,
		Hostname: "höst.example.com",
		SSHPort:  65535, SSHUser: "u", Timestamp: 2147483647, Nonce: nonceB,
	}
	b.Vectors = append(b.Vectors, signed("host_registration_unicode_hostname", protocol.CtxHostRegister, unicodeReg,
		must(unicodeReg.Canonical()), hostPriv, hostSeed))

	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		panic(err)
	}
	out = append(out, '\n')
	dest := "protocol/test-vectors/v1.json"
	if len(os.Args) > 1 {
		dest = os.Args[1]
	}
	if err := os.WriteFile(dest, out, 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("wrote %d vectors to %s\n", len(b.Vectors), dest)
}

func signed(name, ctx string, msg any, canonical []byte, key ed25519.PrivateKey, seed []byte) vector {
	return vector{
		Name:          name,
		Context:       ctx,
		Message:       msg,
		CanonicalHex:  hex.EncodeToString(canonical),
		SignatureHex:  hex.EncodeToString(ed25519.Sign(key, canonical)),
		SigningKeyHex: hex.EncodeToString(seed),
	}
}

func sshLine(pub ed25519.PublicKey) string {
	line, err := sshPublicLine(pub)
	if err != nil {
		panic(err)
	}
	return line
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
