package adversarial

// The visitor's checks on what the service hands back. A hostile service can
// return any host record and any redemption response. The visitor must
// refuse everything that the host named in the capability URL did not sign.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/derekmeegan/grantd/go/agent"
	"github.com/derekmeegan/grantd/go/internal/idkey"
	"github.com/derekmeegan/grantd/go/internal/protocol"
)

// realHostRecord is what an honest service returns for the harness host.
func realHostRecord(t *testing.T, h *harness) protocol.HostPublicRecord {
	t.Helper()
	reg, err := h.signer.HostRegistration(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return protocol.HostPublicRecord{
		HostID:       reg.Registration.HostID,
		Registration: reg.Registration,
		Signature:    reg.Signature,
		Connected:    true,
	}
}

func TestVisitorAcceptsTheRealHost(t *testing.T) {
	h := newHarness(t)
	cap := h.mint(t, 1800)
	rec := realHostRecord(t, h)

	host, err := agent.VerifyHostRecord(cap.HostID, rec)
	if err != nil {
		t.Fatalf("real host record rejected: %v", err)
	}

	ident, key := newVisitor(t)
	status, body := h.service.redeem(t, envelopeFor(t, ident, cap, key.Line))
	if status != 200 {
		t.Fatalf("redeem: %d %s", status, truncate(body))
	}
	resp := decodeResponse(t, body)
	if _, err := agent.VerifyRedemption(host, resp, key, time.Now()); err != nil {
		t.Fatalf("real redemption rejected: %v", err)
	}
}

func TestVisitorRejectsForgedHostRecords(t *testing.T) {
	h := newHarness(t)
	cap := h.mint(t, 1800)
	real := realHostRecord(t, h)

	t.Run("record signed by the service's own key", func(t *testing.T) {
		_, priv, err := idkey.Generate()
		if err != nil {
			t.Fatal(err)
		}
		forged := real
		forged.Registration.Hostname = "attacker.example"
		msg, err := forged.Registration.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		forged.Signature = ed25519.Sign(priv, msg)
		if _, err := agent.VerifyHostRecord(cap.HostID, forged); err == nil {
			t.Fatal("accepted a record the host did not sign")
		}
	})

	t.Run("record for a different host id", func(t *testing.T) {
		pub, priv, err := idkey.Generate()
		if err != nil {
			t.Fatal(err)
		}
		otherID, err := protocol.HostID(pub)
		if err != nil {
			t.Fatal(err)
		}
		forged := real
		forged.HostID = otherID
		forged.Registration.HostID = otherID
		forged.Registration.IdentityPublicKey = pub
		forged.Registration.Hostname = "attacker.example"
		msg, err := forged.Registration.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		forged.Signature = ed25519.Sign(priv, msg)
		if _, err := agent.VerifyHostRecord(cap.HostID, forged); err == nil {
			t.Fatal("accepted a record for another host")
		}
	})

	t.Run("edited hostname under the real signature", func(t *testing.T) {
		forged := real
		forged.Registration.Hostname = "attacker.example"
		if _, err := agent.VerifyHostRecord(cap.HostID, forged); err == nil {
			t.Fatal("accepted an edited record")
		}
	})
}

func TestVisitorRejectsRedirectedRedemptions(t *testing.T) {
	h := newHarness(t)
	cap := h.mint(t, 1800)
	host, err := agent.VerifyHostRecord(cap.HostID, realHostRecord(t, h))
	if err != nil {
		t.Fatal(err)
	}
	ident, key := newVisitor(t)
	status, body := h.service.redeem(t, envelopeFor(t, ident, cap, key.Line))
	if status != 200 {
		t.Fatalf("redeem: %d %s", status, truncate(body))
	}
	real := decodeResponse(t, body)

	t.Run("different hostname", func(t *testing.T) {
		resp := real
		resp.Hostname = "attacker.example"
		if _, err := agent.VerifyRedemption(host, resp, key, time.Now()); err == nil {
			t.Fatal("accepted a redirect to another hostname")
		}
	})

	t.Run("different user", func(t *testing.T) {
		resp := real
		resp.User = "root"
		if _, err := agent.VerifyRedemption(host, resp, key, time.Now()); err == nil {
			t.Fatal("accepted a different user")
		}
	})

	t.Run("certificate from another CA", func(t *testing.T) {
		other := newHarness(t)
		otherCap := other.mint(t, 1800)
		status, body := other.service.redeem(t, envelopeFor(t, ident, otherCap, key.Line))
		if status != 200 {
			t.Fatalf("redeem on other host: %d %s", status, truncate(body))
		}
		resp := real
		resp.Certificate = decodeResponse(t, body).Certificate
		if _, err := agent.VerifyRedemption(host, resp, key, time.Now()); err == nil {
			t.Fatal("accepted a certificate from a different CA")
		}
	})

	t.Run("certificate for another key", func(t *testing.T) {
		_, otherKey := newVisitor(t)
		if _, err := agent.VerifyRedemption(host, real, otherKey, time.Now()); err == nil {
			t.Fatal("accepted a certificate issued for a different key")
		}
	})
}

func decodeResponse(t *testing.T, body []byte) protocol.RedemptionResponse {
	t.Helper()
	var resp protocol.RedemptionResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

// TestVisitorPinsTheHostKey is the check the certificate cannot make. A
// certificate proves the visitor's key was signed by the host's CA. It says
// nothing about which machine answers the address. Only a pinned host key
// does, and the service — which after DNS naming resolves the address — is
// exactly the party that must not be able to move it.
func TestVisitorPinsTheHostKey(t *testing.T) {
	h := newHarness(t)
	cap := h.mint(t, 1800)
	real := realHostRecord(t, h)

	host, err := agent.VerifyHostRecord(cap.HostID, real)
	if err != nil {
		t.Fatalf("real host record rejected: %v", err)
	}
	if host.HostKey == nil {
		t.Fatal("verified host carries no host key to pin")
	}
	if string(host.HostKey.Marshal()) == string(host.CAKey.Marshal()) {
		t.Fatal("host key and CA key are the same key")
	}

	line := agent.KnownHostsLine(cap.HostID, host)
	if want := cap.HostID + " " + real.Registration.SSHHostPublicKey + "\n"; line != want {
		t.Errorf("known_hosts line = %q, want %q", line, want)
	}
	opts := agent.SSHOptions(cap.HostID, "/tmp/kh")
	joined := ""
	for _, o := range opts {
		joined += o + " "
	}
	for _, want := range []string{"StrictHostKeyChecking=yes", "HostKeyAlias=" + cap.HostID, "HostKeyAlgorithms=ssh-ed25519"} {
		if !contains(joined, want) {
			t.Errorf("ssh options lack %s: %s", want, joined)
		}
	}

	t.Run("host key swapped under the real signature", func(t *testing.T) {
		// The subtle attack: leave the address alone so nothing looks wrong,
		// swap only the key the visitor is about to pin, and stand up a
		// machine at that address holding the matching private key.
		pub, _, err := idkey.Generate()
		if err != nil {
			t.Fatal(err)
		}
		other, err := idkey.PublicSSHLine(pub)
		if err != nil {
			t.Fatal(err)
		}
		forged := real
		forged.Registration.SSHHostPublicKey = other
		if _, err := agent.VerifyHostRecord(cap.HostID, forged); err == nil {
			t.Fatal("accepted a record with a substituted host key")
		}
	})

	t.Run("record with no host key at all", func(t *testing.T) {
		// A service replaying a pre-amendment record. The signature would not
		// verify anyway, but the failure must name the missing key when it
		// does not, so the check is exercised on its own.
		_, priv, err := idkey.Generate()
		if err != nil {
			t.Fatal(err)
		}
		pub := priv.Public().(ed25519.PublicKey)
		id, _ := protocol.HostID(pub)
		forged := real
		forged.HostID = id
		forged.Registration.HostID = id
		forged.Registration.IdentityPublicKey = pub
		forged.Registration.SSHHostPublicKey = ""
		msg, _ := forged.Registration.Canonical()
		forged.Signature = ed25519.Sign(priv, msg)
		_, err = agent.VerifyHostRecord(id, forged)
		if err == nil {
			t.Fatal("accepted a record with no host key")
		}
		if !errors.Is(err, agent.ErrHostRecordNoKey) {
			t.Errorf("error = %v, want ErrHostRecordNoKey", err)
		}
	})
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
