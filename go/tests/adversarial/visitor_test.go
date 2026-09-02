package adversarial

// The visitor's checks on what the service hands back. A hostile service can
// return any host record and any redemption response. The visitor must
// refuse everything that the host named in the capability URL did not sign.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
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
