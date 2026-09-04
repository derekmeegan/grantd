package signer_test

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/derekmeegan/grantd/go/agent"
	"github.com/derekmeegan/grantd/go/internal/idkey"
	"github.com/derekmeegan/grantd/go/internal/protocol"
	"github.com/derekmeegan/grantd/go/signer"
	"golang.org/x/crypto/ssh"
)

const testOrigin = "https://grantd.test"

// newHostKeyLine returns a fresh ssh-ed25519 authorized_keys line, standing in
// for the machine's sshd host key.
func newHostKeyLine(t *testing.T) string {
	t.Helper()
	pub, _, err := idkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	line, err := idkey.PublicSSHLine(pub)
	if err != nil {
		t.Fatal(err)
	}
	return line
}

// newBareSigner opens a signer without enrolling it, so that enrollment
// itself can be the thing under test.
func newBareSigner(t *testing.T) *signer.Signer {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"host_identity", "ssh_ca"} {
		_, priv, err := idkey.Generate()
		if err != nil {
			t.Fatal(err)
		}
		if err := idkey.SavePrivate(filepath.Join(dir, name), priv); err != nil {
			t.Fatal(err)
		}
	}
	s, err := signer.Open(signer.Config{
		HostIdentityKeyPath: filepath.Join(dir, "host_identity"),
		SSHCAKeyPath:        filepath.Join(dir, "ssh_ca"),
		StatePath:           filepath.Join(dir, "state.db"),
		Origin:              testOrigin,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// newSigner builds an enrolled signer on a temporary directory. The tests use
// the production code paths, except where one simulates a compromised part.
func newSigner(t *testing.T) *signer.Signer {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"host_identity", "ssh_ca"} {
		_, priv, err := idkey.Generate()
		if err != nil {
			t.Fatal(err)
		}
		if err := idkey.SavePrivate(filepath.Join(dir, name), priv); err != nil {
			t.Fatal(err)
		}
	}
	s, err := signer.Open(signer.Config{
		HostIdentityKeyPath: filepath.Join(dir, "host_identity"),
		SSHCAKeyPath:        filepath.Join(dir, "ssh_ca"),
		StatePath:           filepath.Join(dir, "state.db"),
		Origin:              testOrigin,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Enroll(context.Background(), "ubuntu", "box.example.com", 22, newHostKeyLine(t)); err != nil {
		t.Fatal(err)
	}
	return s
}

func newAgent(t *testing.T) *agent.Identity {
	t.Helper()
	id, err := agent.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func newSSHKey(t *testing.T) *agent.EphemeralSSHKey {
	t.Helper()
	k, err := agent.NewEphemeralSSHKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// mintCapability creates a grant and parses the capability URL as a recipient
// does.
func mintCapability(t *testing.T, s *signer.Signer, ttl int64) agent.Capability {
	t.Helper()
	g, err := s.CreateGrant(context.Background(), ttl)
	if err != nil {
		t.Fatal(err)
	}
	cap, err := agent.ParseCapabilityURL(g.CapabilityURL)
	if err != nil {
		t.Fatal(err)
	}
	return cap
}

func redeemErrCode(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	var re *signer.RedeemError
	if !asRedeemError(err, &re) {
		t.Fatalf("expected a RedeemError, got %T: %v", err, err)
	}
	return re.Code
}

func asRedeemError(err error, target **signer.RedeemError) bool {
	if re, ok := err.(*signer.RedeemError); ok {
		*target = re
		return true
	}
	return false
}

// --------------------------------------------------------------- happy path

func TestRedeemIssuesUsableCertificate(t *testing.T) {
	s := newSigner(t)
	ctx := context.Background()
	cap := mintCapability(t, s, 1800)
	ident := newAgent(t)
	key := newSSHKey(t)

	req, err := agent.BuildRedemption(ident, cap, key.Line, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := s.Redeem(ctx, req)
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}

	if resp.User != "ubuntu" {
		t.Errorf("principal = %q, want ubuntu", resp.User)
	}
	if resp.Hostname != "box.example.com" || resp.Port != 22 {
		t.Errorf("connection info = %s:%d, want box.example.com:22", resp.Hostname, resp.Port)
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Certificate))
	if err != nil {
		t.Fatalf("certificate does not parse: %v", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatalf("issued object is not a certificate: %T", pub)
	}
	if cert.CertType != ssh.UserCert {
		t.Errorf("cert type = %d, want user cert", cert.CertType)
	}
	if got := cert.ValidPrincipals; len(got) != 1 || got[0] != "ubuntu" {
		t.Errorf("principals = %v, want [ubuntu]", got)
	}
	if want := "grantd:" + cap.GrantID + ":" + ident.ID; cert.KeyId != want {
		t.Errorf("key id = %q, want %q", cert.KeyId, want)
	}
	if !strings.Contains(string(ssh.MarshalAuthorizedKey(cert.Key)), strings.Fields(key.Line)[1]) {
		t.Error("certificate was issued over a different public key than the one submitted")
	}

	// A visiting agent must not receive a tunnel into the customer network.
	for _, forbidden := range []string{"permit-port-forwarding", "permit-agent-forwarding", "permit-X11-forwarding"} {
		if _, present := cert.Permissions.Extensions[forbidden]; present {
			t.Errorf("certificate grants %s", forbidden)
		}
	}
	if _, ok := cert.Permissions.Extensions["permit-pty"]; !ok {
		t.Error("certificate does not permit a pty, so it cannot deliver a shell")
	}

	// OpenSSH's own checker must accept it for the enrolled principal only.
	caLine, err := s.SSHCAPublicKeyLine()
	if err != nil {
		t.Fatal(err)
	}
	caKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(caLine))
	if err != nil {
		t.Fatal(err)
	}
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return string(auth.Marshal()) == string(caKey.Marshal())
		},
	}
	if err := checker.CheckCert("ubuntu", cert); err != nil {
		t.Errorf("OpenSSH cert checker rejected a valid certificate: %v", err)
	}
	if err := checker.CheckCert("root", cert); err == nil {
		t.Error("certificate was accepted for root; the principal is not being enforced")
	}
}

func TestCapabilityURLKeepsSecretInFragment(t *testing.T) {
	s := newSigner(t)
	g, err := s.CreateGrant(context.Background(), 600)
	if err != nil {
		t.Fatal(err)
	}
	before, _, found := strings.Cut(g.CapabilityURL, "#")
	if !found {
		t.Fatal("capability url has no fragment")
	}
	// The service sees only the part before the '#'.
	if strings.Contains(before, "=") || len(strings.Split(before, "/")) != 6 {
		t.Errorf("unexpected capability url path shape: %q", before)
	}
	cap, err := agent.ParseCapabilityURL(g.CapabilityURL)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(before, protocol.EncodeSecret(cap.Secret)) {
		t.Fatal("the grant secret appears in the server-visible part of the capability URL")
	}
}

// ------------------------------------------------------------ negative cases

func TestRedeemRejections(t *testing.T) {
	ctx := context.Background()

	t.Run("substituted ssh key breaks the proof", func(t *testing.T) {
		s := newSigner(t)
		cap := mintCapability(t, s, 1800)
		ident := newAgent(t)
		req, err := agent.BuildRedemption(ident, cap, newSSHKey(t).Line, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		// Keep the envelope, swap in a key the attacker controls.
		attacker := newSSHKey(t)
		req.Payload.SSHPublicKey = attacker.Line
		if code := redeemErrCode(t, mustFail(s.Redeem(ctx, req))); code != protocol.ErrCodeBadSignature && code != protocol.ErrCodeBadProof {
			t.Errorf("code = %s, want BAD_SIGNATURE or BAD_PROOF", code)
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		s := newSigner(t)
		cap := mintCapability(t, s, 1800)
		cap.Secret = make([]byte, protocol.SecretLen) // all zeros
		req, err := agent.BuildRedemption(newAgent(t), cap, newSSHKey(t).Line, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if code := redeemErrCode(t, mustFail(s.Redeem(ctx, req))); code != protocol.ErrCodeBadProof {
			t.Errorf("code = %s, want BAD_PROOF", code)
		}
	})

	t.Run("bad proof does not consume the grant", func(t *testing.T) {
		s := newSigner(t)
		cap := mintCapability(t, s, 1800)
		bad := cap
		bad.Secret = make([]byte, protocol.SecretLen)
		for i := 0; i < 20; i++ {
			req, err := agent.BuildRedemption(newAgent(t), bad, newSSHKey(t).Line, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Redeem(ctx, req); err == nil {
				t.Fatal("a wrong proof was accepted")
			}
		}
		// The legitimate holder must still be able to use the grant.
		req, err := agent.BuildRedemption(newAgent(t), cap, newSSHKey(t).Line, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Redeem(ctx, req); err != nil {
			t.Fatalf("guessing attempts burned a legitimate grant: %v", err)
		}
	})

	t.Run("expired grant", func(t *testing.T) {
		s := newSigner(t)
		cap := mintCapability(t, s, 120)
		// Advance the signer's clock past expiry but keep the payload fresh.
		future := time.Now().Add(200 * time.Second)
		s.SetClock(func() time.Time { return future })
		req, err := agent.BuildRedemption(newAgent(t), cap, newSSHKey(t).Line, future)
		if err != nil {
			t.Fatal(err)
		}
		if code := redeemErrCode(t, mustFail(s.Redeem(ctx, req))); code != protocol.ErrCodeGrantExpired {
			t.Errorf("code = %s, want GRANT_EXPIRED", code)
		}
	})

	t.Run("revoked grant", func(t *testing.T) {
		s := newSigner(t)
		cap := mintCapability(t, s, 1800)
		if err := s.RevokeGrant(ctx, cap.GrantID); err != nil {
			t.Fatal(err)
		}
		req, err := agent.BuildRedemption(newAgent(t), cap, newSSHKey(t).Line, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if code := redeemErrCode(t, mustFail(s.Redeem(ctx, req))); code != protocol.ErrCodeGrantRevoked {
			t.Errorf("code = %s, want GRANT_REVOKED", code)
		}
	})

	t.Run("unknown grant", func(t *testing.T) {
		s := newSigner(t)
		cap := mintCapability(t, s, 1800)
		other, err := protocol.NewGrantID()
		if err != nil {
			t.Fatal(err)
		}
		cap.GrantID = other
		req, err := agent.BuildRedemption(newAgent(t), cap, newSSHKey(t).Line, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if code := redeemErrCode(t, mustFail(s.Redeem(ctx, req))); code != protocol.ErrCodeGrantNotFound {
			t.Errorf("code = %s, want GRANT_NOT_FOUND", code)
		}
	})

	t.Run("redemption addressed to another host", func(t *testing.T) {
		s := newSigner(t)
		cap := mintCapability(t, s, 1800)
		req, err := agent.BuildRedemption(newAgent(t), cap, newSSHKey(t).Line, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		req.Payload.HostID = "h_" + strings.Repeat("a", 32)
		if code := redeemErrCode(t, mustFail(s.Redeem(ctx, req))); code != protocol.ErrCodeIDMismatch {
			t.Errorf("code = %s, want ID_MISMATCH", code)
		}
	})

	t.Run("stale timestamp", func(t *testing.T) {
		s := newSigner(t)
		cap := mintCapability(t, s, 1800)
		old := time.Now().Add(-time.Duration(protocol.SkewRedemption+60) * time.Second)
		req, err := agent.BuildRedemption(newAgent(t), cap, newSSHKey(t).Line, old)
		if err != nil {
			t.Fatal(err)
		}
		if code := redeemErrCode(t, mustFail(s.Redeem(ctx, req))); code != protocol.ErrCodeStaleTimestamp {
			t.Errorf("code = %s, want STALE_TIMESTAMP", code)
		}
	})

	t.Run("agent id not derived from agent key", func(t *testing.T) {
		s := newSigner(t)
		cap := mintCapability(t, s, 1800)
		req, err := agent.BuildRedemption(newAgent(t), cap, newSSHKey(t).Line, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		req.Payload.AgentID = newAgent(t).ID
		if code := redeemErrCode(t, mustFail(s.Redeem(ctx, req))); code != protocol.ErrCodeIDMismatch {
			t.Errorf("code = %s, want ID_MISMATCH", code)
		}
	})

	t.Run("forged agent signature", func(t *testing.T) {
		s := newSigner(t)
		cap := mintCapability(t, s, 1800)
		req, err := agent.BuildRedemption(newAgent(t), cap, newSSHKey(t).Line, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		req.AgentSignature[0] ^= 0xff
		if code := redeemErrCode(t, mustFail(s.Redeem(ctx, req))); code != protocol.ErrCodeBadSignature {
			t.Errorf("code = %s, want BAD_SIGNATURE", code)
		}
	})

	t.Run("malformed ssh key", func(t *testing.T) {
		s := newSigner(t)
		cap := mintCapability(t, s, 1800)
		for _, bad := range []string{
			"",
			"ssh-rsa AAAAB3NzaC1yc2E",
			"ssh-ed25519",
			"ssh-ed25519 not-base64!!",
			"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF3nBGa2Q0F3PLNMU5b6nZlYA0Wa0d5jSf2Uf7f1yQhF comment",
			" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF3nBGa2Q0F3PLNMU5b6nZlYA0Wa0d5jSf2Uf7f1yQhF",
		} {
			ident := newAgent(t)
			req, err := agent.BuildRedemption(ident, cap, bad, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Redeem(ctx, req); err == nil {
				t.Errorf("accepted malformed ssh key %q", bad)
			}
		}
	})

	t.Run("root is never enrollable", func(t *testing.T) {
		s := newSigner(t)
		if err := s.Enroll(ctx, "root", "box.example.com", 22, newHostKeyLine(t)); err == nil {
			t.Fatal("root enrollment was accepted")
		}
	})
}

func mustFail(_ protocol.RedemptionResponse, err error) error { return err }

// ------------------------------------------------------------- single use

func TestGrantIsSingleUse(t *testing.T) {
	s := newSigner(t)
	ctx := context.Background()
	cap := mintCapability(t, s, 1800)

	first, err := agent.BuildRedemption(newAgent(t), cap, newSSHKey(t).Line, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Redeem(ctx, first); err != nil {
		t.Fatal(err)
	}
	second, err := agent.BuildRedemption(newAgent(t), cap, newSSHKey(t).Line, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if code := redeemErrCode(t, mustFail(s.Redeem(ctx, second))); code != protocol.ErrCodeAlreadyRedeemed {
		t.Errorf("code = %s, want GRANT_ALREADY_REDEEMED", code)
	}
}

// TestReplayingAWonRedemptionIsRejected pins the absence of a retry path. A
// grant is consumed once, even for the agent that won it. A lost response
// costs one more grant. See protocol/v1.md section 8.
func TestReplayingAWonRedemptionIsRejected(t *testing.T) {
	s := newSigner(t)
	ctx := context.Background()
	cap := mintCapability(t, s, 1800)

	req, err := agent.BuildRedemption(newAgent(t), cap, newSSHKey(t).Line, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Redeem(ctx, req); err != nil {
		t.Fatal(err)
	}
	if code := redeemErrCode(t, mustFail(s.Redeem(ctx, req))); code != protocol.ErrCodeReplayedNonce {
		t.Errorf("code = %s, want REPLAYED_NONCE", code)
	}
	n, err := s.Store().CertificateCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("certificates issued = %d, want exactly 1", n)
	}
}

func TestReplayWithADifferentKeyIsRejected(t *testing.T) {
	s := newSigner(t)
	ctx := context.Background()
	cap := mintCapability(t, s, 1800)
	ident := newAgent(t)

	req, err := agent.BuildRedemption(ident, cap, newSSHKey(t).Line, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Redeem(ctx, req); err != nil {
		t.Fatal(err)
	}
	// Same nonce, different key.
	replay := req
	other := newSSHKey(t)
	replay.Payload.SSHPublicKey = other.Line
	if _, err := s.Redeem(ctx, replay); err == nil {
		t.Fatal("a replayed envelope with a substituted key was accepted")
	}
}

// TestConcurrentRedemptionsProduceExactlyOneWinner fires many simultaneous
// redemptions with distinct SSH keys at one grant. Single-use must hold under
// contention.
func TestConcurrentRedemptionsProduceExactlyOneWinner(t *testing.T) {
	s := newSigner(t)
	ctx := context.Background()
	cap := mintCapability(t, s, 1800)

	const n = 200
	reqs := make([]protocol.RedemptionRequest, n)
	for i := range reqs {
		req, err := agent.BuildRedemption(newAgent(t), cap, newSSHKey(t).Line, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		reqs[i] = req
	}

	var (
		mu      sync.Mutex
		winners []protocol.RedemptionResponse
		codes   = map[string]int{}
		wg      sync.WaitGroup
		start   = make(chan struct{})
	)
	for i := range reqs {
		wg.Add(1)
		go func(req protocol.RedemptionRequest) {
			defer wg.Done()
			<-start
			resp, err := s.Redeem(ctx, req)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				winners = append(winners, resp)
				return
			}
			var re *signer.RedeemError
			if asRedeemError(err, &re) {
				codes[re.Code]++
			} else {
				codes["NON_PROTOCOL_ERROR:"+err.Error()]++
			}
		}(reqs[i])
	}
	close(start)
	wg.Wait()

	if len(winners) != 1 {
		t.Fatalf("%d redemptions succeeded, want exactly 1 (codes: %v)", len(winners), codes)
	}
	for code := range codes {
		if code != protocol.ErrCodeAlreadyRedeemed {
			t.Errorf("loser got %s, want GRANT_ALREADY_REDEEMED", code)
		}
	}
	certs, err := s.Store().CertificateCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if certs != 1 {
		t.Errorf("certificates issued = %d, want 1", certs)
	}
}

// TestEnrollmentRequiresAUsableHostKey pins the guard that makes a visitor's
// verification possible at all. A machine that could enroll without a host
// key would publish a record that silently leaves every visitor with nothing
// to check, so it is refused at enrollment rather than found out later.
func TestEnrollmentRequiresAUsableHostKey(t *testing.T) {
	ctx := context.Background()
	good := newHostKeyLine(t)
	for _, tc := range []struct{ name, line string }{
		{"empty", ""},
		{"with a comment", good + " root@box"},
		{"trailing whitespace", good + " "},
		{"not ed25519", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7"},
		{"not a key at all", "hello world"},
		{"only a type", "ssh-ed25519"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := newBareSigner(t).Enroll(ctx, "ubuntu", "box.example.com", 22, tc.line); err == nil {
				t.Fatalf("enrolled with host key %q, which must be refused", tc.line)
			}
		})
	}
	t.Run("a clean two-field line is accepted and stored", func(t *testing.T) {
		s := newBareSigner(t)
		if err := s.Enroll(ctx, "ubuntu", "box.example.com", 22, good); err != nil {
			t.Fatalf("a valid host key was refused: %v", err)
		}
		h, err := s.Host(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if h.SSHHostPublicKey != good {
			t.Errorf("stored host key = %q, want %q", h.SSHHostPublicKey, good)
		}
	})
}

// TestRegistrationCarriesTheHostKeyAndVerifies is the visitor's chain checked
// from the host's end: the published record must verify under the identity
// key its host_id derives from, and must carry a host key that is not the CA.
func TestRegistrationCarriesTheHostKeyAndVerifies(t *testing.T) {
	s := newSigner(t)
	reg, err := s.HostRegistration(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if reg.Registration.SSHHostPublicKey == "" {
		t.Fatal("the published registration carries no ssh host key")
	}
	if _, err := protocol.ParseSSHPublicKey(reg.Registration.SSHHostPublicKey); err != nil {
		t.Errorf("published host key does not parse: %v", err)
	}
	if reg.Registration.SSHHostPublicKey == reg.Registration.SSHCAPublicKey {
		t.Error("the ssh host key and the ssh CA key are the same key")
	}
	if err := protocol.CheckHostID(reg.Registration.HostID, reg.Registration.IdentityPublicKey); err != nil {
		t.Errorf("host_id does not match the identity key: %v", err)
	}
	msg, err := reg.Registration.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !protocol.Verify(reg.Registration.IdentityPublicKey, msg, reg.Signature) {
		t.Fatal("the host's own registration signature does not verify")
	}
	// Swapping the host key must break the signature: this is what stops a
	// coordination service substituting a machine it controls.
	tampered := reg.Registration
	tampered.SSHHostPublicKey = newHostKeyLine(t)
	tmsg, _ := tampered.Canonical()
	if protocol.Verify(tampered.IdentityPublicKey, tmsg, reg.Signature) {
		t.Fatal("a registration with a swapped host key still verified")
	}
}

// TestRegistrationRefusesToPublishWithoutAHostKey covers a machine enrolled
// before host keys were published: the migrated row is empty, and the signer
// must refuse to publish rather than emit an unpinnable record.
func TestRegistrationRefusesToPublishWithoutAHostKey(t *testing.T) {
	s := newBareSigner(t)
	ctx := context.Background()
	if err := s.Enroll(ctx, "ubuntu", "box.example.com", 22, newHostKeyLine(t)); err != nil {
		t.Fatal(err)
	}
	h, err := s.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h.SSHHostPublicKey = ""
	if err := s.Store().SetHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if _, err := s.HostRegistration(ctx); err == nil {
		t.Fatal("published a registration with no ssh host key")
	}
}
