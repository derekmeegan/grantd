// Package adversarial runs the real signer and the real daemon against a
// coordination service that is trying to break them.
//
// This is the test the whole architecture exists to pass. The product's central
// claim is that compromising the coordination plane — the Worker, the Durable
// Objects, the deployment credentials, everything — is not enough to obtain SSH
// access to a customer's machine. A test that only exercises the honest service
// cannot show that. So the service here is not a mock of the real one: it is an
// attacker with full control of every byte on the wire, and every one of its
// attempts must fail on the customer's side.
package adversarial

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/derekmeegan/grantd/go/agent"
	"github.com/derekmeegan/grantd/go/daemon/rendezvous"
	"github.com/derekmeegan/grantd/go/daemon/signerclient"
	"github.com/derekmeegan/grantd/go/internal/idkey"
	"github.com/derekmeegan/grantd/go/internal/protocol"
	"github.com/derekmeegan/grantd/go/signer"
	"github.com/derekmeegan/grantd/go/signer/api"
)

// ---------------------------------------------------------------- the attacker

// hostileService is a coordination service under an attacker's complete
// control. It accepts any registration without checking a signature, accepts
// any WebSocket upgrade without verifying who is connecting, and lets the test
// send arbitrary bytes to the host at will.
type hostileService struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	conn      *websocket.Conn
	pending   map[string]chan protocol.Frame
	published map[string]protocol.GrantPublishRequest
	dropped   []string

	connected chan struct{}
	once      sync.Once
}

func newHostileService(t *testing.T) *hostileService {
	h := &hostileService{
		t:         t,
		pending:   map[string]chan protocol.Frame{},
		published: map[string]protocol.GrantPublishRequest{},
		connected: make(chan struct{}),
	}
	mux := http.NewServeMux()

	// Registration: accepted blindly. A hostile service has no incentive to
	// verify the signature it is given.
	mux.HandleFunc("PUT /v1/hosts/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"registered":true}`))
	})

	// Grant publication: recorded, so the attacker can try to tamper with it.
	mux.HandleFunc("PUT /v1/hosts/{host}/grants/{grant}", func(w http.ResponseWriter, r *http.Request) {
		var pub protocol.GrantPublishRequest
		if err := json.NewDecoder(r.Body).Decode(&pub); err == nil {
			h.mu.Lock()
			h.published[pub.Grant.GrantID] = pub
			h.mu.Unlock()
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"published":true}`))
	})

	mux.HandleFunc("GET /v1/hosts/{id}/connect", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			h.t.Logf("hostile service: accept failed: %v", err)
			return
		}
		conn.SetReadLimit(1 << 20)
		h.mu.Lock()
		h.conn = conn
		h.mu.Unlock()
		h.once.Do(func() { close(h.connected) })
		h.readLoop(conn)
	})

	h.srv = httptest.NewServer(mux)
	t.Cleanup(h.srv.Close)
	return h
}

func (h *hostileService) readLoop(conn *websocket.Conn) {
	for {
		_, data, err := conn.Read(context.Background())
		if err != nil {
			return
		}
		var f protocol.Frame
		if err := json.Unmarshal(data, &f); err != nil {
			continue
		}
		h.mu.Lock()
		ch, ok := h.pending[f.ID]
		if ok {
			delete(h.pending, f.ID)
		}
		h.mu.Unlock()
		if ok {
			ch <- f
		}
	}
}

// sendRaw pushes an arbitrary frame at the host and waits up to timeout for an
// answer. A false second return means the host said nothing, which for an
// unknown frame type is the correct behaviour.
func (h *hostileService) sendRaw(t *testing.T, frame protocol.Frame, timeout time.Duration) (protocol.Frame, bool) {
	t.Helper()
	if frame.ID == "" {
		frame.ID = fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	ch := make(chan protocol.Frame, 1)
	h.mu.Lock()
	h.pending[frame.ID] = ch
	conn := h.conn
	h.mu.Unlock()
	if conn == nil {
		t.Fatal("hostile service has no connection to the host")
	}
	data, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Write(context.Background(), websocket.MessageText, data); err != nil {
		t.Fatalf("hostile service could not write: %v", err)
	}
	select {
	case f := <-ch:
		return f, true
	case <-time.After(timeout):
		h.mu.Lock()
		delete(h.pending, frame.ID)
		h.mu.Unlock()
		return protocol.Frame{}, false
	}
}

// redeem sends exactly these bytes to the host as a redemption envelope.
func (h *hostileService) redeem(t *testing.T, envelope []byte) (int, []byte) {
	t.Helper()
	f := protocol.Frame{Type: protocol.FrameRedeemRequest}
	f.SetBody(envelope)
	resp, ok := h.sendRaw(t, f, 10*time.Second)
	if !ok {
		t.Fatal("host did not answer a redemption within the timeout")
	}
	body, err := resp.Body()
	if err != nil {
		t.Fatalf("malformed response body: %v", err)
	}
	return resp.Status, body
}

// errorCode extracts the protocol error code from a host response.
func errorCode(t *testing.T, body []byte) string {
	t.Helper()
	apiErr, ok := protocol.ParseErrorBody(body)
	if !ok {
		t.Fatalf("expected an error envelope, got: %s", truncate(body))
	}
	return apiErr.Code
}

func truncate(b []byte) string {
	if len(b) > 300 {
		return string(b[:300]) + "..."
	}
	return string(b)
}

// ------------------------------------------------------------------- harness

type harness struct {
	signer  *signer.Signer
	service *hostileService
	sshUser string
}

// newHarness wires a real signer and a real daemon to a hostile service.
func newHarness(t *testing.T) *harness {
	t.Helper()

	// Sockets live under /tmp because sun_path is 104 bytes on darwin and the
	// default temp directory is longer than that.
	runDir, err := os.MkdirTemp("/tmp", "gd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(runDir) })
	stateDir := t.TempDir()

	for _, name := range []string{"host_identity", "ssh_ca"} {
		_, priv, err := idkey.Generate()
		if err != nil {
			t.Fatal(err)
		}
		if err := idkey.SavePrivate(filepath.Join(stateDir, name), priv); err != nil {
			t.Fatal(err)
		}
	}

	svc := newHostileService(t)

	sg, err := signer.Open(signer.Config{
		HostIdentityKeyPath: filepath.Join(stateDir, "host_identity"),
		SSHCAKeyPath:        filepath.Join(stateDir, "ssh_ca"),
		StatePath:           filepath.Join(stateDir, "state.db"),
		Origin:              svc.srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sg.Close() })
	if err := sg.Enroll(context.Background(), "ubuntu", "127.0.0.1", 22); err != nil {
		t.Fatal(err)
	}

	quiet := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	apiSrv := &api.Server{Signer: sg, Log: quiet}

	daemonSock := filepath.Join(runDir, "d.sock")
	ln, err := api.Listen(daemonSock, 0o600, -1, -1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	httpSrv := &http.Server{Handler: apiSrv.DaemonHandler()}
	go func() { _ = httpSrv.Serve(ln) }()
	t.Cleanup(func() { _ = httpSrv.Close() })

	d := rendezvous.New(rendezvous.Config{
		Origin: svc.srv.URL,
		Signer: signerclient.New(daemonSock),
		Log:    quiet,
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = d.Run(ctx) }()

	select {
	case <-svc.connected:
	case <-time.After(15 * time.Second):
		t.Fatal("daemon never connected to the hostile service")
	}
	// Give the publish loop a moment so that grants created below get published.
	return &harness{signer: sg, service: svc, sshUser: "ubuntu"}
}

// mint creates a real grant and returns the capability exactly as a legitimate
// recipient would hold it.
func (h *harness) mint(t *testing.T, ttl int64) agent.Capability {
	t.Helper()
	g, err := h.signer.CreateGrant(context.Background(), ttl)
	if err != nil {
		t.Fatal(err)
	}
	cap, err := agent.ParseCapabilityURL(g.CapabilityURL)
	if err != nil {
		t.Fatal(err)
	}
	return cap
}

func newVisitor(t *testing.T) (*agent.Identity, *agent.EphemeralSSHKey) {
	t.Helper()
	ident, err := agent.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	key, err := agent.NewEphemeralSSHKey()
	if err != nil {
		t.Fatal(err)
	}
	return ident, key
}

func envelopeFor(t *testing.T, ident *agent.Identity, cap agent.Capability, sshLine string) []byte {
	t.Helper()
	req, err := agent.BuildRedemption(ident, cap, sshLine, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// ------------------------------------------------------------------- attacks

// TestHostileServiceCannotMintAccess is the headline: with total control of the
// coordination plane and of every byte reaching the host, the attacker still
// gets nothing.
func TestHostileServiceCannotMintAccess(t *testing.T) {
	h := newHarness(t)
	svc := h.service

	t.Run("fabricated grant", func(t *testing.T) {
		// The service invents a grant id and a payload out of thin air.
		ident, key := newVisitor(t)
		fakeID, err := protocol.NewGrantID()
		if err != nil {
			t.Fatal(err)
		}
		hostID, _ := h.signer.HostID()
		cap := agent.Capability{HostID: hostID, GrantID: fakeID, Secret: make([]byte, 32)}
		status, body := svc.redeem(t, envelopeFor(t, ident, cap, key.Line))
		if status == 200 {
			t.Fatal("a fabricated grant produced a certificate")
		}
		if code := errorCode(t, body); code != protocol.ErrCodeGrantNotFound {
			t.Errorf("code = %s, want GRANT_NOT_FOUND", code)
		}
	})

	t.Run("guessing the secret of a real grant", func(t *testing.T) {
		cap := h.mint(t, 1800)
		ident, key := newVisitor(t)
		// The service knows the grant id, the host id, and the agent's public
		// key. It does not know the secret, and that is the whole difference.
		guess := cap
		guess.Secret = make([]byte, protocol.SecretLen)
		status, body := svc.redeem(t, envelopeFor(t, ident, guess, key.Line))
		if status == 200 {
			t.Fatal("a guessed secret produced a certificate")
		}
		if code := errorCode(t, body); code != protocol.ErrCodeBadProof {
			t.Errorf("code = %s, want BAD_PROOF", code)
		}
		// And the grant must survive the attempt, or guessing becomes a way to
		// destroy capabilities.
		v, err := h.signer.Store().GetGrantView(context.Background(), cap.GrantID)
		if err != nil {
			t.Fatal(err)
		}
		if v.RedeemedAt != nil {
			t.Error("a failed guess consumed the grant")
		}
	})

	t.Run("substituting the ssh key in a legitimate envelope", func(t *testing.T) {
		cap := h.mint(t, 1800)
		ident, key := newVisitor(t)
		raw := envelopeFor(t, ident, cap, key.Line)

		// This is the attack the design is built around: intercept a real
		// redemption and swap in a key the attacker holds.
		var req protocol.RedemptionRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Fatal(err)
		}
		_, attackerKey := newVisitor(t)
		req.Payload.SSHPublicKey = attackerKey.Line
		tampered, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}

		status, body := svc.redeem(t, tampered)
		if status == 200 {
			t.Fatal("the attacker's SSH key was certified")
		}
		code := errorCode(t, body)
		if code != protocol.ErrCodeBadSignature && code != protocol.ErrCodeBadProof {
			t.Errorf("code = %s, want BAD_SIGNATURE or BAD_PROOF", code)
		}
	})

	t.Run("extending the expiry of a real grant", func(t *testing.T) {
		// The service holds the signed public metadata. It can rewrite its own
		// copy freely; the host never consults it.
		cap := h.mint(t, 60)
		svc.mu.Lock()
		if pub, ok := svc.published[cap.GrantID]; ok {
			pub.Grant.ExpiresAt = time.Now().Add(24 * time.Hour).Unix()
			svc.published[cap.GrantID] = pub
		}
		svc.mu.Unlock()

		// Move the host's clock past the real expiry.
		h.signer.SetClock(func() time.Time { return time.Now().Add(5 * time.Minute) })
		defer h.signer.SetClock(time.Now)

		ident, key := newVisitor(t)
		req, err := agent.BuildRedemption(ident, cap, key.Line, time.Now().Add(5*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(req)
		status, body := svc.redeem(t, raw)
		if status == 200 {
			t.Fatal("an expired grant produced a certificate")
		}
		if code := errorCode(t, body); code != protocol.ErrCodeGrantExpired {
			t.Errorf("code = %s, want GRANT_EXPIRED", code)
		}
	})

	t.Run("issuing a second certificate for one grant", func(t *testing.T) {
		cap := h.mint(t, 1800)
		ident, key := newVisitor(t)
		status, _ := svc.redeem(t, envelopeFor(t, ident, cap, key.Line))
		if status != 200 {
			t.Fatalf("the legitimate redemption failed with %d", status)
		}
		// Same secret, new agent, new key: the attacker has everything the
		// first redeemer had.
		ident2, key2 := newVisitor(t)
		status, body := svc.redeem(t, envelopeFor(t, ident2, cap, key2.Line))
		if status == 200 {
			t.Fatal("a grant was redeemed twice")
		}
		if code := errorCode(t, body); code != protocol.ErrCodeAlreadyRedeemed {
			t.Errorf("code = %s, want GRANT_ALREADY_REDEEMED", code)
		}
	})

	t.Run("replaying a captured successful redemption with a new key", func(t *testing.T) {
		cap := h.mint(t, 1800)
		ident, key := newVisitor(t)
		raw := envelopeFor(t, ident, cap, key.Line)
		if status, _ := svc.redeem(t, raw); status != 200 {
			t.Fatalf("the legitimate redemption failed with %d", status)
		}
		var req protocol.RedemptionRequest
		_ = json.Unmarshal(raw, &req)
		_, attackerKey := newVisitor(t)
		req.Payload.SSHPublicKey = attackerKey.Line
		replay, _ := json.Marshal(req)
		status, _ := svc.redeem(t, replay)
		if status == 200 {
			t.Fatal("a replayed envelope with a substituted key was accepted")
		}
	})

	t.Run("replaying the exact captured envelope", func(t *testing.T) {
		// Byte-identical replay is the one case that is allowed to succeed,
		// because it is indistinguishable from the redeemer retrying a lost
		// response — and it can only ever produce the same certificate for the
		// same key.
		cap := h.mint(t, 1800)
		ident, key := newVisitor(t)
		raw := envelopeFor(t, ident, cap, key.Line)
		status, first := svc.redeem(t, raw)
		if status != 200 {
			t.Fatalf("legitimate redemption failed with %d", status)
		}
		status, second := svc.redeem(t, raw)
		if status != 200 {
			t.Fatalf("identical retry was rejected with %d", status)
		}
		var a, b protocol.RedemptionResponse
		_ = json.Unmarshal(first, &a)
		_ = json.Unmarshal(second, &b)
		if a.Certificate != b.Certificate || a.Serial != b.Serial {
			t.Error("an identical retry produced a different certificate")
		}
	})

	t.Run("redirecting a redemption to a different host", func(t *testing.T) {
		cap := h.mint(t, 1800)
		ident, key := newVisitor(t)
		var req protocol.RedemptionRequest
		_ = json.Unmarshal(envelopeFor(t, ident, cap, key.Line), &req)
		req.Payload.HostID = "h_" + strings.Repeat("a", 32)
		raw, _ := json.Marshal(req)
		status, body := svc.redeem(t, raw)
		if status == 200 {
			t.Fatal("a redemption for another host was honoured")
		}
		if code := errorCode(t, body); code != protocol.ErrCodeIDMismatch {
			t.Errorf("code = %s, want ID_MISMATCH", code)
		}
	})

	t.Run("the certificate principal cannot be chosen by the requester", func(t *testing.T) {
		cap := h.mint(t, 1800)
		ident, key := newVisitor(t)
		raw := envelopeFor(t, ident, cap, key.Line)

		// Inject fields that a naive implementation might read.
		var generic map[string]any
		_ = json.Unmarshal(raw, &generic)
		payload := generic["payload"].(map[string]any)
		payload["ssh_user"] = "root"
		payload["principal"] = "root"
		payload["user"] = "root"
		generic["ssh_user"] = "root"
		injected, _ := json.Marshal(generic)

		status, body := svc.redeem(t, injected)
		if status != 200 {
			t.Fatalf("injecting unknown fields broke a legitimate redemption: %s", truncate(body))
		}
		var resp protocol.RedemptionResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatal(err)
		}
		if resp.User != "ubuntu" {
			t.Fatalf("principal = %q, want ubuntu", resp.User)
		}
		if !strings.Contains(resp.KeyID, cap.GrantID) {
			t.Errorf("key id %q does not identify the grant", resp.KeyID)
		}
	})
}

// TestHostileServiceCannotMakeTheHostDoAnythingElse checks the frame vocabulary.
// A coordination service that can ask a machine to run a command has not reduced
// the trust placed in it, it has moved it.
func TestHostileServiceCannotMakeTheHostDoAnythingElse(t *testing.T) {
	h := newHarness(t)
	svc := h.service

	canary := filepath.Join(t.TempDir(), "grantd-pwned")

	for _, frameType := range []string{
		"command.execute", "exec", "shell", "read_file", "write_file",
		"sign", "sign.arbitrary", "config.set", "update", "redeem.request.v2",
	} {
		f := protocol.Frame{Type: frameType}
		f.SetBody([]byte(`{"cmd":"/bin/sh -c 'touch ` + canary + `'","path":"/etc/grantd/ssh_ca"}`))
		// No answer is the pass condition, so this waits only briefly.
		if _, ok := svc.sendRaw(t, f, 300*time.Millisecond); ok {
			t.Errorf("host answered an unknown frame type %q", frameType)
		}
		if protocol.KnownFrame(frameType) {
			t.Errorf("%q is in the protocol's frame vocabulary and should not be", frameType)
		}
	}

	if _, err := os.Stat(canary); err == nil {
		t.Fatal("an unknown frame had a side effect on the filesystem")
	}

	// The connection must still work afterwards: dropping junk is not the same
	// as falling over.
	cap := h.mint(t, 1800)
	ident, key := newVisitor(t)
	if status, body := svc.redeem(t, envelopeFor(t, ident, cap, key.Line)); status != 200 {
		t.Fatalf("host stopped serving after unknown frames: %d %s", status, truncate(body))
	}
}

// TestHostileServiceCannotForgeSignedMaterial confirms the service cannot
// produce anything the host would accept as host-signed, since it has no key.
func TestHostileServiceCannotForgeSignedMaterial(t *testing.T) {
	h := newHarness(t)

	pub := h.signer.IdentityPublicKey()
	grant := protocol.Grant{
		Version: protocol.Version, HostID: mustHostID(t, h), GrantID: "g_aaaaaaaaaaaaaaaa",
		SSHUser: "root", CreatedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	canon, err := grant.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	// The attacker signs with a key it generated. It verifies under that key
	// and under no other, which is the entire point.
	_, attackerKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	forged := ed25519.Sign(attackerKey, canon)
	if protocol.Verify(pub, canon, forged) {
		t.Fatal("a forged grant signature verified under the host identity key")
	}
}

func mustHostID(t *testing.T, h *harness) string {
	t.Helper()
	id, err := h.signer.HostID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
