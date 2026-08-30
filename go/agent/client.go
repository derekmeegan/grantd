package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/derekmeegan/grantd/go/internal/protocol"
)

// Client talks to a grantd coordination service. It is a thin HTTP client on
// purpose: every security-relevant step happens either here (constructing
// proofs) or on the customer's machine (verifying them). The service in between
// is treated as a router that may be hostile.
type Client struct {
	Origin string
	HTTP   *http.Client
}

// NewClient returns a client for an origin such as
// https://grantd.example.workers.dev.
func NewClient(origin string) *Client {
	return &Client{
		Origin: origin,
		HTTP:   &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Origin+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		if apiErr, ok := protocol.ParseErrorBody(raw); ok {
			return apiErr
		}
		return fmt.Errorf("grantd: %s %s: http %d: %s", method, path, resp.StatusCode, truncate(raw, 256))
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("grantd: %s %s: malformed response: %w", method, path, err)
		}
	}
	return nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}

// AnswerFunc answers an Agent Captcha question. In production this is the
// agent's own model reading the question; in CI it is the reference solver.
type AnswerFunc func(question string) (string, error)

// Register performs the full Agent Captcha flow and enrolls the identity's
// public key.
func (c *Client) Register(ctx context.Context, ident *Identity, answer AnswerFunc) error {
	var ch protocol.Challenge
	if err := c.do(ctx, http.MethodPost, "/v1/agent-challenges", map[string]any{}, &ch); err != nil {
		return err
	}
	prefix, err := protocol.B64.DecodeString(ch.Pow.Prefix)
	if err != nil {
		return fmt.Errorf("grantd: malformed challenge prefix: %w", err)
	}
	powNonce, err := SolvePow(prefix, ch.Pow.DifficultyBits)
	if err != nil {
		return err
	}
	ans, err := answer(ch.Question)
	if err != nil {
		return err
	}

	reg := protocol.AgentRegistration{
		Version:     protocol.Version,
		AgentID:     ident.ID,
		PublicKey:   ident.PublicKey(),
		ChallengeID: ch.ChallengeID,
		Answer:      ans,
		PowNonce:    powNonce,
		Timestamp:   time.Now().Unix(),
	}
	msg, err := reg.Canonical()
	if err != nil {
		return err
	}
	body := protocol.AgentRegisterRequest{Registration: reg, Signature: ident.Sign(msg)}
	return c.do(ctx, http.MethodPost, "/v1/agents", body, nil)
}

// BuildRedemption constructs the redemption envelope. It is separated from the
// HTTP call so that tests can hand the exact same bytes to a signer directly,
// with no service in the middle.
func BuildRedemption(ident *Identity, cap Capability, sshLine string, now time.Time) (protocol.RedemptionRequest, error) {
	nonce, err := protocol.NewNonce()
	if err != nil {
		return protocol.RedemptionRequest{}, err
	}
	p := protocol.RedemptionPayload{
		Version:        protocol.Version,
		HostID:         cap.HostID,
		GrantID:        cap.GrantID,
		AgentID:        ident.ID,
		AgentPublicKey: ident.PublicKey(),
		SSHPublicKey:   sshLine,
		Timestamp:      now.Unix(),
		Nonce:          nonce,
	}
	sigMsg, err := p.CanonicalSig()
	if err != nil {
		return protocol.RedemptionRequest{}, err
	}
	// The proof is the only thing that authorizes issuance, and it is computed
	// here from a secret that never touches the network.
	proof, err := p.Proof(cap.Secret)
	if err != nil {
		return protocol.RedemptionRequest{}, err
	}
	return protocol.RedemptionRequest{
		Payload:        p,
		AgentSignature: ident.Sign(sigMsg),
		Proof:          proof,
	}, nil
}

// Redeem exchanges a capability for a certificate.
func (c *Client) Redeem(ctx context.Context, ident *Identity, cap Capability, sshLine string) (protocol.RedemptionResponse, error) {
	req, err := BuildRedemption(ident, cap, sshLine, time.Now())
	if err != nil {
		return protocol.RedemptionResponse{}, err
	}
	var resp protocol.RedemptionResponse
	path := fmt.Sprintf("/v1/hosts/%s/grants/%s/redeem", cap.HostID, cap.GrantID)
	if err := c.do(ctx, http.MethodPost, path, req, &resp); err != nil {
		return protocol.RedemptionResponse{}, err
	}
	return resp, nil
}
