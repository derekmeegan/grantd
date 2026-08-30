// Package signerclient is the daemon's only way to reach the signer.
//
// The surface is intentionally tiny. There is no method here that creates a
// grant, signs arbitrary bytes, reads a file, or runs a command, because those
// endpoints do not exist on the daemon socket. A compromised daemon gets
// exactly this list and nothing more.
package signerclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/derekmeegan/grantd/go/internal/protocol"
	"github.com/derekmeegan/grantd/go/signer"
)

// Client talks HTTP over a Unix socket.
type Client struct {
	http *http.Client
}

// New returns a client bound to the signer's daemon socket.
func New(socketPath string) *Client {
	return &Client{
		http: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socketPath)
				},
			},
		},
	}
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://signer"+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if out != nil && resp.StatusCode < 400 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, raw, fmt.Errorf("signerclient: malformed response from %s: %w", path, err)
		}
	}
	return resp.StatusCode, raw, nil
}

// Registration asks the signer for a freshly signed host registration.
func (c *Client) Registration(ctx context.Context) (protocol.HostRegisterRequest, error) {
	var out protocol.HostRegisterRequest
	status, raw, err := c.do(ctx, http.MethodGet, "/registration", nil, &out)
	if err != nil {
		return out, err
	}
	if status >= 400 {
		return out, fmt.Errorf("signerclient: registration: %s", string(raw))
	}
	return out, nil
}

// ConnectAuth asks the signer to sign a rendezvous upgrade for a specific path.
func (c *Client) ConnectAuth(ctx context.Context, path string) (signer.ConnectAuth, error) {
	var out signer.ConnectAuth
	status, raw, err := c.do(ctx, http.MethodPost, "/connect-auth",
		map[string]string{"path": path}, &out)
	if err != nil {
		return out, err
	}
	if status >= 400 {
		return out, fmt.Errorf("signerclient: connect-auth: %s", string(raw))
	}
	return out, nil
}

// PendingPublications returns signed grant metadata still to be published.
func (c *Client) PendingPublications(ctx context.Context) ([]protocol.GrantPublishRequest, error) {
	var out struct {
		Publications []protocol.GrantPublishRequest `json:"publications"`
	}
	status, raw, err := c.do(ctx, http.MethodGet, "/pending-publications", nil, &out)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, fmt.Errorf("signerclient: pending-publications: %s", string(raw))
	}
	return out.Publications, nil
}

// MarkPublished records that the coordination service accepted a grant's
// public metadata.
func (c *Client) MarkPublished(ctx context.Context, grantID string) error {
	status, raw, err := c.do(ctx, http.MethodPost, "/grants/"+grantID+"/published", map[string]any{}, nil)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("signerclient: mark published: %s", string(raw))
	}
	return nil
}

// Redeem forwards a redemption envelope, unchanged, to the signer and returns
// the signer's verdict.
//
// The envelope is passed through as raw bytes rather than re-marshalled. The
// daemon must not be able to reshape what the signer verifies, even by
// accident: a re-serialization that reordered or renormalized a field would put
// the daemon in a position to influence a decision that is supposed to be made
// entirely without trusting it.
func (c *Client) Redeem(ctx context.Context, envelope json.RawMessage) (int, json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://signer/redeem",
		bytes.NewReader(envelope))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, raw, nil
}

// Ping checks that the signer is reachable.
func (c *Client) Ping(ctx context.Context) error {
	status, raw, err := c.do(ctx, http.MethodGet, "/status", nil, nil)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("signerclient: status: %s", string(raw))
	}
	return nil
}
