package warden

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/derekmeegan/grantd/go/internal/protocol"
	"github.com/derekmeegan/grantd/go/signer/api"
)

// GrantInfo is the signer's view of a grant, which is the authority for when
// it ends.
type GrantInfo = api.LifetimeGrant

// GrantSource answers what the signer knows about a grant. The signer is the
// real one; tests use a map.
type GrantSource interface {
	Grant(ctx context.Context, id string) (GrantInfo, error)
	// Ping reports whether the signer is reachable. Reconciliation uses it to
	// refuse to open admission until the deadline authority can be reached.
	Ping(ctx context.Context) error
}

// ErrGrantUnknown reports a grant id the signer has never seen or has purged.
var ErrGrantUnknown = errors.New("warden: signer does not know this grant")

// SignerClient reads grant state over the lifetime socket.
type SignerClient struct {
	http *http.Client
}

// NewSignerClient connects to the signer's lifetime socket at path.
func NewSignerClient(path string) *SignerClient {
	return &SignerClient{http: &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		},
	}}
}

func (c *SignerClient) Grant(ctx context.Context, id string) (GrantInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://signer/grants/"+id, nil)
	if err != nil {
		return GrantInfo{}, err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return GrantInfo{}, fmt.Errorf("warden: signer unreachable: %w", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 64*1024))
	if err != nil {
		return GrantInfo{}, err
	}
	if res.StatusCode == http.StatusNotFound {
		return GrantInfo{}, ErrGrantUnknown
	}
	if res.StatusCode != http.StatusOK {
		var e struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Error.Code == protocol.ErrCodeGrantNotFound {
			return GrantInfo{}, ErrGrantUnknown
		}
		return GrantInfo{}, fmt.Errorf("warden: signer returned %d for grant %s", res.StatusCode, id)
	}
	var g GrantInfo
	if err := json.Unmarshal(body, &g); err != nil {
		return GrantInfo{}, fmt.Errorf("warden: signer response: %w", err)
	}
	if g.ID != id {
		return GrantInfo{}, fmt.Errorf("warden: signer answered for %s, asked about %s", g.ID, id)
	}
	return g, nil
}

// Ping reports whether the signer answers on the lifetime socket.
func (c *SignerClient) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://signer/status", nil)
	if err != nil {
		return err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("warden: signer status returned %d", res.StatusCode)
	}
	return nil
}
