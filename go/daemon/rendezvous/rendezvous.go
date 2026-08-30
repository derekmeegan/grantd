// Package rendezvous maintains the daemon's outbound connection to the
// coordination service and relays redemption requests to the signer.
//
// The daemon is the network-facing process and is assumed to be the one that
// gets compromised. It is written accordingly: it holds no key, it can ask the
// signer for exactly four things, and the only message it ever acts on is a
// redemption envelope that the signer will independently verify from scratch.
package rendezvous

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/derekmeegan/grantd/go/daemon/signerclient"
	"github.com/derekmeegan/grantd/go/internal/protocol"
)

// Tuning for the reconnect loop and liveness checks.
const (
	minBackoff       = 1 * time.Second
	maxBackoff       = 60 * time.Second
	pingInterval     = 45 * time.Second
	publishInterval  = 2 * time.Second
	redeemTimeout    = 15 * time.Second
	maxFrameBytes    = 128 * 1024
	handshakeTimeout = 20 * time.Second
)

// Config describes where to connect and how to reach the signer.
type Config struct {
	Origin string
	Signer *signerclient.Client
	Log    *slog.Logger
}

// Daemon runs the rendezvous loop.
type Daemon struct {
	cfg  Config
	log  *slog.Logger
	http *http.Client
}

// New builds a daemon.
func New(cfg Config) *Daemon {
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	return &Daemon{
		cfg:  cfg,
		log:  log,
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

// Run connects, serves, and reconnects until the context is cancelled.
func (d *Daemon) Run(ctx context.Context) error {
	backoff := minBackoff
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err := d.session(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			d.log.Warn("rendezvous session ended", "err", err, "retry_in", backoff)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(jitter(backoff)):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
		if err == nil {
			backoff = minBackoff
		}
	}
}

// jitter spreads reconnect attempts so that a service restart does not bring
// every host back at the same instant.
func jitter(d time.Duration) time.Duration {
	return d/2 + time.Duration(rand.Int63n(int64(d)))
}

// session runs one connection from registration to disconnect.
func (d *Daemon) session(ctx context.Context) error {
	if err := d.cfg.Signer.Ping(ctx); err != nil {
		return fmt.Errorf("signer unreachable: %w", err)
	}
	reg, err := d.register(ctx)
	if err != nil {
		return err
	}
	hostID := reg.Registration.HostID

	path := fmt.Sprintf("/v1/hosts/%s/connect", hostID)
	auth, err := d.cfg.Signer.ConnectAuth(ctx, path)
	if err != nil {
		return fmt.Errorf("connect auth: %w", err)
	}

	dialCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()

	conn, resp, err := websocket.Dial(dialCtx, wsURL(d.cfg.Origin, path), &websocket.DialOptions{
		HTTPClient: d.http,
		HTTPHeader: http.Header{
			"X-Grantd-Timestamp": []string{fmt.Sprintf("%d", auth.Timestamp)},
			"X-Grantd-Nonce":     []string{auth.Nonce},
			"X-Grantd-Signature": []string{auth.Signature},
		},
	})
	if err != nil {
		if resp != nil {
			return fmt.Errorf("rendezvous dial: http %d: %w", resp.StatusCode, err)
		}
		return fmt.Errorf("rendezvous dial: %w", err)
	}
	conn.SetReadLimit(maxFrameBytes)
	defer conn.CloseNow()

	d.log.Info("rendezvous connected", "host_id", hostID, "origin", d.cfg.Origin)

	sessionCtx, stop := context.WithCancel(ctx)
	defer stop()

	go d.publishLoop(sessionCtx, hostID)
	go d.pingLoop(sessionCtx, conn)

	for {
		_, data, err := conn.Read(sessionCtx)
		if err != nil {
			if sessionCtx.Err() != nil {
				return nil
			}
			return fmt.Errorf("rendezvous read: %w", err)
		}
		d.handleFrame(sessionCtx, conn, data)
	}
}

func wsURL(origin, path string) string {
	u := strings.TrimSuffix(origin, "/") + path
	if strings.HasPrefix(u, "https://") {
		return "wss://" + strings.TrimPrefix(u, "https://")
	}
	if strings.HasPrefix(u, "http://") {
		return "ws://" + strings.TrimPrefix(u, "http://")
	}
	return u
}

// register publishes the host's public record. It is idempotent and is redone
// on every reconnect so that a host that changed address recovers on its own.
func (d *Daemon) register(ctx context.Context) (protocol.HostRegisterRequest, error) {
	reg, err := d.cfg.Signer.Registration(ctx)
	if err != nil {
		return reg, fmt.Errorf("registration: %w", err)
	}
	body, err := json.Marshal(reg)
	if err != nil {
		return reg, err
	}
	url := fmt.Sprintf("%s/v1/hosts/%s", strings.TrimSuffix(d.cfg.Origin, "/"), reg.Registration.HostID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, strings.NewReader(string(body)))
	if err != nil {
		return reg, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.http.Do(req)
	if err != nil {
		return reg, fmt.Errorf("register: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return reg, fmt.Errorf("register: http %d", resp.StatusCode)
	}
	return reg, nil
}

// publishLoop pushes signed grant metadata that has not been accepted yet.
//
// Polling rather than being pushed to is deliberate: a grant created while the
// network was down is published as soon as connectivity returns, with no queue
// to lose and no notification to miss.
func (d *Daemon) publishLoop(ctx context.Context, hostID string) {
	t := time.NewTicker(publishInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		pending, err := d.cfg.Signer.PendingPublications(ctx)
		if err != nil {
			if ctx.Err() == nil {
				d.log.Warn("could not read pending publications", "err", err)
			}
			continue
		}
		for _, pub := range pending {
			if err := d.publish(ctx, hostID, pub); err != nil {
				d.log.Warn("publish failed", "grant_id", pub.Grant.GrantID, "err", err)
				break
			}
			if err := d.cfg.Signer.MarkPublished(ctx, pub.Grant.GrantID); err != nil {
				d.log.Warn("could not record publication", "grant_id", pub.Grant.GrantID, "err", err)
			} else {
				d.log.Info("grant published", "grant_id", pub.Grant.GrantID)
			}
		}
	}
}

func (d *Daemon) publish(ctx context.Context, hostID string, pub protocol.GrantPublishRequest) error {
	body, err := json.Marshal(pub)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/v1/hosts/%s/grants/%s",
		strings.TrimSuffix(d.cfg.Origin, "/"), hostID, pub.Grant.GrantID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	return nil
}

func (d *Daemon) pingLoop(ctx context.Context, conn *websocket.Conn) {
	t := time.NewTicker(pingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		ctxPing, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := conn.Ping(ctxPing)
		cancel()
		if err != nil {
			return
		}
	}
}

// handleFrame dispatches one rendezvous message.
//
// The switch is exhaustive and closed. There is no default branch that
// interprets anything, and no frame type in the protocol that carries a
// command, a path, or a filename — the coordination service must not be able to
// ask this machine to do anything except answer a redemption the signer can
// verify on its own.
func (d *Daemon) handleFrame(ctx context.Context, conn *websocket.Conn, data []byte) {
	var frame protocol.Frame
	if err := json.Unmarshal(data, &frame); err != nil {
		d.log.Warn("dropping unparseable frame")
		return
	}
	switch frame.Type {
	case protocol.FrameHello:
		if frame.ProtocolVersion != protocol.Version {
			d.log.Warn("service announced a different protocol version",
				"theirs", frame.ProtocolVersion, "ours", protocol.Version)
		}
	case protocol.FramePing:
		d.send(ctx, conn, protocol.Frame{Type: protocol.FramePong, ID: frame.ID})
	case protocol.FrameRedeemRequest:
		go d.handleRedeem(ctx, conn, frame)
	default:
		d.log.Warn("dropping unknown frame type", "type", frame.Type)
	}
}

func (d *Daemon) handleRedeem(ctx context.Context, conn *websocket.Conn, frame protocol.Frame) {
	ctx, cancel := context.WithTimeout(ctx, redeemTimeout)
	defer cancel()

	envelope, err := frame.Body()
	if err != nil || len(envelope) == 0 {
		d.replyError(ctx, conn, frame.ID, protocol.ErrCodeBadRequest, "empty or malformed redemption envelope")
		return
	}

	// Forwarded verbatim. The signer verifies these exact bytes; anything this
	// process did to them would be an opportunity to influence a decision it is
	// not trusted to make.
	status, body, err := d.cfg.Signer.Redeem(ctx, envelope)
	if err != nil {
		d.log.Error("signer redemption call failed", "err", err)
		d.replyError(ctx, conn, frame.ID, protocol.ErrCodeInternal, "signer unavailable")
		return
	}
	resp := protocol.Frame{Type: protocol.FrameRedeemResponse, ID: frame.ID, Status: status}
	resp.SetBody(body)
	d.send(ctx, conn, resp)
}

func (d *Daemon) replyError(ctx context.Context, conn *websocket.Conn, id, code, msg string) {
	f := protocol.Frame{
		Type:   protocol.FrameRedeemResponse,
		ID:     id,
		Status: protocol.HTTPStatusFor(code),
	}
	f.SetBody(protocol.MarshalErrorBody(code, msg))
	d.send(ctx, conn, f)
}

func (d *Daemon) send(ctx context.Context, conn *websocket.Conn, frame protocol.Frame) {
	data, err := json.Marshal(frame)
	if err != nil {
		d.log.Error("could not marshal frame", "type", frame.Type, "err", err)
		return
	}
	writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := conn.Write(writeCtx, websocket.MessageText, data); err != nil &&
		!errors.Is(err, context.Canceled) {
		d.log.Warn("could not send frame", "type", frame.Type, "err", err)
	}
}
