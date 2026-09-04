// grantd-bridge carries an SSH session over a WebSocket.
//
// It exists for one situation: a visiting agent in a sandbox whose only
// egress is HTTP over TLS. Such a sandbox cannot open a raw TCP connection to
// port 22, and often cannot open one to 443 either — the gateway inspects the
// first bytes and resets anything that is not a TLS handshake. A WebSocket
// upgrade over TLS is ordinary HTTPS to such a gateway, so the session
// travels as something it already allows.
//
// What this does not change:
//
//   - The coordination service is still not in the path. TLS terminates in
//     nginx on this machine, and this process runs on this machine. A bridged
//     session goes from the visitor to here and nowhere else.
//   - The visitor still pins the host key, and still presents a certificate
//     this host's CA issued. The transport moved; nothing about who may open
//     a session did. That is why the protocol is unchanged.
//
// The target is compiled in. No flag, no header, no query and no path can
// move it, because this process is reachable from nginx and a bug that let a
// request name its own destination would turn it into an open relay on the
// loopback interface. After the upgrade this program parses nothing at all:
// it copies bytes.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/coder/websocket"
)

// target is where every bridged session goes.
//
// A var rather than a const only so that the tests can point it at a stub
// sshd. Nothing reachable from a request writes it: there is no flag, no
// header and no path that reaches this variable, which is the property that
// keeps the bridge from becoming an open relay on the loopback interface.
var target = "127.0.0.1:22"

// maxMessageBytes caps one WebSocket message. SSH packets are far smaller;
// this stops a peer from making the bridge buffer without bound.
const maxMessageBytes = 1 << 20

// maxSessions bounds concurrent sessions. nginx limits connections too; this
// is the backstop for anything that reaches the listener another way.
const maxSessions = 64

// dialTimeout bounds the connection to sshd. Loopback either answers at once
// or is not running.
const dialTimeout = 5 * time.Second

func main() {
	addr := flag.String("listen", "127.0.0.1:8022", "loopback address to listen on")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Refuse to listen anywhere but loopback. nginx terminates TLS and is the
	// only thing that should reach this; a bridge bound to a public address
	// would be an unauthenticated path to sshd that skips nginx's limits.
	if err := checkLoopback(*addr); err != nil {
		log.Error("refusing to start", "err", err)
		os.Exit(1)
	}

	sem := make(chan struct{}, maxSessions)
	mux := http.NewServeMux()
	// One handler for every path. nginx routes only its bridge location here,
	// and the path is not read: it must not be able to say where bytes go.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		serve(w, r, sem, log)
	})

	srv := &http.Server{
		Addr:    *addr,
		Handler: mux,
		// No WriteTimeout: a bridged session is long-lived and idle for most
		// of its life. nginx bounds the idle time instead.
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	log.Info("grantd-bridge listening", "addr", *addr, "target", target)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

// checkLoopback rejects any listen address that is not on the loopback
// interface.
func checkLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("malformed listen address %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("listen address %q is not on the loopback interface", addr)
	}
	return nil
}

func serve(w http.ResponseWriter, r *http.Request, sem chan struct{}, log *slog.Logger) {
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	default:
		http.Error(w, "too many sessions", http.StatusServiceUnavailable)
		return
	}

	// Dial sshd before the upgrade. Failing here returns an HTTP status the
	// visitor can read, rather than a WebSocket that closes immediately.
	upstream, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		log.Error("cannot reach sshd", "err", err)
		http.Error(w, "ssh service unavailable", http.StatusServiceUnavailable)
		return
	}
	defer upstream.Close()

	// OriginPatterns is left at its default, which rejects a cross-origin
	// browser request and permits a client that sends no Origin at all. A
	// command-line visitor sends none; a page on another site cannot drive
	// this.
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		log.Warn("upgrade failed", "err", err)
		return
	}
	c.SetReadLimit(maxMessageBytes)
	defer c.CloseNow()

	log.Info("session opened")
	start := time.Now()

	// Binary, because this carries an SSH transport, not text. From here on
	// the program is a pipe: nothing below inspects a byte.
	down := websocket.NetConn(context.Background(), c, websocket.MessageBinary)

	errc := make(chan error, 2)
	go func() { _, err := io.Copy(upstream, down); errc <- err }()
	go func() { _, err := io.Copy(down, upstream); errc <- err }()
	<-errc

	// Closing both ends unblocks the other copy.
	_ = upstream.Close()
	_ = down.Close()
	log.Info("session closed", "duration", time.Since(start).Round(time.Millisecond))
}
