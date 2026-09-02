// Command grantd is the network-facing half of a grantd host. It keeps a
// connection to the coordination service, publishes signed grant metadata,
// and relays redemption envelopes to the signer. It has no key material.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/derekmeegan/grantd/go/daemon/rendezvous"
	"github.com/derekmeegan/grantd/go/daemon/signerclient"
)

const (
	defaultDaemonSock = "/run/grantd/redeem/redeem.sock"
	// The daemon's systemd unit hides /etc/grantd, which holds the private
	// keys. Its public configuration lives outside that directory.
	defaultConfigFile = "/etc/grantd.conf"
)

func main() {
	fs := flag.NewFlagSet("grantd", flag.ExitOnError)
	origin := fs.String("origin", os.Getenv("GRANTD_ORIGIN"),
		"coordination service origin, e.g. https://grantd.example.workers.dev")
	socket := fs.String("signer-sock", envOr("GRANTD_DAEMON_SOCK", defaultDaemonSock),
		"path to the signer's daemon socket")
	originFile := fs.String("origin-file", envOr("GRANTD_ORIGIN_FILE", defaultConfigFile),
		"file to read the origin from when --origin is not given")
	verbose := fs.Bool("v", false, "verbose logging")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if *origin == "" {
		if b, err := os.ReadFile(*originFile); err == nil {
			*origin = trim(string(b))
		}
	}
	if *origin == "" {
		fmt.Fprintln(os.Stderr, "grantd: no origin configured; pass --origin or write one to "+*originFile)
		os.Exit(2)
	}

	d := rendezvous.New(rendezvous.Config{
		Origin: *origin,
		Signer: signerclient.New(*socket),
		Log:    log,
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("grantd starting", "origin", *origin, "signer_sock", *socket)
	if err := d.Run(ctx); err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "grantd: %v\n", err)
		os.Exit(1)
	}
	log.Info("grantd stopped")
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func trim(s string) string {
	for len(s) > 0 {
		c := s[len(s)-1]
		if c == '\n' || c == '\r' || c == ' ' || c == '\t' {
			s = s[:len(s)-1]
			continue
		}
		break
	}
	return s
}
