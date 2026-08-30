// Command grant-signer is the trust root. It holds the host identity key and
// the SSH CA key, owns the authoritative grant database, and is the only
// process that can issue a certificate.
//
// It never opens a network socket. Every input arrives over one of two Unix
// sockets, and every input is treated as hostile.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/derekmeegan/grantd/go/internal/idkey"
	"github.com/derekmeegan/grantd/go/internal/protocol"
	"github.com/derekmeegan/grantd/go/signer"
	"github.com/derekmeegan/grantd/go/signer/api"
	"github.com/derekmeegan/grantd/go/signer/store"
)

const (
	defaultKeyDir     = "/etc/grantd"
	defaultStatePath  = "/var/lib/grant-signer/state.db"
	defaultOwnerSock  = "/run/grantd/owner.sock"
	defaultDaemonSock = "/run/grantd/redeem.sock"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:], log)
	case "serve":
		err = cmdServe(os.Args[2:], log)
	case "status":
		err = cmdStatus(os.Args[2:])
	case "destroy":
		err = cmdDestroy(os.Args[2:], log)
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "grant-signer: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `grant-signer — grantd local trust root

  grant-signer init    --ssh-user U --hostname H [--port 22] [--origin URL]
  grant-signer serve   [--owner-uid N] [--daemon-uid N]
  grant-signer status
  grant-signer destroy --yes

Common flags: --key-dir, --state, --owner-sock, --daemon-sock
`)
}

type paths struct {
	keyDir     string
	state      string
	ownerSock  string
	daemonSock string
	origin     string
}

func (p *paths) bind(fs *flag.FlagSet) {
	fs.StringVar(&p.keyDir, "key-dir", envOr("GRANTD_KEY_DIR", defaultKeyDir), "directory holding host identity and SSH CA keys")
	fs.StringVar(&p.state, "state", envOr("GRANTD_STATE", defaultStatePath), "path to the signer state database")
	fs.StringVar(&p.ownerSock, "owner-sock", envOr("GRANTD_OWNER_SOCK", defaultOwnerSock), "owner Unix socket path")
	fs.StringVar(&p.daemonSock, "daemon-sock", envOr("GRANTD_DAEMON_SOCK", defaultDaemonSock), "daemon Unix socket path")
	fs.StringVar(&p.origin, "origin", envOr("GRANTD_ORIGIN", ""), "coordination service origin, e.g. https://grantd.example.workers.dev")
}

func (p paths) identityKey() string { return filepath.Join(p.keyDir, "host_identity") }
func (p paths) caKey() string       { return filepath.Join(p.keyDir, "ssh_ca") }
func (p paths) caPub() string       { return filepath.Join(p.keyDir, "ssh_ca.pub") }
func (p paths) originFile() string  { return filepath.Join(p.keyDir, "origin") }

func (p paths) signerConfig() signer.Config {
	return signer.Config{
		HostIdentityKeyPath: p.identityKey(),
		SSHCAKeyPath:        p.caKey(),
		StatePath:           p.state,
		Origin:              p.origin,
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// resolveOrigin lets the origin be pinned on disk at init time so that later
// invocations do not have to be told again, and so that a capability URL never
// depends on an environment variable the caller controls.
func (p *paths) resolveOrigin() {
	if p.origin != "" {
		return
	}
	if b, err := os.ReadFile(p.originFile()); err == nil {
		p.origin = string(trimNewline(b))
	}
}

func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}

// ------------------------------------------------------------------------ init

func cmdInit(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	var p paths
	p.bind(fs)
	sshUser := fs.String("ssh-user", "", "the login account visiting agents will use (root is rejected)")
	hostname := fs.String("hostname", "", "address a visiting agent will SSH to")
	port := fs.Uint64("port", 22, "SSH port")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sshUser == "" || *hostname == "" {
		return errors.New("init requires --ssh-user and --hostname")
	}
	if err := protocol.ValidateSSHUser(*sshUser); err != nil {
		return err
	}

	if err := os.MkdirAll(p.keyDir, idkey.KeyDirMode); err != nil {
		return err
	}
	if err := os.Chmod(p.keyDir, idkey.KeyDirMode); err != nil {
		return err
	}

	// Two independent keys. Reusing one key across the application signature
	// protocol and the SSH certificate protocol would mean a flaw in either
	// one compromises both.
	if err := generateIfMissing(p.identityKey(), "", log, "host identity"); err != nil {
		return err
	}
	if err := generateIfMissing(p.caKey(), p.caPub(), log, "ssh ca"); err != nil {
		return err
	}
	if p.origin != "" {
		if err := os.WriteFile(p.originFile(), []byte(p.origin+"\n"), 0o644); err != nil {
			return err
		}
	}
	p.resolveOrigin()

	s, err := signer.Open(p.signerConfig())
	if err != nil {
		return err
	}
	defer s.Close()

	ctx := context.Background()
	if err := s.Enroll(ctx, *sshUser, *hostname, *port); err != nil {
		return err
	}
	hostID, err := s.HostID()
	if err != nil {
		return err
	}
	caLine, err := s.SSHCAPublicKeyLine()
	if err != nil {
		return err
	}
	out, _ := json.MarshalIndent(map[string]any{
		"host_id":           hostID,
		"ssh_user":          *sshUser,
		"hostname":          *hostname,
		"ssh_port":          *port,
		"ssh_ca_public_key": caLine,
		"state":             p.state,
	}, "", "  ")
	fmt.Println(string(out))
	return nil
}

func generateIfMissing(privPath, pubPath string, log *slog.Logger, what string) error {
	if _, err := os.Stat(privPath); err == nil {
		log.Info("key already present, leaving it alone", "what", what, "path", privPath)
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	pub, priv, err := idkey.Generate()
	if err != nil {
		return err
	}
	if err := idkey.SavePrivate(privPath, priv); err != nil {
		return err
	}
	if pubPath != "" {
		if err := idkey.SavePublicSSH(pubPath, pub, "grantd-ca"); err != nil {
			return err
		}
	}
	log.Info("generated key", "what", what, "path", privPath)
	return nil
}

// ----------------------------------------------------------------------- serve

func cmdServe(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var p paths
	p.bind(fs)
	ownerUID := fs.Int("owner-uid", -1, "uid permitted on the owner socket (-1 to rely on file permissions)")
	daemonUID := fs.Int("daemon-uid", -1, "uid permitted on the daemon socket (-1 to rely on file permissions)")
	purgeEvery := fs.Duration("purge-interval", 10*time.Minute, "how often to purge expired grants")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p.resolveOrigin()

	s, err := signer.Open(p.signerConfig())
	if err != nil {
		return err
	}
	defer s.Close()

	srv := &api.Server{Signer: s, Log: log}

	ownerLn, err := listen(p.ownerSock, 0o660, *ownerUID, log, "owner")
	if err != nil {
		return err
	}
	defer ownerLn.Close()
	daemonLn, err := listen(p.daemonSock, 0o660, *daemonUID, log, "daemon")
	if err != nil {
		return err
	}
	defer daemonLn.Close()

	ownerSrv := &http.Server{Handler: srv.OwnerHandler(), ReadHeaderTimeout: 5 * time.Second}
	daemonSrv := &http.Server{Handler: srv.DaemonHandler(), ReadHeaderTimeout: 5 * time.Second}

	go func() {
		if err := ownerSrv.Serve(ownerLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("owner socket server stopped", "err", err)
		}
	}()
	go func() {
		if err := daemonSrv.Serve(daemonLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("daemon socket server stopped", "err", err)
		}
	}()

	hostID, _ := s.HostID()
	log.Info("signer ready", "host_id", hostID, "owner_sock", p.ownerSock, "daemon_sock", p.daemonSock)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ticker := time.NewTicker(*purgeEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = ownerSrv.Shutdown(shutCtx)
			_ = daemonSrv.Shutdown(shutCtx)
			log.Info("signer stopped")
			return nil
		case <-ticker.C:
			// Expired grants are useless and their secrets should not linger.
			if n, err := s.Store().PurgeExpired(context.Background(), time.Now().Unix(), 24*3600); err != nil {
				log.Error("purge failed", "err", err)
			} else if n > 0 {
				log.Info("purged expired grants", "count", n)
			}
		}
	}
}

func listen(path string, mode os.FileMode, uid int, log *slog.Logger, which string) (net.Listener, error) {
	ln, err := api.Listen(path, mode)
	if err != nil {
		return nil, err
	}
	if uid < 0 {
		return ln, nil
	}
	return &api.PeerFilter{
		Listener:    ln,
		AllowedUIDs: []uint32{uint32(uid)},
		OnReject: func(peer uint32, err error) {
			log.Warn("rejected socket peer", "socket", which, "uid", peer, "err", err)
		},
	}, nil
}

// ---------------------------------------------------------------------- status

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	var p paths
	p.bind(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	p.resolveOrigin()
	s, err := signer.Open(p.signerConfig())
	if err != nil {
		return err
	}
	defer s.Close()
	ctx := context.Background()
	h, err := s.Host(ctx)
	if err != nil {
		if errors.Is(err, store.ErrNoHost) {
			return errors.New("not enrolled; run grant-signer init")
		}
		return err
	}
	grants, err := s.ListGrants(ctx)
	if err != nil {
		return err
	}
	out, _ := json.MarshalIndent(map[string]any{
		"host_id":  h.HostID,
		"ssh_user": h.SSHUser,
		"hostname": h.Hostname,
		"ssh_port": h.SSHPort,
		"origin":   p.origin,
		"grants":   grants,
	}, "", "  ")
	fmt.Println(string(out))
	return nil
}

// --------------------------------------------------------------------- destroy

func cmdDestroy(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("destroy", flag.ExitOnError)
	var p paths
	p.bind(fs)
	yes := fs.Bool("yes", false, "confirm irreversible destruction of key material")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*yes {
		return errors.New("destroy requires --yes; this permanently removes the SSH CA and host identity keys")
	}
	// Overwrite before unlinking. On a journaling filesystem this is not a
	// guarantee, but leaving the bytes readable in freed blocks is strictly
	// worse than not trying.
	for _, path := range []string{p.identityKey(), p.caKey(), p.state, p.state + "-wal", p.state + "-shm"} {
		if err := shred(path); err != nil && !os.IsNotExist(err) {
			log.Warn("could not remove", "path", path, "err", err)
		}
	}
	for _, path := range []string{p.caPub(), p.originFile(), p.ownerSock, p.daemonSock} {
		_ = os.Remove(path)
	}
	log.Info("signer key material and state destroyed")
	return nil
}

func shred(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err == nil {
		zeros := make([]byte, 4096)
		remaining := info.Size()
		for remaining > 0 {
			n := int64(len(zeros))
			if remaining < n {
				n = remaining
			}
			if _, werr := f.Write(zeros[:n]); werr != nil {
				break
			}
			remaining -= n
		}
		_ = f.Sync()
		f.Close()
	}
	return os.Remove(path)
}
