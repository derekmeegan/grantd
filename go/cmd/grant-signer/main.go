// Command grant-signer is the trust root. It holds the host identity key and
// the SSH CA key, owns the grant database, and is the only process that can
// issue a certificate. It never opens a network socket.
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
	"strings"
	"syscall"
	"time"

	"github.com/derekmeegan/grantd/go/internal/idkey"
	"github.com/derekmeegan/grantd/go/internal/protocol"
	"github.com/derekmeegan/grantd/go/signer"
	"github.com/derekmeegan/grantd/go/signer/api"
	"github.com/derekmeegan/grantd/go/signer/store"
)

const (
	defaultKeyDir    = "/etc/grantd"
	defaultStatePath = "/var/lib/grant-signer/state.db"
	// Each socket lives in its own setgid directory; see install/install.sh.
	defaultOwnerSock  = "/run/grantd/owner/owner.sock"
	defaultDaemonSock = "/run/grantd/redeem/redeem.sock"
)

// defaultHostKeyFile is where OpenSSH keeps the public half of the ed25519
// host key on every distribution grantd supports. It is world-readable.
const defaultHostKeyFile = "/etc/ssh/ssh_host_ed25519_key.pub"

// readSSHHostKey loads this machine's sshd host key and reduces it to the exact
// two-field form the protocol signs. The file usually carries a third field,
// a comment, which is not part of the key and would change the signed bytes,
// so it is dropped. Everything else is validated by the signer.
func readSSHHostKey(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading the ssh host key at %s: %w\n"+
			"  grantd publishes this key so a visiting agent can verify the machine it reaches.\n"+
			"  Generate host keys with 'ssh-keygen -A' as root, or pass --ssh-host-key-file.", path, err)
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 2 {
		return "", fmt.Errorf("%s does not look like an ssh public key", path)
	}
	line := fields[0] + " " + fields[1]
	if _, err := protocol.ParseSSHPublicKey(line); err != nil {
		return "", fmt.Errorf("the ssh host key at %s is not usable: %w\n"+
			"  grantd v1 pins a single ssh-ed25519 host key.", path, err)
	}
	return line, nil
}

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

  grant-signer init    --ssh-user U (--hostname H | --dns-suffix D) [--port 22] [--origin URL]
                       [--ssh-host-key-file /etc/ssh/ssh_host_ed25519_key.pub]
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
	// The signer's origin is the public address that goes into capability
	// URLs. The daemon's origin (GRANTD_ORIGIN) is where this machine dials
	// out. Behind NAT or in a container the two differ.
	fs.StringVar(&p.origin, "origin", envOr("GRANTD_PUBLIC_ORIGIN", ""),
		"public origin to embed in capability URLs, e.g. https://grantd.example.workers.dev")
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

// resolveOrigin reads the origin pinned on disk at init time, so that later
// runs do not depend on an environment variable.
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
	dnsSuffix := fs.String("dns-suffix", "", "let the service name this host under a suffix it manages, e.g. hosts.grantd.dev")
	port := fs.Uint64("port", 22, "SSH port")
	hostKeyFile := fs.String("ssh-host-key-file",
		envOr("GRANTD_SSH_HOST_KEY_FILE", defaultHostKeyFile),
		"public half of this machine's sshd ed25519 host key, published for visitors to pin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sshUser == "" {
		return errors.New("init requires --ssh-user")
	}
	// Exactly one. The two answer the same question — what does a visiting
	// agent dial — and taking both would leave which one won up to reading
	// the source.
	if (*hostname == "") == (*dnsSuffix == "") {
		return errors.New("init requires exactly one of --hostname or --dns-suffix")
	}
	if err := protocol.ValidateSSHUser(*sshUser); err != nil {
		return err
	}
	if *dnsSuffix != "" {
		if err := protocol.ValidateDNSSuffix(*dnsSuffix); err != nil {
			return err
		}
	}
	hostKeyLine, err := readSSHHostKey(*hostKeyFile)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(p.keyDir, idkey.KeyDirMode); err != nil {
		return err
	}
	if err := os.Chmod(p.keyDir, idkey.KeyDirMode); err != nil {
		return err
	}

	// Two separate keys, so that a flaw in one protocol cannot reach the other.
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

	hostID, err := s.HostID()
	if err != nil {
		return err
	}

	// With --dns-suffix the address is derived from the host id rather than
	// supplied. The service derives the same name and will write a record for
	// that name and no other, so the two must agree exactly. Deriving it here
	// also means the name is inside the signed registration: asking for a
	// name and proving the key are one act.
	enrollHostname := *hostname
	if *dnsSuffix != "" {
		enrollHostname, err = protocol.HostDNSName(hostID, *dnsSuffix)
		if err != nil {
			return err
		}
	}

	ctx := context.Background()
	if err := s.Enroll(ctx, *sshUser, enrollHostname, *port, hostKeyLine); err != nil {
		return err
	}
	caLine, err := s.SSHCAPublicKeyLine()
	if err != nil {
		return err
	}
	out, _ := json.MarshalIndent(map[string]any{
		"host_id":             hostID,
		"ssh_user":            *sshUser,
		"hostname":            enrollHostname,
		"ssh_port":            *port,
		"ssh_ca_public_key":   caLine,
		"ssh_host_public_key": hostKeyLine,
		"state":               p.state,
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
	ownerGID := fs.Int("owner-gid", -1, "group to own the owner socket (-1 to leave as created)")
	daemonGID := fs.Int("daemon-gid", -1, "group to own the daemon socket (-1 to leave as created)")
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

	ownerLn, err := listen(p.ownerSock, 0o660, *ownerUID, *ownerGID, log, "owner")
	if err != nil {
		return err
	}
	defer ownerLn.Close()
	daemonLn, err := listen(p.daemonSock, 0o660, *daemonUID, *daemonGID, log, "daemon")
	if err != nil {
		return err
	}
	defer daemonLn.Close()

	ownerSrv := socketServer(srv.OwnerHandler())
	daemonSrv := socketServer(srv.DaemonHandler())

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
			// Delete expired grants so that their secrets do not linger.
			if n, err := s.Store().PurgeExpired(context.Background(), time.Now().Unix(), 24*3600); err != nil {
				log.Error("purge failed", "err", err)
			} else if n > 0 {
				log.Info("purged expired grants", "count", n)
			}
		}
	}
}

// socketServer builds an HTTP server with timeouts, so that a stuck local
// client cannot hold a connection open forever.
func socketServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func listen(path string, mode os.FileMode, uid, gid int, log *slog.Logger, which string) (net.Listener, error) {
	ln, err := api.Listen(path, mode, -1, gid)
	if err != nil {
		return nil, err
	}
	if info, serr := os.Stat(path); serr == nil {
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			log.Info("socket ready", "socket", which, "path", path,
				"uid", st.Uid, "gid", st.Gid, "mode", fmt.Sprintf("%04o", info.Mode().Perm()))
		}
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
		"host_id":             h.HostID,
		"ssh_user":            h.SSHUser,
		"hostname":            h.Hostname,
		"ssh_port":            h.SSHPort,
		"ssh_host_public_key": h.SSHHostPublicKey,
		"origin":              p.origin,
		"grants":              grants,
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
	// Overwrite before unlinking. A journaling filesystem gives no guarantee,
	// but it is better than leaving the bytes in freed blocks.
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
