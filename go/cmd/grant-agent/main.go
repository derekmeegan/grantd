// Command grant-agent is the visiting side: it turns a capability URL into an
// SSH session.
//
// Everything it does is something an agent could do with curl and ssh-keygen —
// the protocol is designed so that no SDK is required. This binary exists
// because doing it correctly by hand every time is tedious, not because the
// wire protocol needs a client library.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"

	"flag"

	"github.com/derekmeegan/grantd/go/agent"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "register":
		err = cmdRegister(os.Args[2:])
	case "redeem":
		err = cmdRedeem(os.Args[2:], false)
	case "ssh":
		err = cmdRedeem(os.Args[2:], true)
	case "id":
		err = cmdID(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "grant-agent: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `grant-agent — redeem a grantd capability

  grant-agent register --origin URL
  grant-agent redeem   <capability-url>       write key + certificate, print the ssh command
  grant-agent ssh      <capability-url> [--] [command...]
  grant-agent id

Flags: --identity PATH (default ~/.grantd/agent_identity), --out DIR
`)
}

func defaultIdentityPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "grantd_agent_identity"
	}
	return filepath.Join(home, ".grantd", "agent_identity")
}

func cmdID(args []string) error {
	fs := flag.NewFlagSet("id", flag.ExitOnError)
	identity := fs.String("identity", defaultIdentityPath(), "path to the agent identity key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ident, err := agent.LoadIdentity(*identity)
	if err != nil {
		return err
	}
	fmt.Println(ident.ID)
	return nil
}

func cmdRegister(args []string) error {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	origin := fs.String("origin", os.Getenv("GRANTD_ORIGIN"), "coordination service origin")
	identity := fs.String("identity", defaultIdentityPath(), "path to the agent identity key")
	answer := fs.String("answer", "", "answer the captcha question yourself instead of using the reference solver")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *origin == "" {
		return fmt.Errorf("register requires --origin")
	}
	ident, err := agent.LoadIdentity(*identity)
	if err != nil {
		return err
	}
	client := agent.NewClient(*origin)

	answerFn := agent.AnswerFunc(agent.ReferenceAnswer)
	if *answer != "" {
		answerFn = func(string) (string, error) { return *answer, nil }
	}
	if err := client.Register(context.Background(), ident, answerFn); err != nil {
		return err
	}
	fmt.Printf("registered %s at %s\n", ident.ID, *origin)
	return nil
}

func cmdRedeem(args []string, connect bool) error {
	fs := flag.NewFlagSet("redeem", flag.ExitOnError)
	identity := fs.String("identity", defaultIdentityPath(), "path to the agent identity key")
	out := fs.String("out", "", "directory for the ephemeral key and certificate (default: a new temp dir)")
	register := fs.Bool("register", true, "register the agent identity first if the service does not know it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) < 1 {
		return fmt.Errorf("a capability URL is required")
	}
	capURL := rest[0]
	sshArgs := rest[1:]

	cap, err := agent.ParseCapabilityURL(capURL)
	if err != nil {
		return err
	}
	ident, err := agent.LoadIdentity(*identity)
	if err != nil {
		return err
	}
	client := agent.NewClient(cap.Origin)
	ctx := context.Background()

	if *register {
		// Registration is idempotent and cheap to retry; doing it unconditionally
		// on first use means an agent that has never seen this service still
		// works from a single command.
		if err := client.EnsureRegistered(ctx, ident, agent.ReferenceAnswer); err != nil {
			return err
		}
	}

	dir := *out
	if dir == "" {
		dir, err = os.MkdirTemp("", "grantd-*")
		if err != nil {
			return err
		}
	} else if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	// The SSH private key is generated here and written only here. It is never
	// sent anywhere, and the certificate is issued over its public half.
	key, err := agent.NewEphemeralSSHKey()
	if err != nil {
		return err
	}
	keyPath := filepath.Join(dir, "id_ed25519")
	if err := key.WriteOpenSSH(keyPath); err != nil {
		return err
	}

	resp, err := client.Redeem(ctx, ident, cap, key.Line)
	if err != nil {
		return err
	}
	certPath := keyPath + "-cert.pub"
	if err := os.WriteFile(certPath, []byte(resp.Certificate+"\n"), 0o644); err != nil {
		return err
	}

	if !connect {
		summary, _ := json.MarshalIndent(map[string]any{
			"hostname":     resp.Hostname,
			"port":         resp.Port,
			"user":         resp.User,
			"key":          keyPath,
			"certificate":  certPath,
			"serial":       strconv.FormatUint(resp.Serial, 10),
			"key_id":       resp.KeyID,
			"valid_before": resp.ValidBefore,
			"ssh": fmt.Sprintf("ssh -i %s -o CertificateFile=%s -p %d %s@%s",
				keyPath, certPath, resp.Port, resp.User, resp.Hostname),
		}, "", "  ")
		fmt.Println(string(summary))
		return nil
	}

	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("ssh not found in PATH: %w", err)
	}
	argv := []string{
		"ssh",
		"-i", keyPath,
		"-o", "CertificateFile=" + certPath,
		"-o", "IdentitiesOnly=yes",
		"-p", strconv.FormatUint(resp.Port, 10),
		resp.User + "@" + resp.Hostname,
	}
	argv = append(argv, sshArgs...)
	return syscall.Exec(sshPath, argv, os.Environ())
}
