// Command grantctl is what the owner's local agent runs to mint a capability.
//
// It talks only to the signer's owner socket, which is reachable only by the
// enrolled workspace account. Everything it can do is something the protocol
// documents as a plain curl against that socket; this is a convenience, not a
// privileged path.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// Matches the layout install.sh creates. Each socket sits in its own setgid
// directory so the kernel assigns the right group at creation; the directory is
// also what gates traversal, which is why the path has a level the socket name
// alone would not need.
const defaultOwnerSock = "/run/grantd/owner/owner.sock"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "new":
		err = cmdNew(os.Args[2:])
	case "list":
		err = cmdSimple(os.Args[2:], http.MethodGet, "/grants")
	case "status":
		err = cmdSimple(os.Args[2:], http.MethodGet, "/status")
	case "revoke":
		err = cmdRevoke(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "grantctl: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `grantctl — mint and manage grantd capabilities

  grantctl new [--ttl 30m] [--url-only]
  grantctl list
  grantctl status
  grantctl revoke <grant_id>

Flags: --socket PATH (default `+defaultOwnerSock+`)

The capability URL printed by "new" contains the only copy of the grant secret
that leaves this machine. Send it over a channel you trust. It is not recorded
anywhere it can be read back.
`)
}

func client(socket string) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		},
	}
}

func call(socket, method, path string, body any) ([]byte, int, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://signer"+path, rdr)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client(socket).Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("could not reach the signer at %s: %w", socket, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return raw, resp.StatusCode, err
}

func cmdNew(args []string) error {
	fs := flag.NewFlagSet("new", flag.ExitOnError)
	socket := fs.String("socket", envOr("GRANTD_OWNER_SOCK", defaultOwnerSock), "owner socket path")
	ttl := fs.Duration("ttl", 30*time.Minute, "how long the grant stays redeemable")
	urlOnly := fs.Bool("url-only", false, "print just the capability URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw, status, err := call(*socket, http.MethodPost, "/grants",
		map[string]any{"ttl_seconds": int64(ttl.Seconds())})
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("%s", string(raw))
	}
	if *urlOnly {
		var out struct {
			CapabilityURL string `json:"capability_url"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			return err
		}
		fmt.Println(out.CapabilityURL)
		return nil
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, raw, "", "  "); err != nil {
		fmt.Println(string(raw))
		return nil
	}
	fmt.Println(pretty.String())
	return nil
}

func cmdSimple(args []string, method, path string) error {
	fs := flag.NewFlagSet(path, flag.ExitOnError)
	socket := fs.String("socket", envOr("GRANTD_OWNER_SOCK", defaultOwnerSock), "owner socket path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw, status, err := call(*socket, method, path, nil)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("%s", string(raw))
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, raw, "", "  "); err != nil {
		fmt.Println(string(raw))
		return nil
	}
	fmt.Println(pretty.String())
	return nil
}

func cmdRevoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	socket := fs.String("socket", envOr("GRANTD_OWNER_SOCK", defaultOwnerSock), "owner socket path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("revoke takes exactly one grant id")
	}
	raw, status, err := call(*socket, http.MethodDelete, "/grants/"+fs.Arg(0), nil)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("%s", string(raw))
	}
	fmt.Println(string(raw))
	return nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
