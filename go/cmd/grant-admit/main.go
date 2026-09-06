// Command grant-admit is the small program sshd runs at two points in a
// visitor's login. It carries no policy: it relays what sshd verified to the
// warden and does what the warden says.
//
//	grant-admit principals USER CERT_TYPE CERT_B64
//	    The AuthorizedPrincipalsCommand. sshd has already verified the
//	    certificate against the CA. This prints the principals the warden
//	    allows (one line), or nothing to refuse. It always exits 0: an empty
//	    list is how sshd is told to refuse, and a warden that cannot be reached
//	    yields an empty list, so an unreachable warden fails closed.
//
//	grant-admit attach
//	    The PAM session hook, run as root before the visitor's shell starts.
//	    It asks the warden to place this session's sshd process into the
//	    grant's cgroup. It exits non-zero if the warden refuses or cannot be
//	    reached, so PAM fails the session and sshd closes the connection:
//	    a session is never started outside its containment.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

func sockPath() string {
	if v := os.Getenv("GRANTD_ADMIT_SOCK"); v != "" {
		return v
	}
	return "/run/grantd/warden/admit.sock"
}

func client() *http.Client {
	path := sockPath()
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		},
	}
}

func post(path string, body any) (*http.Response, []byte, error) {
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, "http://warden"+path, bytes.NewReader(b))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client().Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(res.Body, 64*1024))
	return res, data, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: grant-admit principals|attach ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "principals":
		principals()
	case "attach":
		attach()
	default:
		fmt.Fprintln(os.Stderr, "grant-admit: unknown mode "+os.Args[1])
		os.Exit(2)
	}
}

// principals prints the allowed principals, or nothing. It never errors out in
// a way that would let a session through: refusal is an empty list.
func principals() {
	if len(os.Args) != 5 {
		// Misconfiguration. Refuse by printing nothing.
		return
	}
	user, certType, certB64 := os.Args[2], os.Args[3], os.Args[4]
	res, data, err := post("/principals", map[string]string{
		"user": user, "cert_type": certType, "cert_b64": certB64,
	})
	if err != nil || res.StatusCode != http.StatusOK {
		// Unreachable or refused: print nothing, which tells sshd to refuse.
		return
	}
	var out struct {
		Principals []string `json:"principals"`
	}
	if json.Unmarshal(data, &out) != nil {
		return
	}
	for _, p := range out.Principals {
		fmt.Println(p)
	}
}

// attach fails the login unless the warden confirms the session is contained.
func attach() {
	user := os.Getenv("PAM_USER")
	if user == "" && len(os.Args) >= 3 {
		user = os.Args[2]
	}
	if user == "" {
		fmt.Fprintln(os.Stderr, "grant-admit attach: no PAM_USER")
		os.Exit(1)
	}
	res, data, err := post("/attach", map[string]string{"user": user})
	if err != nil {
		fmt.Fprintln(os.Stderr, "grant-admit attach: warden unreachable:", err)
		os.Exit(1)
	}
	if res.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "grant-admit attach: refused (%d): %s\n", res.StatusCode, bytes.TrimSpace(data))
		os.Exit(1)
	}
}
