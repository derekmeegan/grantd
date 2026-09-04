package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// stubSSHD stands in for sshd: it sends a banner and echoes what it is sent.
func stubSSHD(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("SSH-2.0-stub\r\n"))
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func bridgeServer(t *testing.T) *httptest.Server {
	t.Helper()
	sem := make(chan struct{}, maxSessions)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serve(w, r, sem, discardLogger())
	}))
	t.Cleanup(srv.Close)
	return srv
}

func dialBridge(t *testing.T, srv *httptest.Server, path string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+path, nil)
	if err != nil {
		t.Fatalf("dial %s: %v", path, err)
	}
	t.Cleanup(func() { c.CloseNow() })
	return websocket.NetConn(context.Background(), c, websocket.MessageBinary)
}

func TestBridgeCarriesBytesBothWays(t *testing.T) {
	target = stubSSHD(t)
	conn := dialBridge(t, bridgeServer(t), "/ssh")

	banner := make([]byte, len("SSH-2.0-stub\r\n"))
	if _, err := io.ReadFull(conn, banner); err != nil {
		t.Fatalf("reading banner: %v", err)
	}
	if got := string(banner); got != "SSH-2.0-stub\r\n" {
		t.Fatalf("banner = %q", got)
	}

	// The transport must be byte-exact: an SSH transport does not survive a
	// helpful rewrite.
	payload := []byte("\x00\x01\x02binary\xff\xfe not text\n")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("echo = %q, want %q", got, payload)
	}
}

// The path is nginx's business. Whatever it is, the bytes go to the one
// compiled-in target: a path that could redirect them would be an open relay.
func TestThePathCannotRedirectTheSession(t *testing.T) {
	target = stubSSHD(t)
	srv := bridgeServer(t)
	for _, path := range []string{"/ssh", "/", "/anything", "/ssh?target=evil.example.com:22"} {
		conn := dialBridge(t, srv, path)
		banner := make([]byte, len("SSH-2.0-stub\r\n"))
		if _, err := io.ReadFull(conn, banner); err != nil {
			t.Fatalf("%s: reading banner: %v", path, err)
		}
		if string(banner) != "SSH-2.0-stub\r\n" {
			t.Errorf("%s: reached something other than the compiled-in target", path)
		}
	}
}

func TestRefusesToListenOffLoopback(t *testing.T) {
	for _, bad := range []string{"0.0.0.0:8022", "192.0.2.1:8022", "[::]:8022", "8022", "not-an-address"} {
		if err := checkLoopback(bad); err == nil {
			t.Errorf("checkLoopback(%q) = nil, want an error", bad)
		}
	}
	for _, ok := range []string{"127.0.0.1:8022", "[::1]:8022"} {
		if err := checkLoopback(ok); err != nil {
			t.Errorf("checkLoopback(%q) = %v, want nil", ok, err)
		}
	}
}

// A visitor gets an HTTP status it can read, rather than a WebSocket that
// opens and then dies, when sshd is not answering.
func TestUnreachableSSHDIsAnHTTPError(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close() // nothing is listening there now
	target = addr

	srv := bridgeServer(t)
	res, err := http.Get(srv.URL + "/ssh")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", res.StatusCode, http.StatusServiceUnavailable)
	}
}

func TestConcurrentSessionsAreCapped(t *testing.T) {
	target = stubSSHD(t)
	sem := make(chan struct{}, 1) // a cap of one, to keep the test small
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serve(w, r, sem, discardLogger())
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	first, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/ssh", nil)
	if err != nil {
		t.Fatalf("first session: %v", err)
	}
	defer first.CloseNow()

	res, err := http.Get(srv.URL + "/ssh")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("second session status = %d, want %d", res.StatusCode, http.StatusServiceUnavailable)
	}
}
