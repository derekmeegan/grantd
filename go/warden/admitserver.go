package warden

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"

	"golang.org/x/crypto/ssh"
)

// AdmitServer is the socket the sshd hooks talk to. Two operations: authorize
// a certificate (the AuthorizedPrincipalsCommand) and attach a session (the
// PAM session hook). Both learn who is calling from the kernel's peer
// credentials, never from the request.
type AdmitServer struct {
	W   *Warden
	Log *slog.Logger
}

type ctxKey int

const peerKey ctxKey = 0

// Serve runs the admission API on ln until the server is closed. ConnContext
// stashes each connection's peer credentials, read once from the kernel.
func (a *AdmitServer) Serve(ln net.Listener) error {
	srv := &http.Server{
		Handler:           a.handler(),
		ReadHeaderTimeout: 5 * 1e9,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			pc, err := ReadPeerCred(c)
			if err != nil {
				return context.WithValue(ctx, peerKey, peerResult{err: err})
			}
			return context.WithValue(ctx, peerKey, peerResult{cred: pc})
		},
	}
	return srv.Serve(ln)
}

type peerResult struct {
	cred PeerCred
	err  error
}

func (a *AdmitServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /principals", a.principals)
	mux.HandleFunc("POST /attach", a.attach)
	mux.HandleFunc("GET /status", a.status)
	return mux
}

// caller reads the connecting process from the kernel-reported peer pid, and
// confirms the uid the kernel reported matches the process it read.
func (a *AdmitServer) caller(r *http.Request) (Proc, error) {
	pr, _ := r.Context().Value(peerKey).(peerResult)
	if pr.err != nil {
		return Proc{}, fmt.Errorf("no peer credentials: %w", pr.err)
	}
	if pr.cred.PID == 0 {
		return Proc{}, errors.New("no peer pid")
	}
	p, err := ReadProc(int(pr.cred.PID))
	if err != nil {
		return Proc{}, fmt.Errorf("read caller %d: %w", pr.cred.PID, err)
	}
	if uint32(p.UID) != pr.cred.UID {
		return Proc{}, fmt.Errorf("caller uid %d disagrees with kernel %d", p.UID, pr.cred.UID)
	}
	return p, nil
}

type principalsRequest struct {
	User     string `json:"user"`
	CertType string `json:"cert_type"`
	CertB64  string `json:"cert_b64"`
}

type principalsResponse struct {
	Principals []string `json:"principals"`
}

func (a *AdmitServer) principals(w http.ResponseWriter, r *http.Request) {
	caller, err := a.caller(r)
	if err != nil {
		a.deny(w, "principals", err)
		return
	}
	var req principalsRequest
	if !readJSON(w, r, &req) {
		return
	}
	keyID, serial, err := certKeyIDSerial(req.CertType, req.CertB64)
	if err != nil {
		a.deny(w, "principals", err)
		return
	}
	principal, err := a.W.Admit(r.Context(), caller, req.User, keyID, serial)
	if err != nil {
		a.deny(w, "principals", err)
		return
	}
	writeJSON(w, http.StatusOK, principalsResponse{Principals: []string{principal}})
}

type attachRequest struct {
	User string `json:"user"`
}

func (a *AdmitServer) attach(w http.ResponseWriter, r *http.Request) {
	caller, err := a.caller(r)
	if err != nil {
		a.deny(w, "attach", err)
		return
	}
	var req attachRequest
	if !readJSON(w, r, &req) {
		return
	}
	if err := a.W.Attach(r.Context(), caller, req.User); err != nil {
		a.deny(w, "attach", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "attached"})
}

func (a *AdmitServer) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ready": a.W.Ready(), "grants": a.W.Snapshot()})
}

func (a *AdmitServer) deny(w http.ResponseWriter, op string, err error) {
	if a.Log != nil {
		a.Log.Info("denied", "op", op, "err", err)
	}
	status := http.StatusForbidden
	if errors.Is(err, ErrNotReady) {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// certKeyIDSerial reconstructs the authorized_keys line sshd verified and
// pulls the key id and serial straight from the certificate, so the grant
// identity comes from the signed certificate and not from any client value.
func certKeyIDSerial(certType, certB64 string) (keyID, serial string, err error) {
	if certType == "" || certB64 == "" {
		return "", "", errors.New("empty certificate")
	}
	line := certType + " " + certB64
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return "", "", fmt.Errorf("parse certificate: %w", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return "", "", errors.New("authentication key is not a certificate")
	}
	return cert.KeyId, strconv.FormatUint(cert.Serial, 10), nil
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
