package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/derekmeegan/grantd/go/internal/protocol"
	"github.com/derekmeegan/grantd/go/signer"
	"github.com/derekmeegan/grantd/go/signer/store"
)

// maxBody caps every request body the signer will read.
const maxBody = protocol.MaxRequestBytes

// Server adapts a Signer to the two socket APIs.
type Server struct {
	Signer *signer.Signer
	Log    *slog.Logger
}

// OwnerHandler serves the owner socket: the API that can mint capabilities.
// It is reachable only by the enrolled workspace user.
func (s *Server) OwnerHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /grants", s.createGrant)
	mux.HandleFunc("GET /grants", s.listGrants)
	mux.HandleFunc("DELETE /grants/{id}", s.revokeGrant)
	mux.HandleFunc("POST /grants/{id}/published", s.markPublished)
	mux.HandleFunc("GET /status", s.status)
	return withRecover(mux, s.Log)
}

// DaemonHandler serves the daemon socket. No route here creates a grant,
// signs arbitrary bytes, or takes a path, a command, or a filename. The
// signer builds every answer from its own state.
func (s *Server) DaemonHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /redeem", s.redeem)
	mux.HandleFunc("GET /registration", s.registration)
	mux.HandleFunc("POST /connect-auth", s.connectAuth)
	mux.HandleFunc("GET /pending-publications", s.pendingPublications)
	mux.HandleFunc("POST /grants/{id}/published", s.markPublished)
	mux.HandleFunc("GET /status", s.status)
	return withRecover(mux, s.Log)
}

func withRecover(h http.Handler, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if log != nil {
					log.Error("signer handler panic", "panic", v, "path", r.URL.Path)
				}
				writeErr(w, protocol.ErrCodeInternal, "internal error")
			}
		}()
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(protocol.HTTPStatusFor(code))
	_, _ = w.Write(protocol.MarshalErrorBody(code, msg))
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeErr(w, protocol.ErrCodeBadRequest, "request body too large or unreadable")
		return false
	}
	if len(body) == 0 {
		body = []byte("{}")
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, protocol.ErrCodeBadRequest, "malformed JSON body")
		return false
	}
	return true
}

// ------------------------------------------------------------- owner handlers

type createGrantRequest struct {
	TTLSeconds int64 `json:"ttl_seconds"`
}

func (s *Server) createGrant(w http.ResponseWriter, r *http.Request) {
	var req createGrantRequest
	if !decode(w, r, &req) {
		return
	}
	g, err := s.Signer.CreateGrant(r.Context(), req.TTLSeconds)
	switch {
	case errors.Is(err, signer.ErrTooManyGrants):
		writeErr(w, protocol.ErrCodeTooManyGrants, err.Error())
		return
	case errors.Is(err, store.ErrNoHost):
		writeErr(w, protocol.ErrCodeInternal, "host is not enrolled; run grant-signer init")
		return
	case err != nil:
		writeErr(w, protocol.ErrCodeBadRequest, err.Error())
		return
	}
	// The capability URL with its secret is returned here and nowhere else.
	writeJSON(w, http.StatusCreated, g)
}

func (s *Server) listGrants(w http.ResponseWriter, r *http.Request) {
	gs, err := s.Signer.ListGrants(r.Context())
	if err != nil {
		writeErr(w, protocol.ErrCodeInternal, err.Error())
		return
	}
	if gs == nil {
		gs = []store.GrantView{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"grants": gs})
}

func (s *Server) revokeGrant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Signer.RevokeGrant(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrGrantNotFound) {
			writeErr(w, protocol.ErrCodeGrantNotFound, "no such grant")
			return
		}
		writeErr(w, protocol.ErrCodeBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"grant_id": id, "revoked": true})
}

func (s *Server) markPublished(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Signer.MarkPublished(r.Context(), id); err != nil {
		writeErr(w, protocol.ErrCodeInternal, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"grant_id": id, "published": true})
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	h, err := s.Signer.Host(ctx)
	if err != nil {
		writeErr(w, protocol.ErrCodeInternal, err.Error())
		return
	}
	caLine, err := s.Signer.SSHCAPublicKeyLine()
	if err != nil {
		writeErr(w, protocol.ErrCodeInternal, err.Error())
		return
	}
	active, err := s.Signer.Store().ActiveGrantCount(ctx, store.Now())
	if err != nil {
		writeErr(w, protocol.ErrCodeInternal, err.Error())
		return
	}
	certs, err := s.Signer.Store().CertificateCount(ctx)
	if err != nil {
		writeErr(w, protocol.ErrCodeInternal, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"host_id":                 h.HostID,
		"ssh_user":                h.SSHUser,
		"hostname":                h.Hostname,
		"ssh_port":                h.SSHPort,
		"ssh_ca_public_key":       caLine,
		"ssh_host_public_key":     h.SSHHostPublicKey,
		"active_grants":           active,
		"certificates_issued":     certs,
		"protocol_version":        protocol.Version,
		"identity_public_key_b64": protocol.B64.EncodeToString(s.Signer.IdentityPublicKey()),
	})
}

// ------------------------------------------------------------ daemon handlers

func (s *Server) redeem(w http.ResponseWriter, r *http.Request) {
	var req protocol.RedemptionRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeErr(w, protocol.ErrCodeBadRequest, "request body too large or unreadable")
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, protocol.ErrCodeBadRequest, "malformed redemption envelope")
		return
	}
	resp, err := s.Signer.Redeem(r.Context(), req)
	if err != nil {
		var re *signer.RedeemError
		if errors.As(err, &re) {
			if s.Log != nil {
				s.Log.Info("redemption rejected",
					"grant_id", req.Payload.GrantID,
					"agent_id", req.Payload.AgentID,
					"code", re.Code)
			}
			writeErr(w, re.Code, re.Message)
			return
		}
		if s.Log != nil {
			s.Log.Error("redemption failed", "grant_id", req.Payload.GrantID, "err", err)
		}
		writeErr(w, protocol.ErrCodeInternal, "internal error")
		return
	}
	if s.Log != nil {
		s.Log.Info("certificate issued",
			"grant_id", req.Payload.GrantID,
			"agent_id", req.Payload.AgentID,
			"serial", resp.Serial,
			"valid_before", resp.ValidBefore)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) registration(w http.ResponseWriter, r *http.Request) {
	reg, err := s.Signer.HostRegistration(r.Context())
	if err != nil {
		writeErr(w, protocol.ErrCodeInternal, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, reg)
}

func (s *Server) pendingPublications(w http.ResponseWriter, r *http.Request) {
	pubs, err := s.Signer.PendingPublications(r.Context())
	if err != nil {
		writeErr(w, protocol.ErrCodeInternal, err.Error())
		return
	}
	// Public metadata only. Nothing here reveals a grant secret.
	writeJSON(w, http.StatusOK, map[string]any{"publications": pubs})
}

type connectAuthRequest struct {
	Path string `json:"path"`
}

func (s *Server) connectAuth(w http.ResponseWriter, r *http.Request) {
	var req connectAuthRequest
	if !decode(w, r, &req) {
		return
	}
	// The signature is bound to one rendezvous path. The daemon cannot ask
	// for a signature over arbitrary bytes.
	if req.Path == "" || !strings.HasPrefix(req.Path, "/v1/hosts/") || len(req.Path) > 256 {
		writeErr(w, protocol.ErrCodeBadRequest, "path must be a /v1/hosts/... rendezvous path")
		return
	}
	auth, err := s.Signer.SignConnect(r.Context(), req.Path)
	if err != nil {
		writeErr(w, protocol.ErrCodeInternal, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, auth)
}
