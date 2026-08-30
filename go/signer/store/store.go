// Package store is the signer's local state: the enrollment record, grant
// secrets, redemption state, issued certificates, and seen nonces.
//
// This database is the authority. The coordination service's copy of any of
// this is a routing hint. Nothing in here is ever uploaded.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// DBFileMode is the only mode the state database may have.
const DBFileMode os.FileMode = 0o600

var (
	ErrNoHost        = errors.New("store: host is not enrolled")
	ErrGrantNotFound = errors.New("store: grant not found")
)

// Store owns the signer's SQLite database.
type Store struct {
	db   *sql.DB
	path string
}

const schema = `
CREATE TABLE IF NOT EXISTS host (
    rowid_guard INTEGER PRIMARY KEY CHECK (rowid_guard = 1),
    host_id     TEXT NOT NULL,
    ssh_user    TEXT NOT NULL,
    hostname    TEXT NOT NULL,
    ssh_port    INTEGER NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS grants (
    id                TEXT PRIMARY KEY,
    secret            BLOB NOT NULL,
    ssh_user          TEXT NOT NULL,
    created_at        INTEGER NOT NULL,
    expires_at        INTEGER NOT NULL,
    redeemed_at       INTEGER,
    revoked_at        INTEGER,
    redeemed_agent_id TEXT,
    redeemed_key_fp   TEXT,
    published_at      INTEGER
);
CREATE INDEX IF NOT EXISTS grants_expires_at ON grants (expires_at);

CREATE TABLE IF NOT EXISTS certificates (
    serial       INTEGER PRIMARY KEY,
    grant_id     TEXT NOT NULL UNIQUE,
    agent_id     TEXT NOT NULL,
    key_fp       TEXT NOT NULL,
    certificate  TEXT NOT NULL,
    valid_after  INTEGER NOT NULL,
    valid_before INTEGER NOT NULL,
    created_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS nonces (
    nonce   BLOB PRIMARY KEY,
    scope   TEXT NOT NULL,
    seen_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS nonces_seen_at ON nonces (seen_at);
`

// Open creates or opens the signer database, enforcing 0600 on the file.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	dsn := "file:" + path +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(10000)" +
		"&_pragma=synchronous(FULL)" +
		"&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: schema: %w", err)
	}
	// The DB is created by whatever umask is in force; pin it explicitly.
	if err := os.Chmod(path, DBFileMode); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, path: path}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// ------------------------------------------------------------------- host

// Host is the enrollment record.
type Host struct {
	HostID    string
	SSHUser   string
	Hostname  string
	SSHPort   uint64
	CreatedAt int64
}

// SetHost writes the enrollment record. There is exactly one row, ever.
func (s *Store) SetHost(ctx context.Context, h Host) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO host (rowid_guard, host_id, ssh_user, hostname, ssh_port, created_at)
        VALUES (1, ?, ?, ?, ?, ?)
        ON CONFLICT(rowid_guard) DO UPDATE SET
            host_id=excluded.host_id, ssh_user=excluded.ssh_user,
            hostname=excluded.hostname, ssh_port=excluded.ssh_port`,
		h.HostID, h.SSHUser, h.Hostname, h.SSHPort, h.CreatedAt)
	return err
}

// Host returns the enrollment record.
func (s *Store) Host(ctx context.Context) (Host, error) {
	var h Host
	err := s.db.QueryRowContext(ctx,
		`SELECT host_id, ssh_user, hostname, ssh_port, created_at FROM host WHERE rowid_guard = 1`).
		Scan(&h.HostID, &h.SSHUser, &h.Hostname, &h.SSHPort, &h.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Host{}, ErrNoHost
	}
	return h, err
}

// ------------------------------------------------------------------ grants

// Grant is a locally stored capability. Secret never leaves this process.
type Grant struct {
	ID              string
	Secret          []byte
	SSHUser         string
	CreatedAt       int64
	ExpiresAt       int64
	RedeemedAt      *int64
	RevokedAt       *int64
	RedeemedAgentID string
	RedeemedKeyFP   string
	PublishedAt     *int64
}

// GrantView is Grant with the secret removed, for anything that reports state.
type GrantView struct {
	ID              string `json:"grant_id"`
	SSHUser         string `json:"ssh_user"`
	CreatedAt       int64  `json:"created_at"`
	ExpiresAt       int64  `json:"expires_at"`
	RedeemedAt      *int64 `json:"redeemed_at"`
	RevokedAt       *int64 `json:"revoked_at"`
	RedeemedAgentID string `json:"redeemed_agent_id,omitempty"`
	RedeemedKeyFP   string `json:"redeemed_key_fingerprint,omitempty"`
	PublishedAt     *int64 `json:"published_at"`
}

func (g Grant) View() GrantView {
	return GrantView{
		ID: g.ID, SSHUser: g.SSHUser, CreatedAt: g.CreatedAt, ExpiresAt: g.ExpiresAt,
		RedeemedAt: g.RedeemedAt, RevokedAt: g.RevokedAt,
		RedeemedAgentID: g.RedeemedAgentID, RedeemedKeyFP: g.RedeemedKeyFP,
		PublishedAt: g.PublishedAt,
	}
}

// CreateGrant stores a new capability.
func (s *Store) CreateGrant(ctx context.Context, g Grant) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO grants (id, secret, ssh_user, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		g.ID, g.Secret, g.SSHUser, g.CreatedAt, g.ExpiresAt)
	return err
}

// MarkPublished records that the daemon successfully published the signed
// public metadata for a grant.
func (s *Store) MarkPublished(ctx context.Context, id string, at int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE grants SET published_at = ? WHERE id = ?`, at, id)
	return err
}

// PendingPublications returns grants whose public metadata has not yet been
// accepted by the coordination service and which are still worth publishing.
//
// The daemon polls this instead of being pushed to. Polling is the failure
// tolerant direction: a grant created while the network is down is published as
// soon as connectivity returns, with no queue to lose and no notification to
// miss.
func (s *Store) PendingPublications(ctx context.Context, now int64) ([]Grant, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, ssh_user, created_at, expires_at
          FROM grants
         WHERE published_at IS NULL
           AND revoked_at IS NULL
           AND expires_at > ?
         ORDER BY created_at ASC`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		var g Grant
		if err := rows.Scan(&g.ID, &g.SSHUser, &g.CreatedAt, &g.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// ListGrants returns every grant, newest first, without secrets.
func (s *Store) ListGrants(ctx context.Context) ([]GrantView, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, ssh_user, created_at, expires_at, redeemed_at, revoked_at,
               COALESCE(redeemed_agent_id, ''), COALESCE(redeemed_key_fp, ''), published_at
          FROM grants ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GrantView
	for rows.Next() {
		var v GrantView
		if err := rows.Scan(&v.ID, &v.SSHUser, &v.CreatedAt, &v.ExpiresAt,
			&v.RedeemedAt, &v.RevokedAt, &v.RedeemedAgentID, &v.RedeemedKeyFP, &v.PublishedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// GetGrantView returns a single grant without its secret.
func (s *Store) GetGrantView(ctx context.Context, id string) (GrantView, error) {
	var v GrantView
	err := s.db.QueryRowContext(ctx, `
        SELECT id, ssh_user, created_at, expires_at, redeemed_at, revoked_at,
               COALESCE(redeemed_agent_id, ''), COALESCE(redeemed_key_fp, ''), published_at
          FROM grants WHERE id = ?`, id).
		Scan(&v.ID, &v.SSHUser, &v.CreatedAt, &v.ExpiresAt, &v.RedeemedAt, &v.RevokedAt,
			&v.RedeemedAgentID, &v.RedeemedKeyFP, &v.PublishedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return GrantView{}, ErrGrantNotFound
	}
	return v, err
}

// RevokeGrant marks a grant unusable. Revocation is immediate for redemption;
// it does not retract a certificate that was already issued.
func (s *Store) RevokeGrant(ctx context.Context, id string, at int64) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE grants SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, at, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Either it does not exist or it was already revoked; distinguish.
		if _, gerr := s.GetGrantView(ctx, id); gerr != nil {
			return gerr
		}
	}
	return nil
}

// PurgeExpired deletes grant rows that expired more than retain seconds ago,
// along with stale nonces. Certificates are kept for audit.
func (s *Store) PurgeExpired(ctx context.Context, now, retain int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM grants WHERE expires_at < ?`, now-retain)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM nonces WHERE seen_at < ?`, now-retain); err != nil {
		return n, err
	}
	return n, nil
}

// ------------------------------------------------------------------ nonces

// ErrNonceReplay is returned when a nonce has already been seen in scope.
var ErrNonceReplay = errors.New("store: nonce replay")

// RememberNonce records a nonce, returning ErrNonceReplay if it was already
// seen. Nonces older than the skew window are pruned opportunistically.
func (s *Store) RememberNonce(ctx context.Context, scope string, nonce []byte, now, window int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM nonces WHERE seen_at < ?`, now-window); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO nonces (nonce, scope, seen_at) VALUES (?, ?, ?)`, nonce, scope, now)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNonceReplay
	}
	return nil
}

// ----------------------------------------------------------------- claiming

// ClaimStatus is the outcome of an attempt to consume a grant.
type ClaimStatus int

const (
	ClaimOK ClaimStatus = iota
	ClaimNotFound
	ClaimRevoked
	ClaimExpired
	ClaimAlreadyRedeemed // consumed by a different agent or key
	ClaimBadProof        // proof did not verify; grant deliberately not consumed
)

// ClaimResult reports what happened and, on an idempotent retry, hands back the
// certificate that was already issued so the caller can return it verbatim.
type ClaimResult struct {
	Status     ClaimStatus
	SSHUser    string
	ExpiresAt  int64
	Retry      bool
	Serial     uint64
	StoredCert string
}

// ClaimGrant performs the single atomic step that makes a grant single-use.
//
// The proof check runs *inside* the write transaction, after the row is locked
// but before the transaction commits. That ordering is deliberate:
//
//   - Locking first means N concurrent redemptions for N different SSH keys
//     serialize, and exactly one can observe redeemed_at IS NULL.
//   - Verifying inside the transaction means a caller who cannot produce a
//     valid proof causes a ROLLBACK, so a flood of wrong guesses cannot burn a
//     legitimate grant.
//
// verify is called with the stored secret and must not retain it.
func (s *Store) ClaimGrant(
	ctx context.Context,
	grantID string,
	now int64,
	agentID, keyFP string,
	verify func(secret []byte) (bool, error),
) (ClaimResult, error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return ClaimResult{}, err
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return ClaimResult{}, fmt.Errorf("store: begin immediate: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	var (
		secret     []byte
		sshUser    string
		expiresAt  int64
		redeemedAt sql.NullInt64
		revokedAt  sql.NullInt64
		redAgent   sql.NullString
		redKeyFP   sql.NullString
	)
	err = conn.QueryRowContext(ctx, `
        SELECT secret, ssh_user, expires_at, redeemed_at, revoked_at,
               redeemed_agent_id, redeemed_key_fp
          FROM grants WHERE id = ?`, grantID).
		Scan(&secret, &sshUser, &expiresAt, &redeemedAt, &revokedAt, &redAgent, &redKeyFP)
	if errors.Is(err, sql.ErrNoRows) {
		return ClaimResult{Status: ClaimNotFound}, nil
	}
	if err != nil {
		return ClaimResult{}, err
	}

	if revokedAt.Valid {
		return ClaimResult{Status: ClaimRevoked}, nil
	}
	if expiresAt <= now {
		return ClaimResult{Status: ClaimExpired}, nil
	}

	retry := false
	if redeemedAt.Valid {
		if redAgent.String != agentID || redKeyFP.String != keyFP {
			return ClaimResult{Status: ClaimAlreadyRedeemed}, nil
		}
		retry = true
	}

	ok, err := verify(secret)
	if err != nil {
		return ClaimResult{}, err
	}
	if !ok {
		// ROLLBACK via the deferred close: the grant stays unconsumed.
		return ClaimResult{Status: ClaimBadProof}, nil
	}

	res := ClaimResult{Status: ClaimOK, SSHUser: sshUser, ExpiresAt: expiresAt, Retry: retry}

	if retry {
		var serial int64
		var cert string
		err := conn.QueryRowContext(ctx,
			`SELECT serial, certificate FROM certificates WHERE grant_id = ?`, grantID).
			Scan(&serial, &cert)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return ClaimResult{}, err
		}
		if err == nil {
			res.Serial = uint64(serial)
			res.StoredCert = cert
		}
	} else {
		if _, err := conn.ExecContext(ctx, `
            UPDATE grants SET redeemed_at = ?, redeemed_agent_id = ?, redeemed_key_fp = ?
             WHERE id = ? AND redeemed_at IS NULL`,
			now, agentID, keyFP, grantID); err != nil {
			return ClaimResult{}, err
		}
	}

	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return ClaimResult{}, fmt.Errorf("store: commit: %w", err)
	}
	committed = true
	return res, nil
}

// RecordCertificate stores an issued certificate so that a lost response can be
// answered with the identical bytes rather than a second certificate.
func (s *Store) RecordCertificate(ctx context.Context, serial uint64, grantID, agentID, keyFP, cert string, validAfter, validBefore, now int64) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO certificates (serial, grant_id, agent_id, key_fp, certificate, valid_after, valid_before, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(grant_id) DO NOTHING`,
		int64(serial), grantID, agentID, keyFP, cert, validAfter, validBefore, now)
	return err
}

// CertificateCount reports how many certificates have been issued, for tests
// and status output.
func (s *Store) CertificateCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM certificates`).Scan(&n)
	return n, err
}

// ActiveGrantCount reports grants that are still redeemable right now.
func (s *Store) ActiveGrantCount(ctx context.Context, now int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
        SELECT COUNT(*) FROM grants
         WHERE expires_at > ? AND redeemed_at IS NULL AND revoked_at IS NULL`, now).Scan(&n)
	return n, err
}

// Now is a small helper so callers share one notion of "now" in seconds.
func Now() int64 { return time.Now().Unix() }
