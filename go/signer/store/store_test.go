package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

// oldSchema is the version 1 layout, where nonces were keyed by nonce alone.
const oldSchema = `
CREATE TABLE host (
    rowid_guard INTEGER PRIMARY KEY CHECK (rowid_guard = 1),
    host_id     TEXT NOT NULL,
    ssh_user    TEXT NOT NULL,
    hostname    TEXT NOT NULL,
    ssh_port    INTEGER NOT NULL,
    created_at  INTEGER NOT NULL
);
CREATE TABLE grants (
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
CREATE TABLE certificates (
    serial       INTEGER PRIMARY KEY,
    grant_id     TEXT NOT NULL UNIQUE,
    agent_id     TEXT NOT NULL,
    key_fp       TEXT NOT NULL,
    certificate  TEXT NOT NULL,
    valid_after  INTEGER NOT NULL,
    valid_before INTEGER NOT NULL,
    created_at   INTEGER NOT NULL
);
CREATE TABLE nonces (
    nonce   BLOB PRIMARY KEY,
    scope   TEXT NOT NULL,
    seen_at INTEGER NOT NULL
);
CREATE INDEX nonces_seen_at ON nonces (seen_at);
`

func TestNewDatabaseGetsCurrentSchema(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	v, err := s.SchemaVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v != schemaVersion {
		t.Fatalf("schema version %d, want %d", v, schemaVersion)
	}
}

func TestMigrationFromVersionOneKeepsDataAndScopesNonces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	old, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(oldSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`INSERT INTO host VALUES (1, 'h_x', 'ubuntu', 'box', 22, 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`INSERT INTO grants (id, secret, ssh_user, created_at, expires_at)
	                       VALUES ('g_old', x'01', 'ubuntu', 1, 9999999999)`); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`INSERT INTO nonces (nonce, scope, seen_at) VALUES (x'aa', 'redeem', 100)`); err != nil {
		t.Fatal(err)
	}
	old.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("open version 1 database: %v", err)
	}
	defer s.Close()
	ctx := context.Background()

	v, err := s.SchemaVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v != schemaVersion {
		t.Fatalf("schema version %d after migration, want %d", v, schemaVersion)
	}

	h, err := s.Host(ctx)
	if err != nil || h.HostID != "h_x" {
		t.Fatalf("host row lost in migration: %v %+v", err, h)
	}
	if _, err := s.GetGrantView(ctx, "g_old"); err != nil {
		t.Fatalf("grant row lost in migration: %v", err)
	}

	// The old nonce is still a replay in its own scope.
	err = s.RememberNonce(ctx, "redeem", []byte{0xaa}, 200, 1000)
	if !errors.Is(err, ErrNonceReplay) {
		t.Fatalf("migrated nonce not remembered: %v", err)
	}
	// The same bytes in another scope are a different nonce.
	if err := s.RememberNonce(ctx, "connect", []byte{0xaa}, 200, 1000); err != nil {
		t.Fatalf("nonce in a second scope rejected: %v", err)
	}

	// Opening again is a no-op.
	s.Close()
	again, err := Open(path)
	if err != nil {
		t.Fatalf("reopen after migration: %v", err)
	}
	again.Close()
}
