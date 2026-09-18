package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rmt.local/monitor/internal/domain"
)

type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time { return c.now }

func TestEmbeddedSchemaMatchesReviewedContract(t *testing.T) {
	want, err := os.ReadFile(filepath.Join("..", "..", "contracts", "storage", "v1", "schema.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != schemaSQL {
		t.Fatal("embedded SQLite schema diverges from contracts/storage/v1/schema.sql")
	}
}

func TestOpenUsesLiteralReservedPathAndPersistsDeployment(t *testing.T) {
	clock := &testClock{now: time.Unix(1_800_000_000, 0)}
	dbPath := filepath.Join(t.TempDir(), "space ? hash #", "monitor.sqlite3")
	st, err := Open(dbPath, clock)
	if err != nil {
		t.Fatal(err)
	}
	var sqliteVersion, sqliteSourceID string
	if err := st.db.QueryRow(`SELECT sqlite_version(),sqlite_source_id()`).Scan(&sqliteVersion, &sqliteSourceID); err != nil {
		t.Fatal(err)
	}
	if sqliteVersion != "3.53.4" || !strings.Contains(sqliteSourceID, "bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc") {
		t.Fatalf("unexpected SQLite runtime version=%q source=%q", sqliteVersion, sqliteSourceID)
	}
	state, created, err := st.EnsureDeployment(context.Background(), "Test")
	if err != nil || !created {
		t.Fatalf("EnsureDeployment created=%v err=%v", created, err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("literal database path missing: %v", err)
	}
	st, err = OpenExisting(dbPath, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	again, created, err := st.EnsureDeployment(context.Background(), "Ignored")
	if err != nil || created || again.DeploymentID != state.DeploymentID || again.DeploymentGeneration != state.DeploymentGeneration {
		t.Fatalf("deployment not persistent/idempotent: %#v created=%v err=%v", again, created, err)
	}
	info, _ := os.Stat(dbPath)
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("database mode=%o", got)
	}
}

func TestSessionIsFencedByExpiryAndDeploymentGeneration(t *testing.T) {
	clock := &testClock{now: time.Unix(1_800_000_000, 0)}
	st, err := Open(filepath.Join(t.TempDir(), "db.sqlite3"), clock)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	state, _, _ := st.EnsureDeployment(ctx, "Test")
	userID, _ := domain.NewUUID()
	now := clock.Now().UnixMilli()
	_, err = st.db.Exec(`INSERT INTO users(id,deployment_id,name,argon2_hash,role,disabled,trust_generation,historical_restored,version,created_ms,updated_ms) VALUES(?,?,?,'00000000000000000000000000000000','admin',0,?,0,1,?,?)`, userID, state.DeploymentID, "admin", state.DeploymentGeneration, now, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateSession(ctx, HashForTest("session"), userID); err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(13 * time.Hour)
	if _, err := st.SessionByHash(ctx, HashForTest("session")); err != ErrSessionExpired {
		t.Fatalf("idle-expired session err=%v", err)
	}
	clock.now = time.Unix(1_800_000_000, 0)
	if _, err := st.CreateSession(ctx, HashForTest("session2"), userID); err != nil {
		t.Fatal(err)
	}
	newGeneration, _ := domain.NewUUID()
	_, err = st.db.Exec(`INSERT INTO deployment_generations(deployment_id,generation,reason,activated_ms) VALUES(?,?,'trust_reset',?)`, state.DeploymentID, newGeneration, now+1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.db.Exec(`UPDATE deployments SET deployment_generation=?,updated_ms=? WHERE id=?`, newGeneration, now+1, state.DeploymentID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SessionByHash(ctx, HashForTest("session2")); err != ErrSessionExpired {
		t.Fatalf("old generation session err=%v", err)
	}
}

func TestOpenReadOnlySeesCommittedWALWithoutChangingProductState(t *testing.T) {
	clock := &testClock{now: time.Unix(1_800_000_000, 0)}
	dbPath := filepath.Join(t.TempDir(), "db.sqlite3")
	st, err := Open(dbPath, clock)
	if err != nil {
		t.Fatal(err)
	}
	state, _, err := st.EnsureDeployment(context.Background(), "Test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE deployments SET display_name='committed-in-wal'`); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	readOnly, err := OpenReadOnly(dbPath, clock)
	if err != nil {
		t.Fatal(err)
	}
	readState, err := readOnly.DeploymentState(context.Background())
	if err != nil || readState.DeploymentID != state.DeploymentID {
		t.Fatalf("read-only state=%#v err=%v", readState, err)
	}
	var displayName string
	if err := readOnly.db.QueryRow(`SELECT display_name FROM deployments WHERE id=?`, state.DeploymentID).Scan(&displayName); err != nil || displayName != "committed-in-wal" {
		t.Fatalf("read-only status missed committed WAL value: name=%q err=%v", displayName, err)
	}
	var tableCount int
	if err := readOnly.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table'`).Scan(&tableCount); err != nil {
		t.Fatal(err)
	}
	if _, err := readOnly.db.Exec(`UPDATE deployments SET display_name='changed'`); err == nil {
		t.Fatal("read-only store accepted a mutation")
	}
	if err := readOnly.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode() != before.Mode() {
		t.Fatalf("read-only open changed database mode: before=%v after=%v", before.Mode(), after.Mode())
	}
	var nameAfter string
	var tableCountAfter int
	if err := st.db.QueryRow(`SELECT display_name FROM deployments WHERE id=?`, state.DeploymentID).Scan(&nameAfter); err != nil || nameAfter != "committed-in-wal" {
		t.Fatalf("read-only open changed product data: name=%q err=%v", nameAfter, err)
	}
	if err := st.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table'`).Scan(&tableCountAfter); err != nil || tableCountAfter != tableCount {
		t.Fatalf("read-only open changed schema: before=%d after=%d err=%v", tableCount, tableCountAfter, err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
}

func HashForTest(value string) string {
	// Stable 64-character value is enough for direct store boundary tests.
	return value + "0000000000000000000000000000000000000000000000000000000000000000"[:64-len(value)]
}
