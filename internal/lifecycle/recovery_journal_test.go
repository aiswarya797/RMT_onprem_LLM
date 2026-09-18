package lifecycle

import (
	"os"
	"path/filepath"
	"testing"

	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
)

func TestRecoveryJournalFailsClosedAcrossActivationBoundary(t *testing.T) {
	paths := config.ForHome(t.TempDir())
	if err := RequireRecoveryReady(paths); err != nil {
		t.Fatal(err)
	}
	if err := config.EnsurePrivateDir(recoveryDirectory(paths)); err != nil {
		t.Fatal(err)
	}
	journal := recoveryJournal{
		SchemaVersion: domain.SchemaVersion, TransactionID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		DeploymentID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", PreviousGeneration: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		DeploymentGeneration: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", State: "prepared", StartedMS: 200, RecoveryPointMS: 100,
		ManifestSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Files: []recoveryFile{{Name: "monitor.sqlite3", SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},
		LaterChangesUnknown: true,
	}
	if err := writeRecoveryJournal(paths, journal); err != nil {
		t.Fatal(err)
	}
	if err := RequireRecoveryReady(paths); err == nil {
		t.Fatal("prepared restore admitted hub startup")
	}
	journal.State = "committed"
	if err := writeRecoveryJournal(paths, journal); err != nil {
		t.Fatal(err)
	}
	if err := RequireRecoveryReady(paths); err == nil {
		t.Fatal("ambiguous activation marker admitted startup")
	}
	now := int64(250)
	journal.CompletedMS = &now
	if err := writeRecoveryJournal(paths, journal); err != nil {
		t.Fatal(err)
	}
	if err := RequireRecoveryReady(paths); err != nil {
		t.Fatal(err)
	}
	if err := config.WritePrivateFile(filepath.Join(recoveryDirectory(paths), "active.json"), []byte("{\"state\":")); err != nil {
		t.Fatal(err)
	}
	if err := RequireRecoveryReady(paths); err == nil {
		t.Fatal("torn journal admitted startup")
	}
}

func TestRecoveryJournalRejectsSymlink(t *testing.T) {
	paths := config.ForHome(t.TempDir())
	if err := config.EnsurePrivateDir(recoveryDirectory(paths)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), filepath.Join(recoveryDirectory(paths), "active.json")); err != nil {
		t.Fatal(err)
	}
	if err := RequireRecoveryReady(paths); err == nil {
		t.Fatal("dangling symlink treated as no recovery")
	}
}
