package lifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"rmt.local/monitor/internal/collector/pairing"
	"rmt.local/monitor/internal/collector/spool"
	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
)

type recoveryCLIFailure struct {
	code                      int
	safeCode, message, action string
}

func captureRecoveryCLIFailure(t *testing.T) (cliFailure, *recoveryCLIFailure) {
	t.Helper()
	result := &recoveryCLIFailure{}
	allowed := map[string]bool{
		"fix_input": true, "upgrade_component": true, "authenticate": true,
		"request_admin": true, "retry_later": true, "review_current_state": true,
		"free_capacity": true, "repair_source": true, "use_local_owner_command": true,
		"none": true,
	}
	return func(code int, safeCode, message, action string) int {
		if !allowed[action] {
			t.Errorf("recovery action %q is outside the closed error contract", action)
		}
		*result = recoveryCLIFailure{code, safeCode, message, action}
		return code
	}, result
}

func TestCollectorRecoveryPreviewIsExactCompactAndReadOnly(t *testing.T) {
	manager, deploymentID, generation, oldGeneration, oldBoot, spoolDir := recoveryCLIFixture(t)
	manifestPath := filepath.Join(manager.Paths.Support, "reviewed-recovery.json")
	key := "77777777-7777-4777-8777-777777777777"
	args := []string{"preview", "--out", manifestPath, "--idempotency-key", key, "--confirm-deployment", deploymentID, "--deployment-generation", generation, "--original-generation", oldGeneration, "--original-boot", oldBoot, "--json"}
	before := recoveryDirectoryHashes(t, spoolDir)

	var stdout, stderr bytes.Buffer
	fail, failure := captureRecoveryCLIFailure(t)
	if code := runCollectorRecoveryCLI(context.Background(), args, &stdout, &stderr, manager, fail); code != 0 {
		t.Fatalf("preview code=%d failure=%#v stderr=%s", code, failure, stderr.String())
	}
	var result collectorRecoveryPreviewResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.Status != "previewed" || result.TotalFrames != 1 || result.ManifestPath != manifestPath {
		t.Fatalf("preview result=%#v err=%v output=%s", result, err, stdout.String())
	}
	after := recoveryDirectoryHashes(t, spoolDir)
	if !equalRecoveryHashes(before, after) {
		t.Fatalf("read-only preview changed spool bytes: before=%v after=%v", before, after)
	}
	receipts, err := loadRecoveryCLIReceipts(manager.Paths.Collector, manager.Clock.Now().UnixMilli())
	if err != nil || len(receipts.Previews) != 1 || receipts.Previews[0].PendingManifest != nil || receipts.Previews[0].ManifestPath != manifestPath || !validSHA256(receipts.Previews[0].ManifestFileSHA) {
		t.Fatalf("compact receipt=%#v err=%v", receipts.Previews, err)
	}

	stdout.Reset()
	if code := runCollectorRecoveryCLI(context.Background(), args, &stdout, &stderr, manager, fail); code != 0 || stdout.String() == "" {
		t.Fatalf("exact retry code=%d failure=%#v", code, failure)
	}
	changed := append(append([]string(nil), args...), "--from-sequence", "0")
	if code := runCollectorRecoveryCLI(context.Background(), changed, &stdout, &stderr, manager, fail); code != 7 || failure.action != "review_current_state" || failure.safeCode != "idempotency_conflict" {
		t.Fatalf("changed-scope code=%d failure=%#v", code, failure)
	}
	if err := os.Remove(manifestPath); err != nil {
		t.Fatal(err)
	}
	if code := runCollectorRecoveryCLI(context.Background(), args, &stdout, &stderr, manager, fail); code != 3 || failure.action != "repair_source" || failure.safeCode != "recovery_manifest_receipt_invalid" {
		t.Fatalf("missing-manifest code=%d failure=%#v", code, failure)
	}
}

func TestCollectorRecoveryCLIHelpAndGrantHashFailure(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"preview", "--help"}, {"apply", "--help"}} {
		var stdout, stderr bytes.Buffer
		fail, failure := captureRecoveryCLIFailure(t)
		if code := runCollectorRecoveryCLI(context.Background(), args, &stdout, &stderr, nil, fail); code != 0 || stdout.Len() == 0 || stderr.Len() != 0 {
			t.Fatalf("help %v code=%d failure=%#v stdout=%q stderr=%q", args, code, failure, stdout.String(), stderr.String())
		}
	}

	manager, deploymentID, generation, _, _, _ := recoveryCLIFixture(t)
	grantPath := filepath.Join(manager.Paths.Support, "reviewed-grant.json")
	if err := config.WritePrivateFile(grantPath, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(manager.Paths.Support, "recovery-report.json")
	fail, failure := captureRecoveryCLIFailure(t)
	code := runCollectorRecoveryCLI(context.Background(), []string{"apply", "--grant", grantPath, "--grant-sha256", hex.EncodeToString(make([]byte, sha256.Size)), "--idempotency-key", "88888888-8888-4888-8888-888888888888", "--confirm-deployment", deploymentID, "--deployment-generation", generation, "--report-out", reportPath, "--json"}, &bytes.Buffer{}, &bytes.Buffer{}, manager, fail)
	if code != 7 || failure.safeCode != "grant_file_hash_mismatch" || failure.action != "review_current_state" {
		t.Fatalf("grant hash code=%d failure=%#v", code, failure)
	}
}

func TestRecoveryCLIReceiptsAllowSequentialSplitsButBoundActiveWork(t *testing.T) {
	paths := testPaths(t)
	hash := hex.EncodeToString(make([]byte, sha256.Size))
	receipts := recoveryCLIReceipts{Version: 1, Previews: []recoveryPreviewReceipt{}, Applies: []recoveryApplyReceipt{}}
	for index := 1; index <= 5; index++ {
		key := fmt.Sprintf("%08d-0000-4000-8000-000000000000", index)
		receipts.Previews = append(receipts.Previews, recoveryPreviewReceipt{Key: key, ScopeSHA: hash, AtMS: 1, ManifestPath: filepath.Join(paths.Support, fmt.Sprintf("manifest-%d.json", index)), ManifestFileSHA: hash, ManifestSHA: hash})
		receipts.Applies = append(receipts.Applies, recoveryApplyReceipt{Key: key, GrantFileSHA256: hash, GrantSHA256: hash, ReportPath: filepath.Join(paths.Support, fmt.Sprintf("report-%d.json", index)), AtMS: 1, BootID: "99999999-9999-4999-8999-999999999999", Session: 1, ActivatedMS: 1, ReportCreatedMS: 1})
	}
	if err := saveRecoveryCLIReceipts(paths.Collector, receipts); err != nil {
		t.Fatalf("five sequential split receipts were rejected: %v", err)
	}
	loaded, err := loadRecoveryCLIReceipts(paths.Collector, int64(24*time.Hour/time.Millisecond))
	if err != nil || len(loaded.Previews) != 5 || len(loaded.Applies) != 5 {
		t.Fatalf("sequential receipts=%#v err=%v", loaded, err)
	}
	for index := range receipts.Applies {
		receipts.Applies[index].ReportCreatedMS = 0
		receipts.Applies[index].Session = 0
		receipts.Applies[index].ActivatedMS = 0
	}
	if err := validateRecoveryCLIReceipts(receipts); err == nil {
		t.Fatal("five active apply receipts escaped the four-grant bound")
	}
}

func recoveryCLIFixture(t *testing.T) (*Manager, string, string, string, string, string) {
	t.Helper()
	paths := testPaths(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	manager := NewManager(paths, newFakeRunner(), fixedClock{now: now})
	deploymentID := "11111111-1111-4111-8111-111111111111"
	generation := "22222222-2222-4222-8222-222222222222"
	oldGeneration := "33333333-3333-4333-8333-333333333333"
	oldBoot := "44444444-4444-4444-8444-444444444444"
	local, err := pairing.Create(paths.Collector, deploymentID, generation)
	if err != nil {
		t.Fatal(err)
	}
	identity := local.Snapshot()
	configured := collectorRecoveryConfig{SchemaVersion: domain.SchemaVersion, DeploymentID: deploymentID, DeploymentGeneration: generation, OwnerSocket: paths.CollectorSocket, CollectionEnabled: true, InferenceEnabled: false}
	encoded, _ := json.Marshal(configured)
	if err := config.WritePrivateFile(paths.CollectorConfig, encoded); err != nil {
		t.Fatal(err)
	}
	spoolDir := filepath.Join(paths.Collector, "spool")
	queue, err := spool.Open(spoolDir, spool.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	record := spool.Record{DeploymentID: deploymentID, Generation: oldGeneration, SessionGeneration: 1, HostID: identity.HostID, BootID: oldBoot, SourceID: identity.HostSourceID, Sequence: 1, ObservedMS: now.Add(-time.Minute).UnixMilli(), Payload: []byte{1}}
	if err := queue.Append(record); err != nil {
		queue.Close()
		t.Fatal(err)
	}
	if err := queue.Close(); err != nil {
		t.Fatal(err)
	}
	return manager, deploymentID, generation, oldGeneration, oldBoot, spoolDir
}

func recoveryDirectoryHashes(t *testing.T, directory string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(data)
		result[entry.Name()] = hex.EncodeToString(hash[:])
	}
	return result
}

func equalRecoveryHashes(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for name, hash := range left {
		if right[name] != hash {
			return false
		}
	}
	return true
}
