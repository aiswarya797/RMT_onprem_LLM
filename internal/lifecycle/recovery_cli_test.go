package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rmt.local/monitor/internal/config"
)

func TestRecoveryInspectDoesNotInventMissingOrInvalidTransaction(t *testing.T) {
	paths := testPaths(t)
	manager := NewManager(paths, newFakeRunner(), fixedClock{time.Unix(1_800_000_000, 0)})
	var output, errorOutput bytes.Buffer
	if code := RunCLI(context.Background(), []string{"recovery", "inspect", "--json"}, &output, &errorOutput, manager); code != 0 {
		t.Fatalf("empty inspection failed: %s", output.String())
	}
	var result RecoveryInspection
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || result.State != "no_journal" || len(result.ResumeArgv) != 0 || result.RecoveryPointMS != nil {
		t.Fatalf("missing journal fabricated a recovery: %+v %v", result, err)
	}
	if _, err := os.Stat(paths.Database); !os.IsNotExist(err) {
		t.Fatalf("inspection created database: %v", err)
	}
	path := filepath.Join(recoveryDirectory(paths), "active.json")
	if err := config.WritePrivateFile(path, []byte("{torn")); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if code := RunCLI(context.Background(), []string{"recovery", "inspect", "--json"}, &output, &errorOutput, manager); code != 8 || !strings.Contains(output.String(), "recovery_journal_invalid") {
		t.Fatalf("invalid journal not refused: %d %s", code, output.String())
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "{torn" {
		t.Fatal("inspection changed torn journal")
	}
}
