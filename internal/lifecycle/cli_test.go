package lifecycle

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rmt.local/monitor/internal/config"
)

func TestRunCLIPartialUninstallStopDenialPrintsRunnableRecovery(t *testing.T) {
	paths := cliTestPathsWithSpaces(t)
	runner := newFakeRunner()
	manager := NewManager(paths, runner, fixedClock{time.Unix(1_800_000_000, 0)})
	setup, err := manager.SetupLocal(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	writeTestBinaries(t, manager)
	runner.loaded[HubLabel] = true
	runner.failStop = HubLabel

	output := runPartialKeepDataCLI(t, manager, setup.DeploymentGeneration)
	assertContainsAll(t, output,
		"Recovery reason: service_stop_unconfirmed.",
		"Failure: stop_unconfirmed_"+HubLabel,
		"Retry: "+shellQuote(manager.HubBinary),
		shellQuote(paths.Home),
		shellQuote(paths.Run),
		shellQuote(setup.DeploymentGeneration),
	)
	if !strings.Contains(output, "LLM Monitor") {
		t.Fatalf("retry output lost the installation path with spaces:\n%s", output)
	}
}

func TestRunCLIPartialUninstallDeletionDenialPrintsFailureAndRunnableRecovery(t *testing.T) {
	paths := cliTestPathsWithSpaces(t)
	manager := NewManager(paths, newFakeRunner(), fixedClock{time.Unix(1_800_000_000, 0)})
	setup, err := manager.SetupLocal(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	writeTestBinaries(t, manager)
	originalRemove := manager.RemovePath
	manager.RemovePath = func(path string) error {
		if path == manager.CollectorBinary {
			return errors.New("permission denied\tby policy")
		}
		return originalRemove(path)
	}

	output := runPartialKeepDataCLI(t, manager, setup.DeploymentGeneration)
	assertContainsAll(t, output,
		"Recovery reason: removal_retry_required.",
		"Failure: llm-monitor-collector: permission denied by policy",
		"Retry: "+shellQuote(manager.HubBinary),
	)
	if strings.Contains(output, "denied\tby") {
		t.Fatalf("failure output retained a control character:\n%s", output)
	}
}

func TestRunCLIFinalReceiptFailureDirectsVerifiedExternalRetryWithoutSetup(t *testing.T) {
	paths := cliTestPathsWithSpaces(t)
	manager := NewManager(paths, newFakeRunner(), fixedClock{time.Unix(1_800_000_000, 0)})
	setup, err := manager.SetupLocal(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	writeTestBinaries(t, manager)
	originalRemove := manager.RemovePath
	manager.RemovePath = func(path string) error {
		if path == paths.RemovalReceipt {
			return errors.New("receipt cleanup interrupted")
		}
		return originalRemove(path)
	}
	var stdout, stderr bytes.Buffer
	code := RunCLI(context.Background(), []string{
		"uninstall", "--purge",
		"--deployment-generation", setup.DeploymentGeneration,
		"--confirm-deployment", setup.DeploymentID,
		"--backup-offer-acknowledged",
	}, &stdout, &stderr, manager)
	if code != 6 || stderr.Len() != 0 {
		t.Fatalf("exit=%d stderr=%q output=%q", code, stderr.String(), stdout.String())
	}
	if _, err := os.Stat(manager.HubBinary); !os.IsNotExist(err) {
		t.Fatalf("fixture did not reach the external-binary boundary: %v", err)
	}
	output := stdout.String()
	assertContainsAll(t, output,
		"Recovery reason: removal_retry_required.",
		"Failure: removal-receipt.json: receipt cleanup interrupted",
		"same verified package",
		"verified restaged copy",
		"do not run setup",
		"Retry arguments:",
		shellQuote(paths.Home),
		shellQuote(paths.Run),
		shellQuote(setup.DeploymentGeneration),
		shellQuote(setup.DeploymentID),
	)
	if strings.Contains(output, "Retry: llm-monitor") || strings.Contains(output, "Retry: "+shellQuote(manager.HubBinary)) {
		t.Fatalf("receipt-only recovery printed an unavailable executable:\n%s", output)
	}
}

func runPartialKeepDataCLI(t *testing.T, manager *Manager, generation string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := RunCLI(context.Background(), []string{"uninstall", "--keep-data", "--deployment-generation", generation}, &stdout, &stderr, manager)
	if code != 6 || stderr.Len() != 0 {
		t.Fatalf("exit=%d stderr=%q output=%q", code, stderr.String(), stdout.String())
	}
	return stdout.String()
}

func cliTestPathsWithSpaces(t *testing.T) config.Paths {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".work", "u02 cli tests"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	home, err := os.MkdirTemp(root, "home with spaces 'quoted' ")
	if err != nil {
		t.Fatal(err)
	}
	run, err := os.MkdirTemp(root, "r ")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(home)
		_ = os.RemoveAll(run)
	})
	return config.ForHome(home).WithRuntimeDir(run)
}

func assertContainsAll(t *testing.T, value string, expected ...string) {
	t.Helper()
	for _, item := range expected {
		if !strings.Contains(value, item) {
			t.Fatalf("output missing %q:\n%s", item, value)
		}
	}
}
