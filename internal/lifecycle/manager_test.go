package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"rmt.local/monitor/internal/collector/pairing"
	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type fakeRunner struct {
	mu       sync.Mutex
	loaded   map[string]bool
	calls    [][]string
	failStop string
	unknown  map[string]bool
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{loaded: make(map[string]bool), unknown: make(map[string]bool)}
}

func (r *fakeRunner) ServiceState(_ context.Context, target string) (ServicePresence, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, []string{"launchctl", "print", target})
	parts := strings.Split(target, "/")
	label := parts[len(parts)-1]
	if r.unknown[label] {
		return ServicePresenceUnknown, errors.New("permission denied")
	}
	if r.loaded[label] {
		return ServicePresenceLoaded, nil
	}
	return ServicePresenceAbsent, nil
}

func (r *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	call := append([]string{name}, args...)
	r.calls = append(r.calls, call)
	if len(args) == 0 {
		return nil, errors.New("missing args")
	}
	switch args[0] {
	case "bootstrap":
		label := HubLabel
		if strings.Contains(args[len(args)-1], "collector") {
			label = CollectorLabel
		}
		r.loaded[label] = true
		return nil, nil
	case "bootout":
		parts := strings.Split(args[1], "/")
		label := parts[len(parts)-1]
		if r.failStop == label {
			return []byte("permission denied"), errors.New("exit 1")
		}
		delete(r.loaded, label)
		return nil, nil
	}
	return nil, nil
}

func TestSetupLocalIsIdempotentAndDoesNotStartCollection(t *testing.T) {
	paths := testPaths(t)
	runner := newFakeRunner()
	manager := NewManager(paths, runner, fixedClock{time.Unix(1_800_000_000, 0)})
	manager.ListenAddress = unusedListenAddress(t)
	manager.ListenAddressExplicit = true
	first, err := manager.SetupLocal(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Created || first.HubState != "loaded" || first.CollectorState != "loaded" {
		t.Fatalf("first setup=%#v", first)
	}
	second, err := manager.SetupLocal(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if second.Created || second.DeploymentID != first.DeploymentID || second.DeploymentGeneration != first.DeploymentGeneration || second.HubState != "already_loaded" {
		t.Fatalf("second setup=%#v", second)
	}
	remaining, options, err := config.ExtractRuntimeOptions(manager.HubProgramArguments()[1:])
	if err != nil || options.InstallationRoot != paths.Home || options.RuntimeDir != paths.Run || strings.Join(remaining, " ") != "hub serve" {
		t.Fatalf("hub launch arguments do not round trip: remaining=%v options=%#v err=%v", remaining, options, err)
	}
	plist, _ := os.ReadFile(paths.HubPlist)
	for _, expected := range manager.HubProgramArguments() {
		if !strings.Contains(string(plist), expected) {
			t.Fatalf("hub plist missing %q: %s", expected, plist)
		}
	}
	collectorConfig, _ := os.ReadFile(paths.CollectorConfig)
	if !strings.Contains(string(collectorConfig), `"collection_enabled": true`) || !strings.Contains(string(collectorConfig), `"inference_enabled": false`) {
		t.Fatalf("setup must enable passive collection and leave inference disabled: %s", collectorConfig)
	}
	targets, err := pairing.ReadTargets(paths.Collector, first.DeploymentGeneration)
	if err != nil || len(targets.Targets) != 1 || targets.Targets[0].Manifest.Endpoint.Host != "127.0.0.1" || targets.Targets[0].Manifest.Endpoint.Port != 11434 {
		t.Fatalf("setup did not create the collector-local Ollama target: targets=%#v err=%v", targets, err)
	}
	for _, secret := range []string{paths.BootstrapToken, paths.SessionSecret, paths.CAKey, paths.CACert, paths.HubKey, paths.HubCert} {
		info, err := os.Stat(secret)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("secret %s mode/error: %v %v", secret, info, err)
		}
	}
}

func TestSetupMasterConfiguresOnlyHubAndRemoteListener(t *testing.T) {
	paths := testPaths(t)
	manager := NewManager(paths, newFakeRunner(), fixedClock{time.Unix(1_800_000_000, 0)})
	manager.ListenAddress = unusedListenAddress(t)
	manager.ListenAddressExplicit = true
	manager.CollectorListenAddress = unusedListenAddress(t)
	manager.CollectorListenExplicit = true
	result, err := manager.SetupMaster(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Created || result.HubState != "not_started" || result.CollectorState != "not_configured" || result.CollectorListen != manager.CollectorListenAddress {
		t.Fatalf("master setup=%#v", result)
	}
	configBytes, err := os.ReadFile(paths.HubConfig)
	if err != nil || !strings.Contains(string(configBytes), `"collector_listen": "`+manager.CollectorListenAddress+`"`) {
		t.Fatalf("master hub config=%s err=%v", configBytes, err)
	}
	if _, err := os.Stat(paths.CollectorConfig); !os.IsNotExist(err) {
		t.Fatalf("master setup created collector config: %v", err)
	}
	if _, err := os.Stat(filepath.Join(paths.Collector, "pairing.json")); !os.IsNotExist(err) {
		t.Fatalf("master setup created collector pairing: %v", err)
	}
}

func TestStopIsRepeatableAndLeavesOllamaOutsideLifecycle(t *testing.T) {
	paths := testPaths(t)
	runner := newFakeRunner()
	runner.loaded[HubLabel] = true
	runner.loaded[CollectorLabel] = true
	manager := NewManager(paths, runner, fixedClock{time.Unix(1_800_000_000, 0)})
	first, err := manager.Stop(context.Background())
	if err != nil || first.Status != "stopped" || first.HubState != "stopped" || first.CollectorState != "stopped" || !first.OllamaUnchanged {
		t.Fatalf("first stop=%#v err=%v", first, err)
	}
	second, err := manager.Stop(context.Background())
	if err != nil || second.Status != "stopped" || second.HubState != "already_stopped" || second.CollectorState != "already_stopped" || !second.OllamaUnchanged {
		t.Fatalf("repeat stop=%#v err=%v", second, err)
	}
	for _, call := range runner.calls {
		if strings.Contains(strings.Join(call, " "), "ollama") {
			t.Fatalf("stop touched Ollama: %v", call)
		}
	}
}

func TestSetupRejectsNonLoopbackBeforeTouchingInstallState(t *testing.T) {
	paths := testPaths(t)
	manager := NewManager(paths, newFakeRunner(), fixedClock{time.Now()})
	manager.ListenAddress = "0.0.0.0:9443"
	if _, err := manager.SetupLocal(context.Background(), false); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("non-loopback setup err=%v", err)
	}
	if _, err := os.Stat(paths.Support); !os.IsNotExist(err) {
		t.Fatalf("rejected setup touched install state: %v", err)
	}
}

func TestInstallCheckReportsCollisionWithoutKillingOccupant(t *testing.T) {
	paths := testPaths(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	manager := NewManager(paths, newFakeRunner(), fixedClock{time.Now()})
	manager.ListenAddress = listener.Addr().String()
	result := manager.InstallCheck(context.Background(), "local")
	if result.Compatible {
		t.Fatal("occupied port reported compatible")
	}
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("port occupant was disturbed: %v", err)
	}
	conn.Close()
}

func TestSetupReportsCollisionBeforeWritingInstallState(t *testing.T) {
	paths := testPaths(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	manager := NewManager(paths, newFakeRunner(), fixedClock{time.Now()})
	manager.ListenAddress = listener.Addr().String()
	if _, err := manager.SetupLocal(context.Background(), true); err == nil || !strings.Contains(err.Error(), "occupied") {
		t.Fatalf("setup collision err=%v", err)
	}
	if _, err := os.Stat(paths.Support); !os.IsNotExist(err) {
		t.Fatalf("failed setup wrote install state: %v", err)
	}
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("setup disturbed port occupant: %v", err)
	}
	_ = conn.Close()
}

func TestRepeatSetupPreservesSavedNondefaultPortAndRejectsExplicitChange(t *testing.T) {
	paths := testPaths(t)
	runner := newFakeRunner()
	selected := unusedListenAddress(t)
	first := NewManager(paths, runner, fixedClock{time.Unix(1_800_000_000, 0)})
	first.ListenAddress = selected
	first.ListenAddressExplicit = true
	if _, err := first.SetupLocal(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(paths.HubConfig)
	if err != nil {
		t.Fatal(err)
	}
	defaultOccupant, err := net.Listen("tcp", "127.0.0.1:9443")
	if err != nil {
		t.Skipf("default port already unavailable to test process: %v", err)
	}
	defer defaultOccupant.Close()

	repeated := NewManager(paths, runner, fixedClock{time.Unix(1_800_000_001, 0)})
	result, err := repeated.SetupLocal(context.Background(), true)
	if err != nil {
		t.Fatalf("omitted listen did not preserve saved port: %v", err)
	}
	if repeated.ListenAddress != selected || result.HubState != "loaded" {
		t.Fatalf("repeat setup listen=%q result=%#v", repeated.ListenAddress, result)
	}
	after, err := os.ReadFile(paths.HubConfig)
	if err != nil {
		t.Fatal(err)
	}
	var configValue map[string]any
	if err := json.Unmarshal(after, &configValue); err != nil || configValue["listen"] != selected {
		t.Fatalf("saved listen changed: %s err=%v", after, err)
	}
	if strings.Contains(strings.Join(repeated.HubProgramArguments(), " "), "--listen") {
		t.Fatalf("restart arguments bypass saved config: %v", repeated.HubProgramArguments())
	}

	explicit := NewManager(paths, runner, fixedClock{time.Unix(1_800_000_002, 0)})
	explicit.ListenAddress = unusedListenAddress(t)
	explicit.ListenAddressExplicit = true
	if _, err := explicit.SetupLocal(context.Background(), false); err == nil || !strings.Contains(err.Error(), "explicit change") {
		t.Fatalf("explicit saved-port change err=%v", err)
	}
	unchanged, err := os.ReadFile(paths.HubConfig)
	if err != nil || string(unchanged) != string(after) || string(before) == "" {
		t.Fatalf("rejected explicit change modified config: err=%v", err)
	}
}

func TestUninstallKeepDataAndPurgePreserveUnknownFiles(t *testing.T) {
	paths := testPaths(t)
	runner := newFakeRunner()
	manager := NewManager(paths, runner, fixedClock{time.Unix(1_800_000_000, 0)})
	setup, err := manager.SetupLocal(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, binary := range []string{manager.HubBinary, manager.CollectorBinary} {
		if err := os.WriteFile(binary, []byte("binary"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeTestPackageFiles(t, paths)
	unknownDoc := filepath.Join(paths.Docs, "operator-notes.txt")
	if err := os.WriteFile(unknownDoc, []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(paths.Support, "user-note.txt")
	if err := os.WriteFile(unknown, []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}
	keep, err := manager.Uninstall(context.Background(), true, false, setup.DeploymentGeneration, "", false)
	if err != nil || keep.Status != "succeeded" {
		t.Fatalf("keep-data=%#v err=%v", keep, err)
	}
	if _, err := os.Stat(paths.Database); err != nil {
		t.Fatalf("database removed by keep-data: %v", err)
	}
	if _, err := os.Stat(paths.HubConfig); err != nil {
		t.Fatalf("config removed by keep-data: %v", err)
	}
	for _, owned := range packagedServiceFiles(paths) {
		if _, err := os.Stat(owned); !os.IsNotExist(err) {
			t.Fatalf("packaged service file survived keep-data removal %s: %v", owned, err)
		}
	}
	if _, err := os.Stat(unknownDoc); err != nil {
		t.Fatalf("unknown docs neighbor was removed: %v", err)
	}
	preview, err := manager.Uninstall(context.Background(), false, true, "", "", false)
	if err != nil || !preview.Preview || preview.RemovedPaths == nil || preview.Failures == nil || len(preview.RemovedPaths) != 0 {
		t.Fatalf("purge preview=%#v err=%v", preview, err)
	}
	purge, err := manager.Uninstall(context.Background(), false, false, setup.DeploymentGeneration, setup.DeploymentID, true)
	if err != nil || purge.Status != "succeeded" || len(purge.RetryArguments) != 0 {
		t.Fatalf("purge=%#v err=%v", purge, err)
	}
	if _, err := os.Stat(unknown); err != nil {
		t.Fatalf("unknown file removed: %v", err)
	}
	if _, err := os.Stat(unknownDoc); err != nil {
		t.Fatalf("unknown docs neighbor removed by purge: %v", err)
	}
	if _, err := os.Stat(paths.Database); !os.IsNotExist(err) {
		t.Fatalf("database remains after purge: %v", err)
	}
}

func TestCollectorUninstallUsesLocalEnrollmentStateWithoutHubDatabase(t *testing.T) {
	paths := testPaths(t)
	manager := NewManager(paths, newFakeRunner(), fixedClock{time.Unix(1_800_000_000, 0)})
	deploymentID := "00000000-0000-4000-8000-000000000001"
	generation := "10000000-0000-4000-8000-000000000001"
	if err := writeJSONFile(paths.CollectorConfig, savedCollectorConfig{
		SchemaVersion:        domain.SchemaVersion,
		DeploymentID:         deploymentID,
		DeploymentGeneration: generation,
		OwnerSocket:          paths.CollectorSocket,
		TargetConfigured:     true,
		CollectionEnabled:    true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.Bin, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, binary := range []string{manager.HubBinary, manager.CollectorBinary} {
		if err := os.WriteFile(binary, []byte("binary"), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	result, err := manager.Uninstall(context.Background(), true, false, generation, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "succeeded" || !result.KeptData || !result.OllamaUnchanged {
		t.Fatalf("collector uninstall result=%#v", result)
	}
	if _, err := os.Stat(paths.CollectorConfig); err != nil {
		t.Fatalf("keep-data removed collector configuration: %v", err)
	}
	if _, err := os.Stat(manager.HubBinary); !os.IsNotExist(err) {
		t.Fatalf("collector uninstall left hub binary: %v", err)
	}
}

func TestUninstallStopFailurePreservesEverythingAndRetrySucceeds(t *testing.T) {
	for _, keepData := range []bool{true, false} {
		t.Run(map[bool]string{true: "keep", false: "purge"}[keepData], func(t *testing.T) {
			paths := testPaths(t)
			runner := newFakeRunner()
			manager := NewManager(paths, runner, fixedClock{time.Unix(1_800_000_000, 0)})
			setup, err := manager.SetupLocal(context.Background(), false)
			if err != nil {
				t.Fatal(err)
			}
			writeTestBinaries(t, manager)
			runner.loaded[CollectorLabel] = true
			runner.loaded[HubLabel] = true
			runner.failStop = HubLabel
			result, err := uninstallForTest(manager, setup, keepData)
			if err != nil || result.Status != "partial" || result.SafeCode != "service_stop_unconfirmed" || len(result.RemovedPaths) != 0 || len(result.RetryArguments) == 0 {
				t.Fatalf("failed stop result=%#v err=%v", result, err)
			}
			expectedRetry := manager.uninstallRetryArguments(removalReceipt{DeploymentID: setup.DeploymentID, DeploymentGeneration: setup.DeploymentGeneration, KeepData: keepData})
			if strings.Join(result.RetryArguments, "\x00") != strings.Join(expectedRetry, "\x00") {
				t.Fatalf("retry arguments=%q want=%q", result.RetryArguments, expectedRetry)
			}
			if keepData {
				if _, err := manager.Uninstall(context.Background(), false, false, setup.DeploymentGeneration, setup.DeploymentID, true); err == nil || !strings.Contains(err.Error(), "mode") {
					t.Fatalf("pending keep-data retry accepted purge mode: %v", err)
				}
			} else if _, err := manager.Uninstall(context.Background(), true, false, setup.DeploymentGeneration, "", false); err == nil || !strings.Contains(err.Error(), "mode") {
				t.Fatalf("pending purge retry accepted keep-data mode: %v", err)
			}
			if !runner.loaded[HubLabel] {
				t.Fatal("faithful stop failure incorrectly marked hub absent")
			}
			for _, path := range []string{paths.Database, manager.HubBinary, manager.CollectorBinary, paths.RemovalReceipt} {
				if _, err := os.Stat(path); err != nil {
					t.Fatalf("failed stop removed retry resource %s: %v", path, err)
				}
			}
			runner.failStop = ""
			retry, err := uninstallForTest(manager, setup, keepData)
			if err != nil || retry.Status != "succeeded" || len(retry.RetryArguments) != 0 {
				t.Fatalf("retry=%#v err=%v", retry, err)
			}
			if _, err := os.Stat(paths.RemovalReceipt); !os.IsNotExist(err) {
				t.Fatalf("successful retry retained receipt: %v", err)
			}
			_, dbErr := os.Stat(paths.Database)
			if keepData && dbErr != nil {
				t.Fatalf("keep-data retry removed database: %v", dbErr)
			}
			if !keepData && !os.IsNotExist(dbErr) {
				t.Fatalf("purge retry retained database: %v", dbErr)
			}
		})
	}
}

func TestUninstallPartialDeletionPreservesAuthorityAndRetries(t *testing.T) {
	for _, keepData := range []bool{true, false} {
		t.Run(map[bool]string{true: "keep", false: "purge"}[keepData], func(t *testing.T) {
			paths := testPaths(t)
			manager := NewManager(paths, newFakeRunner(), fixedClock{time.Unix(1_800_000_000, 0)})
			setup, err := manager.SetupLocal(context.Background(), false)
			if err != nil {
				t.Fatal(err)
			}
			writeTestBinaries(t, manager)
			originalRemove := manager.RemovePath
			failed := false
			manager.RemovePath = func(path string) error {
				if path == manager.CollectorBinary && !failed {
					failed = true
					return errors.New("injected interruption")
				}
				return originalRemove(path)
			}
			partial, err := uninstallForTest(manager, setup, keepData)
			if err != nil || partial.Status != "partial" || len(partial.RemovedPaths) == 0 || len(partial.RetryArguments) == 0 {
				t.Fatalf("partial removal=%#v err=%v", partial, err)
			}
			for _, path := range []string{paths.Database, manager.HubBinary, paths.RemovalReceipt} {
				if _, err := os.Stat(path); err != nil {
					t.Fatalf("partial removal lost authority %s: %v", path, err)
				}
			}
			manager.RemovePath = originalRemove
			retry, err := uninstallForTest(manager, setup, keepData)
			if err != nil || retry.Status != "succeeded" {
				t.Fatalf("partial removal retry=%#v err=%v", retry, err)
			}
		})
	}
}

func TestRemovalReceiptRejectsUnexpectedFields(t *testing.T) {
	paths := testPaths(t)
	if err := config.EnsurePrivateDir(paths.Support); err != nil {
		t.Fatal(err)
	}
	receipt := []byte(`{"schema_version":"1.0","deployment_id":"00000000-0000-4000-8000-000000000001","deployment_generation":"10000000-0000-4000-8000-000000000001","keep_data":false,"created_ms":1,"database":"/tmp/not-owned.sqlite3"}`)
	if err := config.WritePrivateFile(paths.RemovalReceipt, receipt); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(paths, newFakeRunner(), fixedClock{time.Unix(1_800_000_000, 0)})
	if _, err := manager.readRemovalReceipt(); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("receipt-provided path was accepted: %v", err)
	}
}

func TestUninstallFinalBoundariesRemainRetryable(t *testing.T) {
	for _, failAt := range []string{"receipt", "executable"} {
		t.Run(failAt, func(t *testing.T) {
			paths := testPaths(t)
			manager := NewManager(paths, newFakeRunner(), fixedClock{time.Unix(1_800_000_000, 0)})
			setup, err := manager.SetupLocal(context.Background(), false)
			if err != nil {
				t.Fatal(err)
			}
			writeTestBinaries(t, manager)
			wanted := paths.RemovalReceipt
			if failAt == "executable" {
				wanted = manager.HubBinary
			}
			originalRemove := manager.RemovePath
			failed := false
			manager.RemovePath = func(path string) error {
				if path == wanted && !failed {
					failed = true
					return errors.New("injected final interruption")
				}
				return originalRemove(path)
			}
			partial, err := uninstallForTest(manager, setup, false)
			if err != nil || partial.Status != "partial" {
				t.Fatalf("final boundary=%#v err=%v", partial, err)
			}
			_, executableErr := os.Stat(manager.HubBinary)
			if failAt == "executable" && executableErr != nil {
				t.Fatalf("executable failure lost runnable retry command: %v", executableErr)
			}
			if failAt == "receipt" && !os.IsNotExist(executableErr) {
				t.Fatalf("receipt boundary should require same verified external package binary: %v", executableErr)
			}
			if _, err := os.Stat(paths.RemovalReceipt); err != nil {
				t.Fatalf("final boundary lost receipt authority: %v", err)
			}
			if _, err := os.Stat(paths.Database); !os.IsNotExist(err) {
				t.Fatalf("final boundary did not reach post-database phase: %v", err)
			}
			manager.RemovePath = originalRemove
			retry, err := uninstallForTest(manager, setup, false)
			if err != nil || retry.Status != "succeeded" {
				t.Fatalf("final boundary retry=%#v err=%v", retry, err)
			}
		})
	}
}

func TestUninstallUnknownLaunchdStatePreservesRetryAuthority(t *testing.T) {
	paths := testPaths(t)
	runner := newFakeRunner()
	manager := NewManager(paths, runner, fixedClock{time.Unix(1_800_000_000, 0)})
	setup, err := manager.SetupLocal(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	writeTestBinaries(t, manager)
	runner.unknown[HubLabel] = true
	partial, err := uninstallForTest(manager, setup, false)
	if err != nil || partial.Status != "partial" || len(partial.RemovedPaths) != 0 {
		t.Fatalf("unknown launchd state=%#v err=%v", partial, err)
	}
	for _, path := range []string{paths.Database, manager.HubBinary, paths.RemovalReceipt} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("unknown state removed retry authority %s: %v", path, err)
		}
	}
}

func TestRemovalReceiptRejectsWrongGenerationModeAndStaleIdentity(t *testing.T) {
	paths := testPaths(t)
	manager := NewManager(paths, newFakeRunner(), fixedClock{time.Unix(1_800_000_000, 0)})
	setup, err := manager.SetupLocal(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	writeTestBinaries(t, manager)
	stale := removalReceipt{SchemaVersion: domain.SchemaVersion, DeploymentID: "00000000-0000-4000-8000-000000000001", DeploymentGeneration: "10000000-0000-4000-8000-000000000001", KeepData: false, CreatedMS: 1}
	if err := writeJSONFile(paths.RemovalReceipt, stale); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Uninstall(context.Background(), false, false, stale.DeploymentGeneration, stale.DeploymentID, true); err == nil || err.Error() != "restore_state_changed" {
		t.Fatalf("stale receipt overrode newer database: %v", err)
	}

	originalRemove := manager.RemovePath
	manager.RemovePath = func(path string) error {
		if path == paths.RemovalReceipt {
			return errors.New("retain receipt")
		}
		return originalRemove(path)
	}
	partial, err := uninstallForTest(manager, setup, false)
	if err != nil || partial.Status != "partial" {
		t.Fatalf("prepare receipt boundary=%#v err=%v", partial, err)
	}
	manager.RemovePath = originalRemove
	if _, err := manager.Uninstall(context.Background(), false, false, stale.DeploymentGeneration, setup.DeploymentID, true); err == nil || err.Error() != "restore_state_changed" {
		t.Fatalf("wrong receipt generation accepted: %v", err)
	}
	if _, err := manager.Uninstall(context.Background(), true, false, setup.DeploymentGeneration, "", false); err == nil || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("wrong receipt mode accepted: %v", err)
	}
	if _, err := manager.SetupLocal(context.Background(), false); err == nil || !strings.Contains(err.Error(), "removal retry") {
		t.Fatalf("setup replaced pending removal state: %v", err)
	}
	retry, err := uninstallForTest(manager, setup, false)
	if err != nil || retry.Status != "succeeded" {
		t.Fatalf("receipt retry=%#v err=%v", retry, err)
	}
}

func TestLiveOwnedSocketBlocksDeletionUntilProcessStops(t *testing.T) {
	paths := testPaths(t)
	manager := NewManager(paths, newFakeRunner(), fixedClock{time.Unix(1_800_000_000, 0)})
	setup, err := manager.SetupLocal(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	writeTestBinaries(t, manager)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- ServeOwnerSocket(ctx, paths.HubSocket, func(context.Context) (any, error) {
			return map[string]any{"state": "running"}, nil
		})
	}()
	waitForSocket(t, paths.HubSocket)
	partial, err := uninstallForTest(manager, setup, false)
	if err != nil || partial.Status != "partial" || partial.SafeCode != "service_stop_unconfirmed" {
		t.Fatalf("live socket removal=%#v err=%v", partial, err)
	}
	for _, path := range []string{paths.Database, manager.HubBinary} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("live socket allowed deletion of %s: %v", path, err)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	retry, err := uninstallForTest(manager, setup, false)
	if err != nil || retry.Status != "succeeded" {
		t.Fatalf("post-stop retry=%#v err=%v", retry, err)
	}
}

func TestUnhealthyAndNonrespondingOwnedSocketsStillBlockDeletion(t *testing.T) {
	for _, mode := range []string{"http_503", "nonresponding"} {
		t.Run(mode, func(t *testing.T) {
			paths := testPaths(t)
			manager := NewManager(paths, newFakeRunner(), fixedClock{time.Unix(1_800_000_000, 0)})
			setup, err := manager.SetupLocal(context.Background(), false)
			if err != nil {
				t.Fatal(err)
			}
			writeTestBinaries(t, manager)
			var stop func()
			if mode == "http_503" {
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan error, 1)
				go func() {
					done <- ServeOwnerSocket(ctx, paths.HubSocket, func(context.Context) (any, error) {
						return nil, errors.New("database unavailable")
					})
				}()
				stop = func() { cancel(); _ = <-done }
			} else {
				if err := config.EnsurePrivateDir(filepath.Dir(paths.HubSocket)); err != nil {
					t.Fatal(err)
				}
				listener, err := net.Listen("unix", paths.HubSocket)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(paths.HubSocket, 0o600); err != nil {
					t.Fatal(err)
				}
				stop = func() { _ = listener.Close(); _ = os.Remove(paths.HubSocket) }
			}
			defer stop()
			waitForSocket(t, paths.HubSocket)
			partial, err := uninstallForTest(manager, setup, false)
			if err != nil || partial.Status != "partial" || partial.SafeCode != "service_stop_unconfirmed" {
				t.Fatalf("%s socket result=%#v err=%v", mode, partial, err)
			}
			for _, path := range []string{paths.Database, manager.HubBinary} {
				if _, err := os.Stat(path); err != nil {
					t.Fatalf("%s socket allowed deletion of %s: %v", mode, path, err)
				}
			}
		})
	}
}

func TestOwnerSocketStatusIsLiveAndBounded(t *testing.T) {
	paths := testPaths(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- ServeOwnerSocket(ctx, paths.HubSocket, func(context.Context) (any, error) {
			return map[string]any{"state": "running"}, nil
		})
	}()
	waitForSocket(t, paths.HubSocket)
	body, err := ReadOwnerStatus(context.Background(), paths.HubSocket)
	if err != nil || !strings.Contains(string(body), "running") {
		t.Fatalf("owner status=%s err=%v", body, err)
	}
	info, _ := os.Stat(paths.HubSocket)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode=%o", info.Mode().Perm())
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestCLIVersionAndFreshStatusContract(t *testing.T) {
	paths := testPaths(t)
	manager := NewManager(paths, newFakeRunner(), fixedClock{time.Now()})
	var stdout, stderr bytes.Buffer
	if code := RunCLI(context.Background(), []string{"version", "--json"}, &stdout, &stderr, manager); code != 0 {
		t.Fatalf("version exit=%d stderr=%s", code, stderr.String())
	}
	var identity map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &identity); err != nil || identity["registry_revision"] != domain.RegistryRevision {
		t.Fatalf("version=%s err=%v", stdout.String(), err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := RunCLI(context.Background(), []string{"status", "--json"}, &stdout, &stderr, manager); code != 5 {
		t.Fatalf("fresh status exit=%d body=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(paths.Support); !os.IsNotExist(err) {
		t.Fatalf("fresh status created install state: %v", err)
	}
	if code := RunCLI(context.Background(), []string{"version", "--bogus"}, &stdout, &stderr, manager); code != 2 {
		t.Fatalf("unknown version flag exit=%d", code)
	}
}

func testPaths(t *testing.T) config.Paths {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".work", "u02-tests"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	home, err := os.MkdirTemp(root, "home-")
	if err != nil {
		t.Fatal(err)
	}
	run, err := os.MkdirTemp(root, "run-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(home)
		_ = os.RemoveAll(run)
	})
	return config.ForHome(home).WithRuntimeDir(run)
}

func unusedListenAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func writeTestBinaries(t *testing.T, manager *Manager) {
	t.Helper()
	for _, binary := range []string{manager.HubBinary, manager.CollectorBinary} {
		if err := os.WriteFile(binary, []byte("binary"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
}

func writeTestPackageFiles(t *testing.T, paths config.Paths) {
	t.Helper()
	for _, dir := range []string{paths.Docs, paths.Share} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range packagedServiceFiles(paths) {
		if err := os.WriteFile(path, []byte("packaged"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func packagedServiceFiles(paths config.Paths) []string {
	return []string{
		filepath.Join(paths.Docs, "install.html"), filepath.Join(paths.Docs, "operate.html"), filepath.Join(paths.Docs, "recover.html"),
		filepath.Join(paths.Share, "compatibility-unverified.json"), filepath.Join(paths.Share, "sbom.spdx.json"), filepath.Join(paths.Share, "build-provenance.json"), filepath.Join(paths.Share, "THIRD-PARTY-NOTICES.txt"),
	}
}

func uninstallForTest(manager *Manager, setup SetupResult, keepData bool) (UninstallResult, error) {
	if keepData {
		return manager.Uninstall(context.Background(), true, false, setup.DeploymentGeneration, "", false)
	}
	return manager.Uninstall(context.Background(), false, false, setup.DeploymentGeneration, setup.DeploymentID, true)
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Lstat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("owner socket did not appear")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
