package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"rmt.local/monitor/internal/auth"
	"rmt.local/monitor/internal/collector/pairing"
	"rmt.local/monitor/internal/collector/spool"
	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

const (
	HubLabel       = "com.llm-monitor.hub"
	CollectorLabel = "com.llm-monitor.collector"
)

type Manager struct {
	Input                   io.Reader
	Paths                   config.Paths
	Runner                  Runner
	Clock                   domain.Clock
	HubBinary               string
	CollectorBinary         string
	ListenAddress           string
	ListenAddressExplicit   bool
	CollectorListenAddress  string
	CollectorListenExplicit bool
	ConfirmDeployment       string
	ConfirmGeneration       string
	collectorListenChanged  bool
	RemovePath              func(string) error
	restorePrepared         func()
}

type Check struct {
	Code   string `json:"code"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type InstallCheckResult struct {
	SchemaVersion string  `json:"schema_version"`
	Role          string  `json:"role"`
	Compatible    bool    `json:"compatible"`
	Checks        []Check `json:"checks"`
}

type SetupResult struct {
	SchemaVersion        string `json:"schema_version"`
	Status               string `json:"status"`
	DeploymentID         string `json:"deployment_id"`
	DeploymentGeneration string `json:"deployment_generation"`
	BootstrapTokenPath   string `json:"bootstrap_token_path,omitempty"`
	BootstrapExpiresMS   int64  `json:"bootstrap_expires_ms,omitempty"`
	HubState             string `json:"hub_state"`
	CollectorState       string `json:"collector_state"`
	CollectorListen      string `json:"collector_listen,omitempty"`
	Created              bool   `json:"created"`
}

type StopResult struct {
	SchemaVersion   string   `json:"schema_version"`
	Status          string   `json:"status"`
	HubState        string   `json:"hub_state"`
	CollectorState  string   `json:"collector_state"`
	Failures        []string `json:"failures"`
	OllamaUnchanged bool     `json:"ollama_unchanged"`
}

type BootstrapRenewResult struct {
	SchemaVersion        string `json:"schema_version"`
	Status               string `json:"status"`
	DeploymentID         string `json:"deployment_id"`
	DeploymentGeneration string `json:"deployment_generation"`
	BootstrapTokenPath   string `json:"bootstrap_token_path"`
	BootstrapExpiresMS   int64  `json:"bootstrap_expires_ms"`
}

type LocalStatus struct {
	SchemaVersion     string                 `json:"schema_version"`
	DeploymentState   domain.DeploymentState `json:"deployment_state"`
	HubState          string                 `json:"hub_state"`
	CollectorState    string                 `json:"collector_state"`
	TargetState       string                 `json:"target_state"`
	HostCount         int                    `json:"host_count"`
	TargetCount       int                    `json:"target_count"`
	SourceCount       int                    `json:"source_count"`
	CollectionStarted bool                   `json:"collection_started"`
	InferenceStarted  bool                   `json:"inference_started"`
}

type Resource struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Exists bool   `json:"exists"`
	Bytes  int64  `json:"bytes"`
}

type UninstallResult struct {
	SchemaVersion   string     `json:"schema_version"`
	Status          string     `json:"status"`
	Preview         bool       `json:"preview"`
	KeptData        bool       `json:"kept_data"`
	Resources       []Resource `json:"resources"`
	RemovedPaths    []string   `json:"removed_paths"`
	Failures        []string   `json:"failures"`
	OllamaUnchanged bool       `json:"ollama_unchanged"`
	SafeCode        string     `json:"safe_code"`
	RetryArguments  []string   `json:"retry_arguments"`
}

type removalReceipt struct {
	SchemaVersion        string `json:"schema_version"`
	DeploymentID         string `json:"deployment_id"`
	DeploymentGeneration string `json:"deployment_generation"`
	KeepData             bool   `json:"keep_data"`
	CreatedMS            int64  `json:"created_ms"`
}

func NewManager(paths config.Paths, runner Runner, clock domain.Clock) *Manager {
	if runner == nil {
		runner = CommandRunner{}
	}
	if clock == nil {
		clock = domain.RealClock{}
	}
	return &Manager{Paths: paths, Runner: runner, Clock: clock, HubBinary: filepath.Join(paths.Bin, "llm-monitor"), CollectorBinary: filepath.Join(paths.Bin, "llm-monitor-collector"), ListenAddress: "127.0.0.1:9443", RemovePath: removeKnownPath}
}

func (m *Manager) InstallCheck(ctx context.Context, role string) InstallCheckResult {
	result := InstallCheckResult{SchemaVersion: domain.SchemaVersion, Role: role, Compatible: true}
	add := func(code string, ok bool, detail string) {
		status := "pass"
		if !ok {
			status = "fail"
			result.Compatible = false
		}
		result.Checks = append(result.Checks, Check{Code: code, Status: status, Detail: detail})
	}
	add("apple_silicon", runtime.GOOS == "darwin" && runtime.GOARCH == "arm64", runtime.GOOS+"/"+runtime.GOARCH)
	macVersion, macErr := currentMacVersion(ctx)
	add("macos_support_floor", macErr == nil && versionAtLeast(macVersion, 14, 0), macVersion)
	result.Checks = append(result.Checks, Check{Code: "exact_build_qualification", Status: "warning", Detail: "Unverified until T24 for this exact build"})
	var stat syscall.Statfs_t
	err := syscall.Statfs(m.Paths.Home, &stat)
	free := uint64(0)
	if err == nil {
		free = uint64(stat.Bavail) * uint64(stat.Bsize)
	}
	add("local_data_volume", err == nil && free >= 2*1024*1024*1024, fmt.Sprintf("%d bytes free", free))
	if role == "local" {
		settingsErr := m.resolveSetupListen()
		if settingsErr == nil {
			settingsErr = m.ValidateSettings()
		}
		var listenErr error
		if settingsErr == nil {
			listener, err := net.Listen("tcp", m.ListenAddress)
			listenErr = err
			if err == nil {
				_ = listener.Close()
			}
		}
		add("loopback_port_available", settingsErr == nil && listenErr == nil, m.ListenAddress)
	} else if role == "master" {
		settingsErr := m.resolveSetupListen()
		if settingsErr == nil && m.CollectorListenAddress == "" {
			m.CollectorListenAddress, settingsErr = discoverCollectorListenAddress()
		}
		if settingsErr == nil {
			settingsErr = ValidateCollectorListenAddress(m.CollectorListenAddress)
		}
		var listenErr, collectorErr error
		if settingsErr == nil {
			listener, err := net.Listen("tcp", m.ListenAddress)
			listenErr = err
			if err == nil {
				_ = listener.Close()
			}
			collector, err := net.Listen("tcp", m.CollectorListenAddress)
			collectorErr = err
			if err == nil {
				_ = collector.Close()
			}
		}
		add("loopback_port_available", settingsErr == nil && listenErr == nil, m.ListenAddress)
		add("collector_listener_address", settingsErr == nil, m.CollectorListenAddress)
		add("collector_listener_port_available", settingsErr == nil && collectorErr == nil, m.CollectorListenAddress)
	} else {
		add("collector_owner_socket_path", ValidateOwnerSocketPath(m.Paths.CollectorSocket) == nil, m.Paths.CollectorSocket)
	}
	_, launchErr := exec.LookPath("launchctl")
	add("launchd_user_domain", launchErr == nil, "user LaunchAgents")
	add("inference_account_not_required", true, "No inference or cloud account is required")
	return result
}

func (m *Manager) SetupLocal(ctx context.Context, start bool) (SetupResult, error) {
	return m.setupLocal(ctx, start, false)
}

// ReEnrollLocal explicitly advances the same-user collector retained by a
// trust-reset restore. Ordinary setup never rewrites an existing pairing.
func (m *Manager) ReEnrollLocal(ctx context.Context, start bool) (SetupResult, error) {
	return m.setupLocal(ctx, start, true)
}

func (m *Manager) setupLocal(ctx context.Context, start, reEnroll bool) (SetupResult, error) {
	if _, err := m.readRemovalReceipt(); err == nil {
		return SetupResult{}, errors.New("setup is blocked while an authenticated removal retry is pending; retry uninstall first")
	} else if !errors.Is(err, os.ErrNotExist) {
		return SetupResult{}, fmt.Errorf("inspect pending removal retry: %w", err)
	}
	if err := m.resolveSetupListen(); err != nil {
		return SetupResult{}, err
	}
	if err := m.ValidateSettings(); err != nil {
		return SetupResult{}, err
	}
	if start {
		presence, err := m.serviceState(ctx, HubLabel)
		if err != nil {
			return SetupResult{}, fmt.Errorf("cannot determine existing hub service before setup: %w", err)
		}
		if presence == ServicePresenceAbsent {
			listener, err := net.Listen("tcp", m.ListenAddress)
			if err != nil {
				return SetupResult{}, fmt.Errorf("hub listen address is occupied; no process was stopped: %w", err)
			}
			if err := listener.Close(); err != nil {
				return SetupResult{}, fmt.Errorf("close hub port preflight: %w", err)
			}
		}
	}
	for _, dir := range []string{m.Paths.Support, m.Paths.Bin, m.Paths.Hub, m.Paths.Collector, m.Paths.Logs, m.Paths.Run} {
		if err := config.EnsurePrivateDir(dir); err != nil {
			return SetupResult{}, err
		}
	}
	st, err := store.Open(m.Paths.Database, m.Clock)
	if err != nil {
		return SetupResult{}, err
	}
	defer st.Close()
	state, created, err := st.EnsureDeployment(ctx, "Local LLM Monitor")
	if err != nil {
		return SetupResult{}, err
	}
	if err := m.validateCollectorListenChange(state, created); err != nil {
		return SetupResult{}, err
	}
	localReEnrolled := false
	if _, err := os.Lstat(filepath.Join(m.Paths.Collector, "pairing.json")); errors.Is(err, os.ErrNotExist) {
		if reEnroll {
			return SetupResult{}, errors.New("retained local pairing is missing; inspect recovery before re-enrollment")
		}
		status, err := st.FoundationStatus(ctx)
		if err != nil {
			return SetupResult{}, err
		}
		if status.HostCount != 0 {
			return SetupResult{}, errors.New("collector pairing state is missing; explicit recovery required")
		}
		if _, err := pairing.Create(m.Paths.Collector, state.DeploymentID, state.DeploymentGeneration); err != nil {
			return SetupResult{}, err
		}
	} else if err != nil {
		return SetupResult{}, err
	} else if _, openErr := pairing.Open(m.Paths.Collector, state.DeploymentID, state.DeploymentGeneration); openErr != nil {
		if !reEnroll {
			return SetupResult{}, openErr
		}
		retained, retainedErr := pairing.ReadRetained(m.Paths.Collector, state.DeploymentID, "")
		if retainedErr != nil || retained.Generation == state.DeploymentGeneration {
			return SetupResult{}, errors.New("retained local pairing is not eligible for re-enrollment")
		}
		if _, stopErr := m.stopCollectorForReEnrollment(ctx); stopErr != nil {
			return SetupResult{}, stopErr
		}
		owner := store.TrustedOwnerContext{DeploymentID: state.DeploymentID, SecurityGeneration: state.DeploymentGeneration, InstallingUID: uint32(os.Getuid()), VerifiedOSOwner: true}
		registration := store.LocalHostRegistration{HostID: retained.HostID, InstallationUUID: retained.InstallationID, DisplayName: "This Mac", CollectorVersion: protocol.CurrentIdentity().Version, Capabilities: map[string]bool{"darwin": true, "ollama_read_only": true}}
		if err := st.ReEnrollLocalHost(ctx, owner, registration, retained.Generation); err != nil {
			return SetupResult{}, err
		}
		if _, err := pairing.ReEnroll(m.Paths.Collector, state.DeploymentID, retained.Generation, state.DeploymentGeneration, retained.InstallationID, retained.HostID); err != nil {
			return SetupResult{}, err
		}
		localReEnrolled = true
	}
	if _, err := ensureDefaultOllamaTarget(m.Paths.Collector, state.DeploymentGeneration); err != nil {
		return SetupResult{}, err
	}
	if _, err := ensureLocalCA(m.Paths, m.Clock.Now()); err != nil {
		return SetupResult{}, fmt.Errorf("configure local CA: %w", err)
	}
	if m.CollectorListenAddress != "" {
		if err := ensureRemoteHubCertificate(m.Paths, m.CollectorListenAddress, m.Clock.Now()); err != nil {
			return SetupResult{}, fmt.Errorf("configure collector TLS: %w", err)
		}
	}
	hubConfig := map[string]any{"schema_version": domain.SchemaVersion, "deployment_id": state.DeploymentID, "listen": m.ListenAddress, "database": m.Paths.Database, "owner_socket": m.Paths.HubSocket, "collection_enabled": true, "inference_enabled": false}
	if m.CollectorListenAddress != "" {
		hubConfig["collector_listen"] = m.CollectorListenAddress
	}
	targetConfigured := false
	if targets, targetErr := pairing.ReadTargets(m.Paths.Collector, state.DeploymentGeneration); targetErr == nil {
		for _, target := range targets.Targets {
			if !target.Retired {
				targetConfigured = true
			}
		}
	} else {
		return SetupResult{}, targetErr
	}
	collectorConfig := map[string]any{"schema_version": domain.SchemaVersion, "deployment_id": state.DeploymentID, "deployment_generation": state.DeploymentGeneration, "owner_socket": m.Paths.CollectorSocket, "target_configured": targetConfigured, "collection_enabled": true, "inference_enabled": false}
	if err := writeJSONFile(m.Paths.HubConfig, hubConfig); err != nil {
		return SetupResult{}, err
	}
	if err := writeJSONFile(m.Paths.CollectorConfig, collectorConfig); err != nil {
		return SetupResult{}, err
	}
	authService, err := auth.NewService(st, m.Paths, m.Clock)
	if err != nil {
		return SetupResult{}, err
	}
	tokenPath, expires, _, bootstrapErr := authService.EnsureFirstBootstrap(ctx)
	if bootstrapErr != nil && !errors.Is(bootstrapErr, store.ErrAdminExists) {
		return SetupResult{}, bootstrapErr
	}
	hubArgs := m.HubProgramArguments()[1:]
	collectorArgs := m.CollectorProgramArguments()[1:]
	if err := config.WritePrivateFile(m.Paths.HubPlist, []byte(m.plist(HubLabel, m.HubBinary, hubArgs, "hub"))); err != nil {
		return SetupResult{}, err
	}
	if err := config.WritePrivateFile(m.Paths.CollectorPlist, []byte(m.plist(CollectorLabel, m.CollectorBinary, collectorArgs, "collector"))); err != nil {
		return SetupResult{}, err
	}
	hubState, collectorState := "not_started", "not_started"
	if start {
		hubState, err = m.ensureLoaded(ctx, HubLabel, m.Paths.HubPlist)
		if err != nil {
			return SetupResult{}, err
		}
		collectorState, err = m.ensureLoaded(ctx, CollectorLabel, m.Paths.CollectorPlist)
		if err != nil {
			return SetupResult{}, err
		}
	}
	status := "configured"
	if localReEnrolled {
		status = "reenrolled"
	} else if reEnroll {
		status = "already_reenrolled"
	}
	result := SetupResult{SchemaVersion: domain.SchemaVersion, Status: status, DeploymentID: state.DeploymentID, DeploymentGeneration: state.DeploymentGeneration, BootstrapTokenPath: tokenPath, HubState: hubState, CollectorState: collectorState, CollectorListen: m.CollectorListenAddress, Created: created}
	if !expires.IsZero() {
		result.BootstrapExpiresMS = expires.UnixMilli()
	}
	return result, nil
}

func (m *Manager) HubProgramArguments() []string {
	return []string{m.HubBinary, "--installation-root", m.Paths.Home, "--runtime-dir", m.Paths.Run, "hub", "serve"}
}

func (m *Manager) CollectorProgramArguments() []string {
	return []string{m.CollectorBinary, "--installation-root", m.Paths.Home, "--runtime-dir", m.Paths.Run, "serve"}
}

func (m *Manager) RenewBootstrap(ctx context.Context) (BootstrapRenewResult, error) {
	st, err := store.Open(m.Paths.Database, m.Clock)
	if err != nil {
		return BootstrapRenewResult{}, err
	}
	defer st.Close()
	state, err := st.DeploymentState(ctx)
	if err != nil {
		return BootstrapRenewResult{}, err
	}
	service, err := auth.NewService(st, m.Paths, m.Clock)
	if err != nil {
		return BootstrapRenewResult{}, err
	}
	path, expires, _, err := service.RenewBootstrap(ctx)
	if err != nil {
		return BootstrapRenewResult{}, err
	}
	return BootstrapRenewResult{SchemaVersion: domain.SchemaVersion, Status: "bootstrap_renewed", DeploymentID: state.DeploymentID, DeploymentGeneration: state.DeploymentGeneration, BootstrapTokenPath: path, BootstrapExpiresMS: expires.UnixMilli()}, nil
}

func (m *Manager) ensureLoaded(ctx context.Context, label, plist string) (string, error) {
	domainTarget := "gui/" + strconv.Itoa(os.Getuid())
	presence, err := m.serviceState(ctx, label)
	if err != nil {
		return "state_unknown", fmt.Errorf("cannot determine launchd state for %s: %w", label, err)
	}
	if presence == ServicePresenceLoaded {
		return "already_loaded", nil
	}
	if output, err := m.Runner.Run(ctx, "launchctl", "bootstrap", domainTarget, plist); err != nil {
		return "load_failed", fmt.Errorf("launchctl bootstrap %s: %w (%s)", label, err, strings.TrimSpace(string(output)))
	}
	return "loaded", nil
}

func (m *Manager) serviceState(ctx context.Context, label string) (ServicePresence, error) {
	domainTarget := "gui/" + strconv.Itoa(os.Getuid())
	presence, err := m.Runner.ServiceState(ctx, domainTarget+"/"+label)
	if err != nil || presence == ServicePresenceUnknown {
		return ServicePresenceUnknown, err
	}
	return presence, nil
}

type savedHubConfig struct {
	SchemaVersion     string `json:"schema_version"`
	DeploymentID      string `json:"deployment_id"`
	Listen            string `json:"listen"`
	Database          string `json:"database"`
	OwnerSocket       string `json:"owner_socket"`
	CollectionEnabled bool   `json:"collection_enabled"`
	InferenceEnabled  bool   `json:"inference_enabled"`
	CollectorListen   string `json:"collector_listen,omitempty"`
}

type savedCollectorConfig struct {
	SchemaVersion        string `json:"schema_version"`
	DeploymentID         string `json:"deployment_id"`
	DeploymentGeneration string `json:"deployment_generation"`
	OwnerSocket          string `json:"owner_socket"`
	TargetConfigured     bool   `json:"target_configured"`
	CollectionEnabled    bool   `json:"collection_enabled"`
	InferenceEnabled     bool   `json:"inference_enabled"`
}

func (m *Manager) collectorDeploymentState() (domain.DeploymentState, error) {
	if err := config.ValidatePrivateFile(m.Paths.CollectorConfig); err != nil {
		return domain.DeploymentState{}, err
	}
	data, err := os.ReadFile(m.Paths.CollectorConfig)
	if err != nil {
		return domain.DeploymentState{}, err
	}
	if len(data) > 64<<10 {
		return domain.DeploymentState{}, errors.New("collector configuration exceeds bound")
	}
	var saved savedCollectorConfig
	if err := protocol.DecodeStrictJSON(bytes.NewReader(data), 64<<10, &saved); err != nil {
		return domain.DeploymentState{}, fmt.Errorf("decode collector configuration: %w", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return domain.DeploymentState{}, fmt.Errorf("decode collector configuration fields: %w", err)
	}
	for _, key := range []string{"schema_version", "deployment_id", "deployment_generation", "owner_socket", "target_configured", "collection_enabled", "inference_enabled"} {
		if _, ok := raw[key]; !ok {
			return domain.DeploymentState{}, fmt.Errorf("collector configuration missing %s", key)
		}
	}
	if saved.SchemaVersion != domain.SchemaVersion || !validUUID(saved.DeploymentID) || !validUUID(saved.DeploymentGeneration) || saved.OwnerSocket != m.Paths.CollectorSocket || saved.InferenceEnabled {
		return domain.DeploymentState{}, errors.New("collector configuration identity or safety boundary is invalid")
	}
	return domain.DeploymentState{SchemaVersion: domain.SchemaVersion, DeploymentID: saved.DeploymentID, DeploymentGeneration: saved.DeploymentGeneration, RecoveryState: "normal", MutationsAllowed: true}, nil
}

func (m *Manager) resolveSetupListen() error {
	m.collectorListenChanged = m.CollectorListenExplicit && m.CollectorListenAddress != ""
	info, err := os.Lstat(m.Paths.HubConfig)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect saved hub configuration: %w", err)
	}
	if info.Size() > 64*1024 {
		return errors.New("saved hub configuration is too large")
	}
	if err := config.ValidatePrivateFile(m.Paths.HubConfig); err != nil {
		return fmt.Errorf("validate saved hub configuration: %w", err)
	}
	data, err := os.ReadFile(m.Paths.HubConfig)
	if err != nil {
		return fmt.Errorf("read saved hub configuration: %w", err)
	}
	var saved savedHubConfig
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&saved); err != nil {
		return fmt.Errorf("decode saved hub configuration: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("saved hub configuration has trailing content")
	}
	if saved.SchemaVersion != domain.SchemaVersion || saved.DeploymentID == "" || saved.Database != m.Paths.Database || saved.InferenceEnabled {
		return errors.New("saved hub configuration is invalid")
	}
	if err := validateListenAddress(saved.Listen); err != nil {
		return fmt.Errorf("saved hub listen address is invalid: %w", err)
	}
	if saved.CollectorListen != "" {
		if err := ValidateCollectorListenAddress(saved.CollectorListen); err != nil {
			return err
		}
	}
	if m.CollectorListenExplicit {
		m.collectorListenChanged = m.CollectorListenAddress != saved.CollectorListen
	} else {
		m.CollectorListenAddress = saved.CollectorListen
		m.collectorListenChanged = false
	}
	if m.ListenAddressExplicit && m.ListenAddress != saved.Listen {
		return fmt.Errorf("saved hub listens on %s; explicit change to %s is not supported by setup", saved.Listen, m.ListenAddress)
	}
	m.ListenAddress = saved.Listen
	return nil
}

func (m *Manager) plist(label, binary string, arguments []string, logName string) string {
	args := ""
	for _, arg := range append([]string{binary}, arguments...) {
		args += "\n      <string>" + html.EscapeString(arg) + "</string>"
	}
	experimentalEnvironment := ""
	if config.ExperimentalFeaturesEnabled() {
		experimentalEnvironment = "<key>EnvironmentVariables</key><dict><key>LLM_MONITOR_EXPERIMENTAL</key><string>1</string></dict>"
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>` + experimentalEnvironment + `
  <key>Label</key><string>` + html.EscapeString(label) + `</string>
  <key>ProgramArguments</key><array>` + args + `
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>` + html.EscapeString(filepath.Join(m.Paths.Logs, logName+".log")) + `</string>
  <key>StandardErrorPath</key><string>` + html.EscapeString(filepath.Join(m.Paths.Logs, logName+".error.log")) + `</string>
</dict></plist>
`
}

func (m *Manager) Inventory(keepData bool) ([]Resource, error) {
	paths := m.Paths.PurgePaths()
	if keepData {
		paths = m.Paths.ServicePaths()
	}
	resources := make([]Resource, 0, len(paths))
	for _, path := range paths {
		resource := Resource{Path: path, Kind: "file"}
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			resources = append(resources, resource)
			continue
		}
		if err != nil {
			return nil, err
		}
		resource.Exists = true
		resource.Bytes = info.Size()
		if info.IsDir() {
			resource.Kind = "directory"
		} else if info.Mode()&os.ModeSymlink != 0 {
			resource.Kind = "symlink"
		} else if info.Mode()&os.ModeSocket != 0 {
			resource.Kind = "socket"
		}
		resources = append(resources, resource)
	}
	return resources, nil
}

func (m *Manager) Uninstall(ctx context.Context, keepData, preview bool, expectedGeneration, confirmDeployment string, backupAcknowledged bool) (UninstallResult, error) {
	resources, err := m.Inventory(keepData)
	if err != nil {
		return UninstallResult{}, err
	}
	result := UninstallResult{SchemaVersion: domain.SchemaVersion, Status: "succeeded", Preview: preview, KeptData: keepData, Resources: resources, RemovedPaths: []string{}, Failures: []string{}, OllamaUnchanged: true, SafeCode: "ok", RetryArguments: []string{}}
	if preview {
		return result, nil
	}
	receipt, receiptErr := m.readRemovalReceipt()
	haveReceipt := receiptErr == nil
	if receiptErr != nil && !errors.Is(receiptErr, os.ErrNotExist) {
		return UninstallResult{}, receiptErr
	}
	st, openErr := store.OpenExisting(m.Paths.Database, m.Clock)
	if openErr == nil {
		state, stateErr := st.DeploymentState(ctx)
		_ = st.Close()
		if stateErr != nil {
			return UninstallResult{}, stateErr
		}
		if haveReceipt && receipt.DeploymentID == state.DeploymentID && receipt.DeploymentGeneration == state.DeploymentGeneration && receipt.KeepData != keepData {
			return UninstallResult{}, errors.New("removal retry mode does not match the preserved receipt")
		}
		receipt = removalReceipt{SchemaVersion: domain.SchemaVersion, DeploymentID: state.DeploymentID, DeploymentGeneration: state.DeploymentGeneration, KeepData: keepData, CreatedMS: m.Clock.Now().UnixMilli()}
	} else if errors.Is(openErr, store.ErrNotConfigured) {
		state, collectorErr := m.collectorDeploymentState()
		if collectorErr == nil {
			if haveReceipt && receipt.DeploymentID == state.DeploymentID && receipt.DeploymentGeneration == state.DeploymentGeneration && receipt.KeepData != keepData {
				return UninstallResult{}, errors.New("removal retry mode does not match the preserved receipt")
			}
			receipt = removalReceipt{SchemaVersion: domain.SchemaVersion, DeploymentID: state.DeploymentID, DeploymentGeneration: state.DeploymentGeneration, KeepData: keepData, CreatedMS: m.Clock.Now().UnixMilli()}
		} else if !haveReceipt {
			return UninstallResult{}, collectorErr
		} else if receipt.KeepData != keepData {
			return UninstallResult{}, errors.New("removal retry mode does not match the preserved receipt")
		}
	} else if !haveReceipt {
		return UninstallResult{}, openErr
	}
	if expectedGeneration == "" {
		return UninstallResult{}, errors.New("uninstall apply requires --deployment-generation")
	}
	if expectedGeneration != receipt.DeploymentGeneration {
		return UninstallResult{}, errors.New("restore_state_changed")
	}
	if !keepData {
		if confirmDeployment != receipt.DeploymentID || !backupAcknowledged {
			return UninstallResult{}, errors.New("purge requires exact deployment id and acknowledged backup offer")
		}
	}
	if err := writeJSONFile(m.Paths.RemovalReceipt, receipt); err != nil {
		return UninstallResult{}, fmt.Errorf("preserve removal receipt: %w", err)
	}
	if refreshed, err := m.Inventory(keepData); err == nil {
		result.Resources = refreshed
	} else {
		return UninstallResult{}, err
	}
	result.RetryArguments = m.uninstallRetryArguments(receipt)
	if !m.stopOwnedServices(ctx, &result) {
		return markUninstallPartial(result, "service_stop_unconfirmed"), nil
	}
	for _, socket := range []struct {
		name string
		path string
	}{{"hub", m.Paths.HubSocket}, {"collector", m.Paths.CollectorSocket}} {
		active, probeErr := ProbeOwnerSocket(ctx, socket.path)
		if active {
			result.Failures = append(result.Failures, "active_owner_socket_"+socket.name)
		} else if probeErr != nil {
			result.Failures = append(result.Failures, "owner_socket_state_unknown_"+socket.name)
		}
	}
	if len(result.Failures) > 0 {
		return markUninstallPartial(result, "service_stop_unconfirmed"), nil
	}

	// Remove ordinary resources first. The database, retry command, and receipt
	// remain intact whenever an earlier deletion is interrupted or denied.
	for _, resource := range resources {
		if !resource.Exists || resource.Path == m.Paths.Database || resource.Path == m.HubBinary || resource.Path == m.Paths.RemovalReceipt {
			continue
		}
		var removeErr error
		if resource.Path == filepath.Join(m.Paths.Collector, "spool") {
			removeErr = spool.RemoveOwned(ctx, resource.Path)
		} else {
			removeErr = m.RemovePath(resource.Path)
		}
		if err := removeErr; err != nil {
			result.Failures = append(result.Failures, filepath.Base(resource.Path)+": "+err.Error())
			return markUninstallPartial(result, "removal_retry_required"), nil
		}
		result.RemovedPaths = append(result.RemovedPaths, resource.Path)
	}
	if !keepData {
		if err := m.RemovePath(m.Paths.Database); err != nil && !errors.Is(err, os.ErrNotExist) {
			result.Failures = append(result.Failures, filepath.Base(m.Paths.Database)+": "+err.Error())
			return markUninstallPartial(result, "removal_retry_required"), nil
		}
		result.RemovedPaths = appendIfPresent(result.RemovedPaths, resources, m.Paths.Database)
	}
	if err := m.RemovePath(m.HubBinary); err != nil && !errors.Is(err, os.ErrNotExist) {
		result.Failures = append(result.Failures, filepath.Base(m.HubBinary)+": "+err.Error())
		return markUninstallPartial(result, "removal_retry_required"), nil
	}
	result.RemovedPaths = appendIfPresent(result.RemovedPaths, resources, m.HubBinary)
	// The receipt is last. If its cleanup is interrupted after executable
	// unlink, the same verified package binary can resume from this receipt.
	// Setup refuses to create a replacement deployment while it remains.
	if err := m.RemovePath(m.Paths.RemovalReceipt); err != nil {
		result.Failures = append(result.Failures, filepath.Base(m.Paths.RemovalReceipt)+": "+err.Error())
		return markUninstallPartial(result, "removal_retry_required"), nil
	}
	result.RemovedPaths = append(result.RemovedPaths, m.Paths.RemovalReceipt)
	result.RetryArguments = []string{}
	removeEmptyParents(m.Paths)
	return result, nil
}

func (m *Manager) stopOwnedServices(ctx context.Context, result *UninstallResult) bool {
	domainTarget := "gui/" + strconv.Itoa(os.Getuid())
	for _, label := range []string{CollectorLabel, HubLabel} {
		target := domainTarget + "/" + label
		presence, stateErr := m.Runner.ServiceState(ctx, target)
		if stateErr != nil || presence == ServicePresenceUnknown {
			result.Failures = append(result.Failures, "state_unknown_"+label)
			continue
		}
		if presence == ServicePresenceAbsent {
			continue
		}
		_, stopErr := m.Runner.Run(ctx, "launchctl", "bootout", target)
		after, afterErr := m.Runner.ServiceState(ctx, target)
		if afterErr != nil || after != ServicePresenceAbsent {
			result.Failures = append(result.Failures, "stop_unconfirmed_"+label)
			continue
		}
		// A nonzero bootout followed by confirmed absence is safe: another owned
		// lifecycle action may have completed the stop concurrently.
		_ = stopErr
	}
	return len(result.Failures) == 0
}

func (m *Manager) uninstallRetryArguments(receipt removalReceipt) []string {
	args := []string{"--installation-root", m.Paths.Home, "--runtime-dir", m.Paths.Run, "uninstall"}
	if receipt.KeepData {
		args = append(args, "--keep-data")
	} else {
		args = append(args, "--purge")
	}
	args = append(args, "--deployment-generation", receipt.DeploymentGeneration)
	if !receipt.KeepData {
		args = append(args, "--confirm-deployment", receipt.DeploymentID, "--backup-offer-acknowledged")
	}
	return args
}

func (m *Manager) readRemovalReceipt() (removalReceipt, error) {
	if err := config.ValidatePrivateFile(m.Paths.RemovalReceipt); err != nil {
		return removalReceipt{}, err
	}
	info, err := os.Stat(m.Paths.RemovalReceipt)
	if err != nil {
		return removalReceipt{}, err
	}
	if info.Size() > 4096 {
		return removalReceipt{}, errors.New("removal receipt is too large")
	}
	data, err := os.ReadFile(m.Paths.RemovalReceipt)
	if err != nil {
		return removalReceipt{}, err
	}
	var receipt removalReceipt
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return removalReceipt{}, fmt.Errorf("decode removal receipt: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return removalReceipt{}, errors.New("removal receipt has trailing content")
	}
	if receipt.SchemaVersion != domain.SchemaVersion || !validUUID(receipt.DeploymentID) || !validUUID(receipt.DeploymentGeneration) || receipt.CreatedMS <= 0 {
		return removalReceipt{}, errors.New("removal receipt is invalid")
	}
	return receipt, nil
}

func validUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, char := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if char != '-' {
				return false
			}
			continue
		}
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}

func markUninstallPartial(result UninstallResult, safeCode string) UninstallResult {
	result.Status = "partial"
	result.SafeCode = safeCode
	return result
}

func appendIfPresent(paths []string, resources []Resource, wanted string) []string {
	for _, resource := range resources {
		if resource.Path == wanted && resource.Exists {
			return append(paths, wanted)
		}
	}
	return paths
}

func removeKnownPath(path string) error {
	if err := config.RejectSymlinkTree(filepath.Dir(path)); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.IsDir() {
		return os.Remove(path) // succeeds only when empty; never traverses unknown data.
	}
	return os.Remove(path)
}

func removeEmptyParents(paths config.Paths) {
	for _, dir := range []string{paths.Bin, paths.Docs, paths.Share, paths.Hub, paths.Collector, paths.Run, paths.Logs, paths.Support, filepath.Dir(paths.Run)} {
		_ = os.Remove(dir)
	}
}

func writeJSONFile(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return config.WritePrivateFile(path, data)
}

func (m *Manager) ValidateSettings() error {
	if err := validateListenAddress(m.ListenAddress); err != nil {
		return err
	}
	if err := ValidateOwnerSocketPath(m.Paths.HubSocket); err != nil {
		return err
	}
	return ValidateOwnerSocketPath(m.Paths.CollectorSocket)
}

func validateListenAddress(address string) error {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return errors.New("cleartext hub address must be loopback")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("listen port must be between 1 and 65535")
	}
	return nil
}

func currentMacVersion(ctx context.Context) (string, error) {
	if runtime.GOOS != "darwin" {
		return runtime.GOOS, errors.New("not macOS")
	}
	output, err := exec.CommandContext(ctx, "sw_vers", "-productVersion").Output()
	if err != nil {
		return "unknown", err
	}
	return strings.TrimSpace(string(output)), nil
}

func versionAtLeast(value string, wantMajor, wantMinor int) bool {
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return false
	}
	major, errMajor := strconv.Atoi(parts[0])
	minor, errMinor := strconv.Atoi(parts[1])
	if errMajor != nil || errMinor != nil {
		return false
	}
	return major > wantMajor || (major == wantMajor && minor >= wantMinor)
}
