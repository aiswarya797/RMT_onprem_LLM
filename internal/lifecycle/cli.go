package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"rmt.local/monitor/internal/collector/pairing"
	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

func RunCLI(ctx context.Context, args []string, stdout, stderr io.Writer, manager *Manager) int {
	jsonOutput := contains(args, "--json")
	fail := func(code int, safeCode, message, recovery string) int {
		if jsonOutput {
			requestID, _ := domain.NewUUID()
			_ = protocol.WriteJSON(stdout, domain.APIError{SchemaVersion: domain.SchemaVersion, Code: safeCode, Message: message, RecoveryAction: recovery, RequestID: requestID, Retryable: false, CLIExitCode: code})
		} else {
			fmt.Fprintln(stderr, message)
		}
		return code
	}
	if len(args) == 0 {
		return fail(2, "command_required", "A command is required.", "fix_input")
	}
	if args[0] == "--version" || args[0] == "version" {
		if !onlyFlags(args[1:], "--json") {
			return fail(2, "invalid_input", "Version accepts only --json.", "fix_input")
		}
		if jsonOutput {
			_ = protocol.WriteJSON(stdout, protocol.CurrentIdentity())
		} else {
			id := protocol.CurrentIdentity()
			fmt.Fprintf(stdout, "llm-monitor %s (%s) registry %s protocol %s\n", id.Version, id.Build, id.RegistryRevision, id.ProtocolVersion)
		}
		return 0
	}
	if !config.ExperimentalFeaturesEnabled() {
		remoteSetup := len(args) > 1 && args[0] == "setup" && (args[1] == "master" || args[1] == "collector")
		if remoteSetup || args[0] == "probe" || args[0] == "compare" || args[0] == "destinations" || args[0] == "deliveries" {
			return fail(2, "preview_feature_disabled", config.ExperimentalMessage, "none")
		}
	}
	// Recovery holds the exclusive installation lease in its own handler.
	// All other commands operating on configured state share the hub's lease,
	// so a stopped-hub restore cannot race a local-owner mutation.
	if args[0] != "restore" && args[0] != "install" {
		if args[0] == "setup" || args[0] == "backup" {
			if err := config.EnsurePrivateDir(manager.Paths.Support); err != nil {
				return fail(8, "installation_unavailable", "Installation directory is unavailable.", "use_local_owner_command")
			}
		}
		if _, err := os.Lstat(manager.Paths.Support); err == nil {
			lease, err := config.AcquireInstallationLease(manager.Paths, false)
			if err != nil {
				return fail(8, "installation_in_use", "Offline recovery is in progress or the installation lock is invalid.", "use_local_owner_command")
			}
			defer lease.Close()
			if err := RequireRecoveryReady(manager.Paths); err != nil && !(len(args) >= 2 && args[0] == "recovery" && args[1] == "inspect") {
				return fail(8, "recovery_incomplete", "Offline recovery must finish before this command can use the installation. Run recovery inspect with the same installation-root and runtime-dir options for verified resume instructions.", "use_local_owner_command")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fail(8, "installation_unavailable", "Installation directory is unavailable.", "use_local_owner_command")
		}
	}
	switch args[0] {
	case "collector":
		if len(args) > 1 && args[1] == "recover-spool" {
			return runCollectorRecoveryCLI(ctx, args[2:], stdout, stderr, manager, fail)
		}
		return fail(2, "invalid_command", "Use collector recover-spool preview|apply.", "fix_input")
	case "series", "history", "monitor-health":
		return runQueryCLI(ctx, args, stdout, stderr, manager, fail)
	case "incidents", "annotations":
		return runInvestigationCLI(ctx, args, stdout, stderr, manager, fail)
	case "destinations", "deliveries":
		return runNotificationsCLI(ctx, args, stdout, stderr, manager, fail)
	case "rules":
		return runRulesCLI(ctx, args, stdout, stderr, manager, fail)
	case "probe", "compare":
		return runComparisonCLI(ctx, args, stdout, stderr, manager, fail)
	case "recovery":
		if len(args) > 1 && args[1] == "grants" {
			return runRecoveryGrantsCLI(ctx, args[2:], stdout, stderr, manager, fail)
		}
		return runRecoveryInspectCLI(args[1:], stdout, manager, jsonOutput, fail)
	case "restore":
		return runRestoreCLI(ctx, args[1:], stdout, stderr, manager, jsonOutput, fail)
	case "backup":
		return runBackupCLI(ctx, args[1:], stdout, stderr, manager, jsonOutput, fail)
	case "auth":
		if len(args) > 1 && (args[1] == "login" || args[1] == "logout") {
			return runAuthSessionCLI(ctx, args[1:], stdout, stderr, manager, fail)
		}
		return runAuthTokenCLI(ctx, args[1:], stdout, stderr, manager, fail)
	case "hosts":
		if len(args) > 1 && (args[1] == "list" || args[1] == "show") {
			return runQueryCLI(ctx, args, stdout, stderr, manager, fail)
		}
		return runHostsCLI(ctx, args[1:], stdout, stderr, manager, fail)
	case "targets":
		if len(args) > 1 && args[1] == "check" {
			return runQueryCLI(ctx, args, stdout, stderr, manager, fail)
		}
		if len(args) < 2 {
			return fail(2, "invalid_command", "Use: llm-monitor targets add|edit|remove|list", "fix_input")
		}
		fs := flag.NewFlagSet("targets", flag.ContinueOnError)
		fs.SetOutput(stderr)
		manifestPath := fs.String("manifest", "", "reviewed private target manifest")
		manifestHash := fs.String("manifest-sha256", "", "reviewed file SHA-256")
		generation := fs.String("deployment-generation", "", "reviewed deployment generation")
		deployment := fs.String("confirm-deployment", "", "reviewed deployment ID")
		key := fs.String("idempotency-key", "", "retry identity UUID")
		targetID := fs.String("target", "", "target ID")
		revision := fs.Int("expected-revision", 0, "current target revision")
		_ = fs.Bool("json", false, "JSON output")
		if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 0 {
			return fail(2, "invalid_input", "Invalid target option.", "fix_input")
		}
		state, err := manager.targetConfigurationState(ctx)
		if err != nil {
			return fail(5, "state_unavailable", "Run setup before configuring a target.", "use_local_owner_command")
		}
		if args[1] == "list" {
			targets, err := pairing.ReadTargets(manager.Paths.Collector, state.DeploymentGeneration)
			if err != nil {
				return fail(8, "target_state_unavailable", safeMessage(err), "use_local_owner_command")
			}
			if jsonOutput {
				_ = protocol.WriteJSON(stdout, targets.Targets)
			} else {
				for _, target := range targets.Targets {
					fmt.Fprintf(stdout, "%s\t%s\trevision %d\tretired=%t\n", target.TargetID, target.Manifest.DisplayName, target.Revision, target.Retired)
				}
			}
			return 0
		}
		if *generation != state.DeploymentGeneration || *deployment != state.DeploymentID || !state.MutationsAllowed {
			return fail(7, "restore_state_changed", "Review the current deployment ID and generation before changing targets.", "review_current_state")
		}
		var manifest *pairing.TargetManifest
		if args[1] != "remove" {
			value, err := pairing.LoadManifest(*manifestPath, *manifestHash)
			if err != nil {
				return fail(2, "manifest_rejected", safeMessage(err), "fix_input")
			}
			manifest = &value
		}
		result, err := pairing.ApplyTarget(manager.Paths.Collector, state.DeploymentGeneration, *key, args[1], *targetID, *revision, manifest, *manifestHash)
		if err != nil {
			return fail(7, "target_change_rejected", safeMessage(err), "review_current_state")
		}
		if jsonOutput {
			_ = protocol.WriteJSON(stdout, result)
		} else {
			fmt.Fprintf(stdout, "Target configuration saved: %s. The collector will apply it on its next configuration check.\n", *result.ResourceID)
		}
		return 0
	case "install":
		if len(args) < 2 || args[1] != "check" {
			return fail(2, "invalid_command", "Use: llm-monitor install check --role local", "fix_input")
		}
		fs := flag.NewFlagSet("install check", flag.ContinueOnError)
		fs.SetOutput(stderr)
		role := fs.String("role", "local", "installation role")
		_ = fs.Bool("json", false, "JSON output")
		if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 0 || (*role != "local" && *role != "master" && *role != "collector") {
			return fail(2, "invalid_input", "Role must be local, master or collector.", "fix_input")
		}
		result := manager.InstallCheck(ctx, *role)
		if jsonOutput {
			_ = protocol.WriteJSON(stdout, result)
		} else {
			for _, check := range result.Checks {
				fmt.Fprintf(stdout, "%-34s %s (%s)\n", check.Code, strings.ToUpper(check.Status), check.Detail)
			}
		}
		if !result.Compatible {
			return 3
		}
		return 0
	case "setup":
		if len(args) < 2 || (args[1] != "local" && args[1] != "master" && args[1] != "collector") {
			return fail(2, "invalid_command", "Use: llm-monitor setup local, setup master or setup collector --pairing-code CODE --hub-url URL", "fix_input")
		}
		if args[1] == "collector" {
			fs := flag.NewFlagSet("setup collector", flag.ContinueOnError)
			fs.SetOutput(stderr)
			enrollmentFile := fs.String("enrollment-file", "", "reviewed private enrollment file")
			pairingCode := fs.String("pairing-code", "", "one-use pairing code generated by the master")
			hubURL := fs.String("hub-url", "", "reviewed master HTTPS endpoint")
			noStart := fs.Bool("no-start", false, "configure without loading the collector LaunchAgent")
			reEnroll := fs.Bool("re-enroll", false, "explicitly replace credentials for the retained reviewed host after restore")
			_ = fs.Bool("json", false, "JSON output")
			if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 0 || (*enrollmentFile == "" && (*pairingCode == "" || *hubURL == "")) || (*enrollmentFile != "" && (*pairingCode != "" || *hubURL != "")) {
				return fail(2, "invalid_input", "setup collector requires either --pairing-code CODE with --hub-url URL, or the legacy --enrollment-file PATH.", "fix_input")
			}
			if *reEnroll && *enrollmentFile == "" {
				return fail(2, "invalid_input", "collector re-enrollment requires the reviewed enrollment file.", "fix_input")
			}
			var result CollectorSetupResult
			var err error
			if *reEnroll {
				result, err = manager.ReEnrollCollector(ctx, *enrollmentFile, !*noStart)
			} else if *pairingCode != "" {
				result, err = manager.SetupCollectorPairing(ctx, *hubURL, *pairingCode, !*noStart)
			} else {
				result, err = manager.SetupCollector(ctx, *enrollmentFile, !*noStart)
			}
			if err != nil {
				return fail(8, "collector_setup_failed", safeMessage(err), "review_enrollment")
			}
			if jsonOutput {
				_ = protocol.WriteJSON(stdout, result)
			} else {
				fmt.Fprintf(stdout, "Remote collector configured for host %s. It will report to the master after the service starts.\n", result.HostID)
			}
			return 0
		}
		if args[1] == "master" {
			fs := flag.NewFlagSet("setup master", flag.ContinueOnError)
			fs.SetOutput(stderr)
			noStart := fs.Bool("no-start", false, "configure without loading the hub LaunchAgent")
			collectorListen := fs.String("collector-listen", "", "reviewed TLS collector listener: literal private IP:port")
			confirmDeployment := fs.String("confirm-deployment", "", "current deployment ID when changing collector listener")
			confirmGeneration := fs.String("deployment-generation", "", "current generation when changing collector listener")
			_ = fs.Bool("json", false, "JSON output")
			if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 0 || strings.EqualFold(*collectorListen, "off") {
				return fail(2, "invalid_input", "Invalid master setup option; master setup needs a collector listener.", "fix_input")
			}
			if !config.ExperimentalFeaturesEnabled() && *collectorListen != "" && *collectorListen != "off" {
				return fail(2, "preview_feature_disabled", config.ExperimentalMessage, "none")
			}
			fs.Visit(func(option *flag.Flag) {
				if option.Name == "collector-listen" {
					manager.CollectorListenExplicit = true
					manager.CollectorListenAddress = *collectorListen
				}
			})
			manager.ConfirmDeployment, manager.ConfirmGeneration = *confirmDeployment, *confirmGeneration
			result, err := manager.SetupMaster(ctx, !*noStart)
			if err != nil {
				return fail(8, "setup_failed", safeMessage(err), "use_local_owner_command")
			}
			if jsonOutput {
				_ = protocol.WriteJSON(stdout, result)
			} else {
				if *noStart {
					fmt.Fprintln(stdout, "Master dashboard and storage configured. The user hub service was not loaded.")
				} else {
					fmt.Fprintln(stdout, "Master dashboard and storage configured. The user hub service was loaded.")
				}
				fmt.Fprintf(stdout, "Open http://%s. Remote collectors use https://%s.\n", manager.ListenAddress, result.CollectorListen)
				if result.BootstrapTokenPath != "" {
					fmt.Fprintln(stdout, "Complete first-administrator setup in the local browser; the setup handoff is automatic.")
				}
			}
			return 0
		}
		fs := flag.NewFlagSet("setup local", flag.ContinueOnError)
		fs.SetOutput(stderr)
		noStart := fs.Bool("no-start", false, "configure without loading LaunchAgents")
		reEnroll := fs.Bool("re-enroll", false, "explicitly reactivate the retained same-user host after restore")
		collectorListen := fs.String("collector-listen", "", "opt-in TLS collector listener: literal private IP:port, or off")
		confirmDeployment := fs.String("confirm-deployment", "", "current deployment ID when changing collector listener")
		confirmGeneration := fs.String("deployment-generation", "", "current generation when changing collector listener")
		_ = fs.Bool("json", false, "JSON output")
		if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 0 {
			return fail(2, "invalid_input", "Invalid setup option.", "fix_input")
		}
		fs.Visit(func(option *flag.Flag) {
			if option.Name == "collector-listen" {
				manager.CollectorListenExplicit = true
				manager.CollectorListenAddress = *collectorListen
				if *collectorListen == "off" {
					manager.CollectorListenAddress = ""
				}
			}
		})
		manager.ConfirmDeployment, manager.ConfirmGeneration = *confirmDeployment, *confirmGeneration
		var result SetupResult
		var err error
		if *reEnroll {
			result, err = manager.ReEnrollLocal(ctx, !*noStart)
		} else {
			result, err = manager.SetupLocal(ctx, !*noStart)
		}
		if err != nil {
			return fail(8, "setup_failed", safeMessage(err), "use_local_owner_command")
		}
		if jsonOutput {
			_ = protocol.WriteJSON(stdout, result)
		} else {
			if *noStart {
				fmt.Fprintln(stdout, "Hub and collector configured. User LaunchAgents were not loaded.")
			} else {
				fmt.Fprintln(stdout, "Hub and collector configured. User LaunchAgents loaded.")
			}
			if manager.CollectorListenExplicit && result.HubState == "already_loaded" {
				fmt.Fprintln(stdout, "The collector listener configuration takes effect when the hub restarts.")
			}
			fmt.Fprintf(stdout, "Open http://%s.\n", manager.ListenAddress)
			if result.BootstrapTokenPath != "" {
				fmt.Fprintln(stdout, "Complete first-administrator setup in the local browser; the setup handoff is automatic.")
			}
		}
		return 0
	case "admin":
		if len(args) < 2 || args[1] != "bootstrap-renew" {
			return fail(2, "invalid_command", "Use: llm-monitor admin bootstrap-renew", "fix_input")
		}
		if !onlyFlags(args[2:], "--json") {
			return fail(2, "invalid_input", "bootstrap-renew accepts only --json.", "fix_input")
		}
		result, err := manager.RenewBootstrap(ctx)
		if err != nil {
			return fail(8, "bootstrap_renew_failed", safeMessage(err), "use_local_owner_command")
		}
		if jsonOutput {
			_ = protocol.WriteJSON(stdout, result)
		} else {
			fmt.Fprintf(stdout, "One-use admin setup token: %s\n", result.BootstrapTokenPath)
			fmt.Fprintln(stdout, "Expires in 30 minutes. The token value is not printed.")
		}
		return 0
	case "stop":
		if !onlyFlags(args[1:], "--json") {
			return fail(2, "invalid_input", "stop accepts only --json.", "fix_input")
		}
		result, err := manager.Stop(ctx)
		if err != nil {
			if jsonOutput {
				_ = protocol.WriteJSON(stdout, result)
				return 6
			}
			return fail(6, "stop_unconfirmed", safeMessage(err), "retry_later")
		}
		if jsonOutput {
			_ = protocol.WriteJSON(stdout, result)
		} else {
			fmt.Fprintf(stdout, "LLM Monitor stopped. Hub: %s. Collector: %s. Ollama and models unchanged.\n", result.HubState, result.CollectorState)
		}
		return 0
	case "status":
		if !onlyFlags(args[1:], "--json") {
			return fail(2, "invalid_input", "status accepts only --json.", "fix_input")
		}
		hubRaw, hubErr := ReadOwnerStatus(ctx, manager.Paths.HubSocket)
		collectorRaw, collectorErr := ReadOwnerStatus(ctx, manager.Paths.CollectorSocket)
		st, err := store.OpenReadOnly(manager.Paths.Database, manager.Clock)
		if err != nil {
			return fail(5, "status_unreachable", "Monitor state is unavailable.", "retry_later")
		}
		status, err := st.FoundationStatus(ctx)
		collected := false
		if err == nil {
			collected, err = st.HasCollectedFrames(ctx, status.State.DeploymentID)
		}
		_ = st.Close()
		if err != nil {
			return fail(8, "status_failed", "Monitor state could not be read.", "retry_later")
		}
		value := LocalStatus{SchemaVersion: domain.SchemaVersion, DeploymentState: status.State, HubState: "stopped", CollectorState: "stopped", TargetState: "none", HostCount: status.HostCount, TargetCount: status.TargetCount, SourceCount: status.SourceCount, CollectionStarted: collected, InferenceStarted: false}
		if hubErr == nil && json.Valid(hubRaw) {
			value.HubState = "running"
		}
		if status.TargetCount > 0 {
			value.TargetState = "configured"
		}
		if collectorErr == nil {
			var live struct {
				SchemaVersion     string `json:"schema_version"`
				Service           string `json:"service"`
				State             string `json:"state"`
				TargetState       string `json:"target_state"`
				CollectionStarted bool   `json:"collection_started"`
			}
			if json.Unmarshal(collectorRaw, &live) == nil && live.SchemaVersion == domain.SchemaVersion && live.Service == "collector" {
				switch live.State {
				case "starting", "running", "degraded", "configured_paused", "stopped":
					value.CollectorState = live.State
					value.CollectionStarted = value.CollectionStarted || live.CollectionStarted
				}
				if live.TargetState == "none" || live.TargetState == "configured" {
					value.TargetState = live.TargetState
				}
			}
		}
		if jsonOutput {
			_ = protocol.WriteJSON(stdout, value)
		} else {
			fmt.Fprintf(stdout, "Hub: %s\nCollector: %s\nTargets: %d\nCollection started: %t\nInference started: no\n", value.HubState, value.CollectorState, status.TargetCount, value.CollectionStarted)
		}
		return 0
	case "uninstall":
		fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
		fs.SetOutput(stderr)
		keep := fs.Bool("keep-data", false, "retain protected state")
		purge := fs.Bool("purge", false, "remove enumerated RMT state")
		preview := fs.Bool("preview", false, "show owned resources only")
		generation := fs.String("deployment-generation", "", "reviewed deployment generation")
		confirm := fs.String("confirm-deployment", "", "deployment ID")
		backupAck := fs.Bool("backup-offer-acknowledged", false, "acknowledge backup offer")
		_ = fs.Bool("json", false, "JSON output")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || *keep == *purge {
			return fail(2, "invalid_input", "Choose exactly one of --keep-data or --purge.", "fix_input")
		}
		result, err := manager.Uninstall(ctx, *keep, *preview, *generation, *confirm, *backupAck)
		if err != nil {
			if err.Error() == "restore_state_changed" {
				return fail(7, "restore_state_changed", "The deployment generation changed. Review current state before retrying.", "review_current_state")
			}
			return fail(2, "uninstall_blocked", safeMessage(err), "fix_input")
		}
		if jsonOutput {
			_ = protocol.WriteJSON(stdout, result)
		} else if result.Preview {
			for _, item := range result.Resources {
				fmt.Fprintf(stdout, "%s\t%s\t%t\n", item.Kind, item.Path, item.Exists)
			}
		} else {
			fmt.Fprintf(stdout, "Uninstall %s; removed %d paths. Ollama unchanged.\n", result.Status, len(result.RemovedPaths))
			if result.Status == "partial" && len(result.RetryArguments) > 0 {
				writePartialUninstallRecovery(stdout, manager.HubBinary, result)
			}
		}
		if result.Status == "partial" {
			return 6
		}
		return 0
	default:
		return fail(2, "invalid_command", "Unknown command.", "fix_input")
	}
}

func writePartialUninstallRecovery(output io.Writer, installedExecutable string, result UninstallResult) {
	fmt.Fprintf(output, "Recovery reason: %s.\n", safeMessage(errors.New(result.SafeCode)))
	const maxFailures = 8
	for index, failure := range result.Failures {
		if index == maxFailures {
			fmt.Fprintf(output, "Failure: %d additional failures omitted.\n", len(result.Failures)-maxFailures)
			break
		}
		fmt.Fprintf(output, "Failure: %s\n", safeMessage(errors.New(failure)))
	}
	if retryExecutableExists(installedExecutable) {
		fmt.Fprint(output, "Retry:", " ", shellQuote(installedExecutable))
		writeShellArguments(output, result.RetryArguments)
		fmt.Fprintln(output)
		return
	}
	fmt.Fprintln(output, "Retry with the llm-monitor executable from the same verified package or a verified restaged copy; do not run setup.")
	fmt.Fprint(output, "Retry arguments:")
	writeShellArguments(output, result.RetryArguments)
	fmt.Fprintln(output)
}

func retryExecutableExists(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}

func writeShellArguments(output io.Writer, arguments []string) {
	for _, argument := range arguments {
		fmt.Fprint(output, " ", shellQuote(argument))
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func contains(args []string, value string) bool {
	for _, arg := range args {
		if arg == value {
			return true
		}
	}
	return false
}

func onlyFlags(args []string, allowed ...string) bool {
	set := make(map[string]struct{}, len(allowed))
	for _, item := range allowed {
		set[item] = struct{}{}
	}
	for _, arg := range args {
		if _, ok := set[arg]; !ok {
			return false
		}
	}
	return true
}

func safeMessage(err error) string {
	if err == nil {
		return "Operation failed."
	}
	message := err.Error()
	if len(message) > 256 {
		message = message[:256]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, message)
}
