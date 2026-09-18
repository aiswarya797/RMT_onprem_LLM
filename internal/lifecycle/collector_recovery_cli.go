package lifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"time"

	"rmt.local/monitor/internal/collector/pairing"
	"rmt.local/monitor/internal/collector/scheduler"
	"rmt.local/monitor/internal/collector/spool"
	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

const (
	// A full 256 MiB spool can require thousands of disjoint 64 KiB
	// manifests. Keep compact retry identities for the whole 24 hour
	// eligibility window while limiting incomplete, inline crash-recovery
	// records and active applies to the deployment-wide grant cap.
	recoveryCLIReceiptBytes         = protocol.MaxRecoveryReceiptStateBytes
	recoveryCLIReceiptLimit         = 8192
	recoveryPendingPreviewLimit     = 4
	recoveryActiveApplyReceiptLimit = 4
)

type collectorRecoveryPreviewResult struct {
	SchemaVersion  string `json:"schema_version"`
	Status         string `json:"status"`
	ManifestPath   string `json:"manifest_path"`
	ManifestSHA256 string `json:"manifest_sha256"`
	TotalFrames    int    `json:"total_frames"`
	TotalBytes     int64  `json:"total_bytes"`
	SegmentCount   int    `json:"segment_count"`
	FirstMS        int64  `json:"first_ms"`
	LastMS         int64  `json:"last_ms"`
}

type collectorRecoveryApplyReport struct {
	SchemaVersion               string `json:"schema_version"`
	Status                      string `json:"status"`
	GrantID                     string `json:"grant_id"`
	GrantSHA256                 string `json:"grant_sha256"`
	DeploymentID                string `json:"deployment_id"`
	HostID                      string `json:"host_id"`
	OriginalSecurityGeneration  string `json:"original_security_generation"`
	OriginalCollectorBootID     string `json:"original_collector_boot_id"`
	AdmittingSecurityGeneration string `json:"admitting_security_generation"`
	AdmittingSessionGeneration  int64  `json:"admitting_session_generation"`
	Recovered                   int    `json:"recovered"`
	Duplicate                   int    `json:"duplicate"`
	Rejected                    int    `json:"rejected"`
	Remaining                   int    `json:"remaining"`
	Complete                    bool   `json:"complete"`
	CreatedMS                   int64  `json:"created_ms"`
}

type recoveryPreviewReceipt struct {
	Key             string                     `json:"key"`
	ScopeSHA        string                     `json:"scope_sha256"`
	AtMS            int64                      `json:"at_ms"`
	ManifestPath    string                     `json:"manifest_path,omitempty"`
	ManifestFileSHA string                     `json:"manifest_file_sha256,omitempty"`
	ManifestSHA     string                     `json:"manifest_sha256,omitempty"`
	PendingManifest *protocol.RecoveryManifest `json:"pending_manifest,omitempty"`
}

type recoveryApplyReceipt struct {
	Key             string                `json:"key"`
	GrantFileSHA256 string                `json:"grant_file_sha256"`
	GrantSHA256     string                `json:"grant_sha256"`
	ReportPath      string                `json:"report_path"`
	AtMS            int64                 `json:"at_ms"`
	BootID          string                `json:"admitting_collector_boot_id"`
	PreviousSession int64                 `json:"previous_session_generation"`
	Session         int64                 `json:"admitting_session_generation"`
	ActivatedMS     int64                 `json:"activated_ms"`
	Recovered       int                   `json:"recovered"`
	Duplicate       int                   `json:"duplicate"`
	PendingACK      *protocol.RecoveryACK `json:"pending_ack"`
	Complete        bool                  `json:"complete"`
	ReportCreatedMS int64                 `json:"report_created_ms,omitempty"`
}

type recoveryCLIReceipts struct {
	Version  int                      `json:"version"`
	Previews []recoveryPreviewReceipt `json:"previews"`
	Applies  []recoveryApplyReceipt   `json:"applies"`
}

type collectorRecoveryConfig struct {
	SchemaVersion        string `json:"schema_version"`
	DeploymentID         string `json:"deployment_id"`
	DeploymentGeneration string `json:"deployment_generation"`
	OwnerSocket          string `json:"owner_socket"`
	TargetConfigured     bool   `json:"target_configured"`
	CollectionEnabled    bool   `json:"collection_enabled"`
	InferenceEnabled     bool   `json:"inference_enabled"`
}

type recoveryTransport interface {
	Activate(context.Context, protocol.SessionActivation) (protocol.SessionResult, error)
	RecoveryReplay(context.Context, protocol.RecoveryReplay) (protocol.RecoveryACK, error)
	Close()
}

func runCollectorRecoveryCLI(ctx context.Context, args []string, stdout, stderr io.Writer, manager *Manager, fail cliFailure) int {
	if len(args) == 1 && args[0] == "--help" {
		fmt.Fprintln(stdout, "llm-monitor collector recover-spool preview|apply")
		return 0
	}
	if len(args) == 0 || (args[0] != "preview" && args[0] != "apply") {
		return fail(2, "invalid_command", "Use collector recover-spool preview or apply.", "fix_input")
	}
	if args[0] == "preview" {
		return runCollectorRecoveryPreview(ctx, args[1:], stdout, stderr, manager, fail)
	}
	return runCollectorRecoveryApply(ctx, args[1:], stdout, stderr, manager, fail)
}

func runCollectorRecoveryPreview(_ context.Context, args []string, stdout, stderr io.Writer, manager *Manager, fail cliFailure) int {
	fs := flag.NewFlagSet("collector recover-spool preview", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "new private recovery manifest path")
	key := fs.String("idempotency-key", "", "exact preview retry UUID")
	confirmDeployment := fs.String("confirm-deployment", "", "reviewed deployment ID")
	generation := fs.String("deployment-generation", "", "reviewed current generation")
	originalGeneration := fs.String("original-generation", "", "retained spool generation")
	originalBoot := fs.String("original-boot", "", "retained collector boot ID")
	source := fs.String("source", "", "optional retained source ID")
	from := fs.Uint64("from-sequence", 0, "optional inclusive sequence start")
	to := fs.Uint64("to-sequence", 0, "optional inclusive sequence end")
	jsonOutput := fs.Bool("json", false, "versioned JSON result")
	if len(args) == 1 && args[0] == "--help" {
		fs.SetOutput(stdout)
		fmt.Fprintln(stdout, "llm-monitor collector recover-spool preview")
		fs.PrintDefaults()
		return 0
	}
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return fail(2, "invalid_input", "Invalid recovery preview option.", "fix_input")
	}
	if !filepath.IsAbs(*out) || len(*out) > 1024 || !validUUID(*key) || !validUUID(*confirmDeployment) || !validUUID(*generation) || !validUUID(*originalGeneration) || !validUUID(*originalBoot) || (*source != "" && !validUUID(*source)) {
		return fail(2, "invalid_input", "Provide reviewed identities, a UUID idempotency key and an absolute output path.", "fix_input")
	}
	var fromValue, toValue *uint64
	fs.Visit(func(value *flag.Flag) {
		switch value.Name {
		case "from-sequence":
			fromValue = from
		case "to-sequence":
			toValue = to
		}
	})
	if (fromValue != nil && *fromValue > uint64(protocol.MaxUint53)) || (toValue != nil && *toValue > uint64(protocol.MaxUint53)) || (fromValue != nil && toValue != nil && *fromValue > *toValue) {
		return fail(2, "invalid_input", "Sequence bounds must be exact nondecreasing JSON integers.", "fix_input")
	}
	configured, local, err := openCollectorRecoveryIdentity(manager, *confirmDeployment, *generation)
	if err != nil {
		return fail(7, "recovery_identity_rejected", safeMessage(err), "review_current_state")
	}
	identity := local.Snapshot()
	definitions, err := collectorRecoveryDefinitions(manager.Paths.Collector, identity)
	if err != nil {
		return fail(3, "recovery_definition_unavailable", safeMessage(err), "repair_source")
	}
	queue, err := spool.OpenReadOnly(filepath.Join(manager.Paths.Collector, "spool"), spool.Options{Now: manager.Clock.Now})
	if err != nil {
		return fail(7, "collector_must_be_stopped", "Stop the collector, then retry. "+safeMessage(err), "retry_later")
	}
	defer queue.Close()
	now := manager.Clock.Now().UnixMilli()
	receipts, err := loadRecoveryCLIReceipts(manager.Paths.Collector, now)
	if err != nil {
		return fail(3, "recovery_receipt_rejected", safeMessage(err), "repair_source")
	}
	scope := struct {
		DeploymentID, Generation, OriginalGeneration, OriginalBoot, Source, OutputPath string
		From, To                                                                       *uint64
	}{configured.DeploymentID, configured.DeploymentGeneration, *originalGeneration, *originalBoot, *source, *out, fromValue, toValue}
	scopeBytes, _ := json.Marshal(scope)
	scopeHash := sha256.Sum256(scopeBytes)
	scopeSHA := hex.EncodeToString(scopeHash[:])
	var manifest protocol.RecoveryManifest
	receiptIndex := -1
	for index := range receipts.Previews {
		receipt := &receipts.Previews[index]
		if receipt.Key != *key {
			continue
		}
		if receipt.ScopeSHA != scopeSHA {
			return fail(7, "idempotency_conflict", "The preview key was used for a different recovery scope. Review the scope and use a new UUID only for a new preview.", "review_current_state")
		}
		receiptIndex = index
		break
	}
	if receiptIndex < 0 {
		if len(receipts.Previews) >= recoveryCLIReceiptLimit {
			return fail(7, "recovery_receipt_capacity", "The bounded 24-hour recovery preview receipt ledger is full.", "retry_later")
		}
		pending := 0
		for _, receipt := range receipts.Previews {
			if receipt.PendingManifest != nil {
				pending++
			}
		}
		if pending >= recoveryPendingPreviewLimit {
			return fail(7, "recovery_receipt_capacity", "Four recovery previews still need their exact private manifest files repaired.", "retry_later")
		}
		manifest, err = queue.PreviewRecovery(spool.RecoveryPreviewOptions{DeploymentID: configured.DeploymentID, HostID: identity.HostID, OriginalSecurityGeneration: *originalGeneration, OriginalCollectorBootID: *originalBoot, CreatedMS: now, Definitions: definitions, SourceID: *source, FromSequence: fromValue, ToSequence: toValue})
		if err != nil {
			return fail(7, "recovery_preview_refused", safeMessage(err), "review_current_state")
		}
		receipts.Previews = append(receipts.Previews, recoveryPreviewReceipt{Key: *key, ScopeSHA: scopeSHA, AtMS: now, PendingManifest: &manifest})
		receiptIndex = len(receipts.Previews) - 1
		if err := saveRecoveryCLIReceipts(manager.Paths.Collector, receipts); err != nil {
			return fail(8, "recovery_receipt_write_failed", "Retry with the same idempotency key. "+safeMessage(err), "retry_later")
		}
	} else {
		manifest, err = manifestForPreviewReceipt(receipts.Previews[receiptIndex])
		if err != nil {
			return fail(3, "recovery_manifest_receipt_invalid", safeMessage(err), "repair_source")
		}
	}
	encoded, _ := json.Marshal(manifest)
	fileBytes := encoded
	if err := writeExactPrivateRecoveryFile(*out, fileBytes, protocol.MaxRecoveryManifestBytes); err != nil {
		return fail(8, "manifest_file_write_failed", "Retry with the same idempotency key. "+safeMessage(err), "retry_later")
	}
	fileHash := sha256.Sum256(fileBytes)
	receipt := &receipts.Previews[receiptIndex]
	receipt.ManifestPath = *out
	receipt.ManifestFileSHA = hex.EncodeToString(fileHash[:])
	receipt.ManifestSHA = manifest.ManifestSHA256
	receipt.PendingManifest = nil
	if err := saveRecoveryCLIReceipts(manager.Paths.Collector, receipts); err != nil {
		return fail(8, "recovery_receipt_write_failed", "Retry with the same idempotency key. "+safeMessage(err), "retry_later")
	}
	firstMS, lastMS := recoveryManifestRange(manifest)
	result := collectorRecoveryPreviewResult{SchemaVersion: domain.SchemaVersion, Status: "previewed", ManifestPath: *out, ManifestSHA256: manifest.ManifestSHA256, TotalFrames: manifest.TotalFrames, TotalBytes: manifest.TotalBytes, SegmentCount: len(manifest.Segments), FirstMS: firstMS, LastMS: lastMS}
	writeCollectorRecoveryResult(stdout, *jsonOutput, result, fmt.Sprintf("Recovery preview: %d frames in %d reviewed segments\nManifest: %s\nSHA-256: %s", result.TotalFrames, result.SegmentCount, result.ManifestPath, result.ManifestSHA256))
	return 0
}

func runCollectorRecoveryApply(ctx context.Context, args []string, stdout, stderr io.Writer, manager *Manager, fail cliFailure) int {
	fs := flag.NewFlagSet("collector recover-spool apply", flag.ContinueOnError)
	fs.SetOutput(stderr)
	grantPath := fs.String("grant", "", "reviewed private recovery grant")
	grantFileSHA := fs.String("grant-sha256", "", "SHA-256 of exact grant file bytes")
	key := fs.String("idempotency-key", "", "exact apply retry UUID")
	confirmDeployment := fs.String("confirm-deployment", "", "reviewed deployment ID")
	generation := fs.String("deployment-generation", "", "reviewed current generation")
	reportOut := fs.String("report-out", "", "private recovery report path")
	jsonOutput := fs.Bool("json", false, "versioned JSON result")
	if len(args) == 1 && args[0] == "--help" {
		fs.SetOutput(stdout)
		fmt.Fprintln(stdout, "llm-monitor collector recover-spool apply")
		fs.PrintDefaults()
		return 0
	}
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return fail(2, "invalid_input", "Invalid recovery apply option.", "fix_input")
	}
	if !filepath.IsAbs(*grantPath) || !filepath.IsAbs(*reportOut) || len(*grantPath) > 1024 || len(*reportOut) > 1024 || !validSHA256(*grantFileSHA) || !validUUID(*key) || !validUUID(*confirmDeployment) || !validUUID(*generation) {
		return fail(2, "invalid_input", "Provide the reviewed grant, exact file hash, identities, retry UUID and absolute report path.", "fix_input")
	}
	configured, local, err := openCollectorRecoveryIdentity(manager, *confirmDeployment, *generation)
	if err != nil {
		return fail(7, "recovery_identity_rejected", safeMessage(err), "review_current_state")
	}
	grantBytes, err := readPrivateRecoveryFile(*grantPath, protocol.MaxRecoveryManifestBytes)
	if err != nil {
		return fail(3, "grant_file_rejected", safeMessage(err), "fix_input")
	}
	digest := sha256.Sum256(grantBytes)
	if hex.EncodeToString(digest[:]) != *grantFileSHA {
		return fail(7, "grant_file_hash_mismatch", "The grant file differs from the reviewed SHA-256.", "review_current_state")
	}
	grant, err := protocol.DecodeRecoveryGrant(bytes.NewReader(grantBytes))
	if err != nil {
		return fail(3, "grant_file_rejected", "The grant file is invalid or its embedded hash differs.", "fix_input")
	}
	identity := local.Snapshot()
	if grant.DeploymentID != configured.DeploymentID || grant.HostID != identity.HostID || grant.CurrentSecurityGeneration != configured.DeploymentGeneration {
		return fail(7, "grant_owner_mismatch", "The grant does not belong to this current collector identity.", "review_current_state")
	}
	queue, err := spool.Open(filepath.Join(manager.Paths.Collector, "spool"), spool.Options{Now: manager.Clock.Now})
	if err != nil {
		return fail(7, "collector_must_be_stopped", "Stop the collector, then retry. "+safeMessage(err), "retry_later")
	}
	defer queue.Close()
	now := manager.Clock.Now().UnixMilli()
	receipts, err := loadRecoveryCLIReceipts(manager.Paths.Collector, now)
	if err != nil {
		return fail(3, "recovery_receipt_rejected", safeMessage(err), "repair_source")
	}
	receiptIndex := -1
	for index := range receipts.Applies {
		if receipts.Applies[index].Key == *key {
			receiptIndex = index
			break
		}
	}
	if receiptIndex >= 0 {
		receipt := &receipts.Applies[receiptIndex]
		if receipt.GrantFileSHA256 != *grantFileSHA || receipt.GrantSHA256 != grant.GrantSHA256 || receipt.ReportPath != *reportOut {
			return fail(7, "idempotency_conflict", "The apply key was used for a different reviewed grant. Review the grant and use a new UUID only for a new apply.", "review_current_state")
		}
		if receipt.ReportCreatedMS != 0 {
			report := collectorRecoveryReport(grant, *receipt)
			if code := finishCollectorRecoveryReport(stdout, *jsonOutput, *reportOut, report, fail); code != 0 {
				return code
			}
			if !receipt.Complete {
				return 6
			}
			return 0
		}
	} else {
		if len(receipts.Applies) >= recoveryCLIReceiptLimit {
			return fail(7, "recovery_receipt_capacity", "The bounded 24-hour recovery apply receipt ledger is full.", "retry_later")
		}
		active := 0
		for _, receipt := range receipts.Applies {
			if receipt.ReportCreatedMS == 0 {
				active++
			}
		}
		if active >= recoveryActiveApplyReceiptLimit {
			return fail(7, "recovery_receipt_capacity", "Four recovery applies are still active. Retry an existing apply before starting another.", "retry_later")
		}
		bootID, err := domain.NewUUID()
		if err != nil {
			return fail(8, "recovery_identity_failed", safeMessage(err), "retry_later")
		}
		receipts.Applies = append(receipts.Applies, recoveryApplyReceipt{Key: *key, GrantFileSHA256: *grantFileSHA, GrantSHA256: grant.GrantSHA256, ReportPath: *reportOut, AtMS: now, BootID: bootID, PreviousSession: identity.PreviousSession})
		receiptIndex = len(receipts.Applies) - 1
		if err := saveRecoveryCLIReceipts(manager.Paths.Collector, receipts); err != nil {
			return fail(8, "recovery_receipt_write_failed", "Retry with the same idempotency key. "+safeMessage(err), "retry_later")
		}
	}
	receipt := &receipts.Applies[receiptIndex]
	transport, err := newCollectorRecoveryTransport(manager.Paths, configured)
	if err != nil {
		return fail(5, "hub_unreachable", "Retry with the same idempotency key. "+safeMessage(err), "retry_later")
	}
	defer transport.Close()
	current := local.Snapshot()
	if receipt.Session == 0 {
		if current.PendingActivation == nil && current.PreviousSession != receipt.PreviousSession {
			return fail(7, "session_activation_ambiguous", "Collector session changed after recovery apply began.", "review_current_state")
		}
		request, err := local.PrepareActivation(receipt.BootID)
		if err != nil {
			return fail(8, "session_activation_failed", "Retry with the same idempotency key. "+safeMessage(err), "retry_later")
		}
		result, err := transport.Activate(ctx, request)
		if err != nil {
			return collectorRecoveryTransportError(err, fail)
		}
		receipt.Session, receipt.ActivatedMS = result.SessionGeneration, result.ActivatedMS
		// Persist the exact hub result before clearing pairing's pending CAS.
		// Either side of a crash can therefore finish without guessing a boot
		// or allocating a second session generation.
		if err := saveRecoveryCLIReceipts(manager.Paths.Collector, receipts); err != nil {
			return fail(8, "recovery_receipt_write_failed", "Retry with the same idempotency key. "+safeMessage(err), "retry_later")
		}
	}
	current = local.Snapshot()
	if current.PendingActivation != nil {
		result := protocol.SessionResult{ActivationRequestID: current.PendingActivation.ActivationRequestID, SecurityGeneration: grant.CurrentSecurityGeneration, SessionGeneration: receipt.Session, CollectorBootID: receipt.BootID, ActivatedMS: receipt.ActivatedMS, Current: true}
		if err := local.CompleteActivation(result); err != nil {
			return fail(7, "session_activation_ambiguous", safeMessage(err), "review_current_state")
		}
	} else if current.PreviousSession != receipt.Session {
		return fail(7, "session_activation_ambiguous", "Durable pairing state does not match the recovery session receipt.", "review_current_state")
	}
	codec, err := store.NewFrameCodecV1()
	if err != nil {
		return fail(8, "frame_codec_unavailable", safeMessage(err), "retry_later")
	}
	defer codec.Close()
	for receipt.Recovered+receipt.Duplicate < grant.MaxFrames {
		pending, err := queue.ReadRecovery(grant, int(protocol.MaxRecoverySegmentBytes), protocol.MaxRecoveryReplayFrames)
		if err != nil {
			return fail(3, "recovery_spool_refused", safeMessage(err), "repair_source")
		}
		if receipt.PendingACK != nil && !pendingMatchesRecoveryACK(pending, *receipt.PendingACK) {
			receipt.Recovered += receipt.PendingACK.Accepted
			receipt.Duplicate += receipt.PendingACK.Duplicate
			receipt.PendingACK = nil
			if err := saveRecoveryCLIReceipts(manager.Paths.Collector, receipts); err != nil {
				return fail(8, "recovery_receipt_write_failed", "Retry with the same idempotency key. "+safeMessage(err), "retry_later")
			}
		}
		if len(pending.Records) == 0 {
			break
		}
		replay, err := recoveryReplayFromPending(codec, grant, *receipt, pending)
		if err != nil {
			return fail(3, "recovery_frame_incompatible", safeMessage(err), "repair_source")
		}
		encoded, err := json.Marshal(replay)
		if err != nil || int64(len(encoded)) > protocol.MaxBatchBytes {
			return fail(3, "recovery_request_too_large", "A complete reviewed segment exceeds the bounded recovery wire request. Create a smaller reviewed preview.", "fix_input")
		}
		var ack protocol.RecoveryACK
		if receipt.PendingACK != nil {
			ack = *receipt.PendingACK
		} else {
			ack, err = transport.RecoveryReplay(ctx, replay)
			if err != nil {
				return collectorRecoveryTransportError(err, fail)
			}
			receipt.PendingACK = &ack
			if err := saveRecoveryCLIReceipts(manager.Paths.Collector, receipts); err != nil {
				return fail(8, "recovery_receipt_write_failed", "Retry with the same idempotency key. "+safeMessage(err), "retry_later")
			}
		}
		if err := queue.AckRecovery(pending, replay, ack); err != nil {
			return fail(8, "recovery_cursor_not_advanced", "Retry with the same idempotency key. "+safeMessage(err), "retry_later")
		}
		receipt.Recovered += ack.Accepted
		receipt.Duplicate += ack.Duplicate
		receipt.PendingACK = nil
		if err := saveRecoveryCLIReceipts(manager.Paths.Collector, receipts); err != nil {
			return fail(8, "recovery_receipt_write_failed", "Retry with the same idempotency key. "+safeMessage(err), "retry_later")
		}
	}
	receipt.Complete = receipt.Recovered+receipt.Duplicate == grant.MaxFrames
	receipt.ReportCreatedMS = manager.Clock.Now().UnixMilli()
	if err := saveRecoveryCLIReceipts(manager.Paths.Collector, receipts); err != nil {
		return fail(8, "recovery_receipt_write_failed", "Retry with the same idempotency key. "+safeMessage(err), "retry_later")
	}
	report := collectorRecoveryReport(grant, *receipt)
	if !receipt.Complete {
		if code := finishCollectorRecoveryReport(stdout, *jsonOutput, *reportOut, report, fail); code != 0 {
			return code
		}
		return 6
	}
	return finishCollectorRecoveryReport(stdout, *jsonOutput, *reportOut, report, fail)
}

func openCollectorRecoveryIdentity(manager *Manager, deploymentID, generation string) (collectorRecoveryConfig, *pairing.LocalState, error) {
	if err := config.ValidatePrivateFile(manager.Paths.CollectorConfig); err != nil {
		return collectorRecoveryConfig{}, nil, err
	}
	file, err := os.Open(manager.Paths.CollectorConfig)
	if err != nil {
		return collectorRecoveryConfig{}, nil, err
	}
	defer file.Close()
	var configured collectorRecoveryConfig
	if err := protocol.DecodeStrictJSON(file, 64<<10, &configured); err != nil || configured.SchemaVersion != domain.SchemaVersion || configured.DeploymentID != deploymentID || configured.DeploymentGeneration != generation || configured.InferenceEnabled {
		return collectorRecoveryConfig{}, nil, errors.New("collector configuration does not match reviewed recovery identity")
	}
	local, err := pairing.Open(manager.Paths.Collector, deploymentID, generation)
	return configured, local, err
}

func collectorRecoveryDefinitions(directory string, identity pairing.State) (protocol.RecoveryDefinitions, error) {
	sources := append([]protocol.InventorySource(nil), identity.InventorySources...)
	foundHost := false
	for index := range sources {
		sources[index].Active = false
		foundHost = foundHost || sources[index].SourceID == identity.HostSourceID
	}
	if !foundHost {
		sources = append(sources, protocol.InventorySource{SourceID: identity.HostSourceID, Kind: "host", CapabilityRevision: domain.RegistryRevision, Active: false})
	}
	targetState, err := pairing.ReadTargets(directory, identity.Generation)
	if err != nil {
		return protocol.RecoveryDefinitions{}, err
	}
	targets := make([]protocol.InventoryTarget, 0, len(targetState.Targets))
	for _, target := range targetState.Targets {
		targets = append(targets, protocol.InventoryTarget{TargetID: target.TargetID, AdapterID: target.Manifest.AdapterID, LocalSelectorSHA256: target.SelectorSHA256, AssociationState: "verified"})
	}
	models := make([]protocol.InventoryModel, 0, len(identity.Models))
	for _, model := range identity.Models {
		var digest *string
		if model.Digest != "" {
			value := model.Digest
			digest = &value
		}
		models = append(models, protocol.InventoryModel{ModelID: model.ID, TargetID: model.TargetID, Alias: model.Alias, Digest: digest, ReportedLoaded: false})
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].SourceID < sources[j].SourceID })
	sort.Slice(targets, func(i, j int) bool { return targets[i].TargetID < targets[j].TargetID })
	sort.Slice(models, func(i, j int) bool { return models[i].ModelID < models[j].ModelID })
	return protocol.RecoveryDefinitions{HistoricalOnly: true, Sources: sources, Targets: targets, Models: models}, nil
}

func newCollectorRecoveryTransport(paths config.Paths, configured collectorRecoveryConfig) (recoveryTransport, error) {
	if _, err := os.Lstat(paths.RemoteCollectorConfig); err == nil {
		return scheduler.NewRemoteTransport(paths, configured.DeploymentID, configured.DeploymentGeneration)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return scheduler.NewLocalTransport(paths.HubSocket)
}

func collectorRecoveryTransportError(err error, fail cliFailure) int {
	message := "Retry with the same idempotency key. " + safeMessage(err)
	var admission *scheduler.AdmissionError
	if errors.As(err, &admission) {
		switch admission.StatusCode {
		case 401, 403:
			return fail(4, "recovery_transport_unauthorized", message, "authenticate")
		case 409, 410:
			return fail(7, "recovery_transport_conflict", message, "review_current_state")
		case 429, 503:
			return fail(7, "recovery_transport_busy", message, "retry_later")
		case 422:
			return fail(3, "recovery_transport_incompatible", message, "repair_source")
		default:
			return fail(8, "recovery_transport_failed", message, "retry_later")
		}
	}
	var networkError net.Error
	if errors.As(err, &networkError) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || errors.Is(err, scheduler.ErrTransportClosed) {
		return fail(5, "hub_unreachable", message, "retry_later")
	}
	return fail(3, "recovery_transport_incompatible", message, "repair_source")
}

func recoveryReplayFromPending(codec *store.FrameCodecV1, grant protocol.RecoveryGrant, receipt recoveryApplyReceipt, pending spool.RecoveryPending) (protocol.RecoveryReplay, error) {
	frames := make([]protocol.RecoveryFrame, 0, len(pending.Records))
	digest := sha256.New()
	digest.Write([]byte(grant.GrantSHA256))
	for _, record := range pending.Records {
		frame, err := codec.Decode(record.Payload)
		if err != nil {
			return protocol.RecoveryReplay{}, err
		}
		payloadHash := sha256.Sum256(record.Payload)
		value := protocol.RecoveryFrame{OriginalSourceID: record.SourceID, OriginalSequence: int64(record.Sequence), OriginalObservedMS: record.ObservedMS, OriginalPayloadSHA256: hex.EncodeToString(payloadHash[:]), Frame: frame}
		if frame.SourceID != value.OriginalSourceID || frame.Sequence != value.OriginalSequence || frame.ObservedWallMS != value.OriginalObservedMS {
			return protocol.RecoveryReplay{}, errors.New("canonical frame identity conflicts with retained spool metadata")
		}
		if err := protocol.WriteRecoveryDescriptor(digest, protocol.RecoveryDescriptor{SourceID: value.OriginalSourceID, Sequence: value.OriginalSequence, ObservedMS: value.OriginalObservedMS, PayloadSHA256: value.OriginalPayloadSHA256}); err != nil {
			return protocol.RecoveryReplay{}, err
		}
		frames = append(frames, value)
	}
	requestID := recoveryUUID(digest.Sum(nil))
	replay := protocol.RecoveryReplay{Protocol: domain.ProtocolVersion, GrantID: grant.GrantID, GrantSHA256: grant.GrantSHA256, ReplayRequestID: requestID, AdmittingSecurityGeneration: grant.CurrentSecurityGeneration, AdmittingSessionGeneration: receipt.Session, AdmittingCollectorBootID: receipt.BootID, DeploymentID: grant.DeploymentID, HostID: grant.HostID, OriginalSecurityGeneration: grant.OriginalSecurityGeneration, OriginalCollectorBootID: grant.OriginalCollectorBootID, Frames: frames}
	var err error
	replay.ScopeSHA256, err = protocol.CanonicalRecoveryScopeHash(replay)
	if err != nil {
		return protocol.RecoveryReplay{}, err
	}
	return replay, replay.Validate()
}

func recoveryUUID(seed []byte) string {
	sum := sha256.Sum256(seed)
	sum[6] = (sum[6] & 0x0f) | 0x40
	sum[8] = (sum[8] & 0x3f) | 0x80
	value := hex.EncodeToString(sum[:16])
	return value[:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:32]
}

func pendingMatchesRecoveryACK(pending spool.RecoveryPending, ack protocol.RecoveryACK) bool {
	if len(pending.Records) != len(ack.Receipts) {
		return false
	}
	for index, record := range pending.Records {
		receipt := ack.Receipts[index]
		hash := sha256.Sum256(record.Payload)
		if record.BootID != receipt.OriginalCollectorBootID || record.SourceID != receipt.OriginalSourceID || int64(record.Sequence) != receipt.OriginalSequence || hex.EncodeToString(hash[:]) != receipt.OriginalPayloadSHA256 {
			return false
		}
	}
	return true
}

func recoveryManifestRange(manifest protocol.RecoveryManifest) (int64, int64) {
	first, last := manifest.Segments[0].FirstMS, manifest.Segments[0].LastMS
	for _, segment := range manifest.Segments[1:] {
		if segment.FirstMS < first {
			first = segment.FirstMS
		}
		if segment.LastMS > last {
			last = segment.LastMS
		}
	}
	return first, last
}

func manifestForPreviewReceipt(receipt recoveryPreviewReceipt) (protocol.RecoveryManifest, error) {
	if receipt.PendingManifest != nil {
		if receipt.ManifestPath != "" || receipt.ManifestFileSHA != "" || receipt.ManifestSHA != "" {
			return protocol.RecoveryManifest{}, errors.New("pending recovery preview receipt has compact file fields")
		}
		if err := receipt.PendingManifest.Validate(); err != nil {
			return protocol.RecoveryManifest{}, err
		}
		return *receipt.PendingManifest, nil
	}
	if !filepath.IsAbs(receipt.ManifestPath) || len(receipt.ManifestPath) > 1024 || !validSHA256(receipt.ManifestFileSHA) || !validSHA256(receipt.ManifestSHA) {
		return protocol.RecoveryManifest{}, errors.New("recovery preview receipt does not identify an exact private manifest")
	}
	data, err := readPrivateRecoveryFile(receipt.ManifestPath, protocol.MaxRecoveryManifestBytes)
	if err != nil {
		return protocol.RecoveryManifest{}, fmt.Errorf("exact recovery manifest file is missing or unreadable: %w", err)
	}
	fileHash := sha256.Sum256(data)
	if hex.EncodeToString(fileHash[:]) != receipt.ManifestFileSHA {
		return protocol.RecoveryManifest{}, errors.New("exact recovery manifest file hash differs from its receipt")
	}
	manifest, err := protocol.DecodeRecoveryManifest(bytes.NewReader(data))
	if err != nil {
		return protocol.RecoveryManifest{}, err
	}
	if manifest.ManifestSHA256 != receipt.ManifestSHA {
		return protocol.RecoveryManifest{}, errors.New("recovery manifest canonical hash differs from its receipt")
	}
	return manifest, nil
}

func collectorRecoveryReport(grant protocol.RecoveryGrant, receipt recoveryApplyReceipt) collectorRecoveryApplyReport {
	status := "partial"
	if receipt.Complete {
		status = "complete"
	}
	return collectorRecoveryApplyReport{
		SchemaVersion:               domain.SchemaVersion,
		Status:                      status,
		GrantID:                     grant.GrantID,
		GrantSHA256:                 grant.GrantSHA256,
		DeploymentID:                grant.DeploymentID,
		HostID:                      grant.HostID,
		OriginalSecurityGeneration:  grant.OriginalSecurityGeneration,
		OriginalCollectorBootID:     grant.OriginalCollectorBootID,
		AdmittingSecurityGeneration: grant.CurrentSecurityGeneration,
		AdmittingSessionGeneration:  receipt.Session,
		Recovered:                   receipt.Recovered,
		Duplicate:                   receipt.Duplicate,
		Remaining:                   grant.MaxFrames - receipt.Recovered - receipt.Duplicate,
		Complete:                    receipt.Complete,
		CreatedMS:                   receipt.ReportCreatedMS,
	}
}

func loadRecoveryCLIReceipts(directory string, now int64) (recoveryCLIReceipts, error) {
	path := filepath.Join(directory, "recovery-receipts.json")
	result := recoveryCLIReceipts{Version: 1, Previews: []recoveryPreviewReceipt{}, Applies: []recoveryApplyReceipt{}}
	if err := config.ValidatePrivateFile(path); errors.Is(err, os.ErrNotExist) {
		return result, nil
	} else if err != nil {
		return result, err
	}
	file, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer file.Close()
	if err := protocol.DecodeStrictRecoveryReceiptJSON(file, &result); err != nil || validateRecoveryCLIReceipts(result) != nil {
		return recoveryCLIReceipts{}, errors.New("collector recovery receipt file is invalid")
	}
	cutoff := now - int64(24*time.Hour/time.Millisecond)
	previews := result.Previews[:0]
	for _, receipt := range result.Previews {
		if receipt.AtMS >= cutoff {
			previews = append(previews, receipt)
		}
	}
	applies := result.Applies[:0]
	for _, receipt := range result.Applies {
		if receipt.AtMS >= cutoff {
			applies = append(applies, receipt)
		}
	}
	result.Previews, result.Applies = previews, applies
	return result, nil
}

func saveRecoveryCLIReceipts(directory string, receipts recoveryCLIReceipts) error {
	if err := validateRecoveryCLIReceipts(receipts); err != nil {
		return err
	}
	encoded, err := json.Marshal(receipts)
	if err != nil || int64(len(encoded)) > recoveryCLIReceiptBytes {
		return errors.New("collector recovery receipt capacity exceeded")
	}
	return config.WritePrivateFile(filepath.Join(directory, "recovery-receipts.json"), encoded)
}

func validateRecoveryCLIReceipts(receipts recoveryCLIReceipts) error {
	if receipts.Version != 1 || len(receipts.Previews) > recoveryCLIReceiptLimit || len(receipts.Applies) > recoveryCLIReceiptLimit {
		return errors.New("collector recovery receipt count is invalid")
	}
	keys := make(map[string]bool, len(receipts.Previews)+len(receipts.Applies))
	pendingPreviews, activeApplies := 0, 0
	for _, receipt := range receipts.Previews {
		if !validUUID(receipt.Key) || keys["preview/"+receipt.Key] || !validSHA256(receipt.ScopeSHA) || receipt.AtMS < 0 || receipt.AtMS > protocol.MaxUint53 {
			return errors.New("collector recovery preview receipt is invalid")
		}
		keys["preview/"+receipt.Key] = true
		if receipt.PendingManifest != nil {
			pendingPreviews++
			if receipt.ManifestPath != "" || receipt.ManifestFileSHA != "" || receipt.ManifestSHA != "" || receipt.PendingManifest.Validate() != nil {
				return errors.New("collector pending recovery preview receipt is invalid")
			}
		} else if !filepath.IsAbs(receipt.ManifestPath) || len(receipt.ManifestPath) > 1024 || !validSHA256(receipt.ManifestFileSHA) || !validSHA256(receipt.ManifestSHA) {
			return errors.New("collector compact recovery preview receipt is invalid")
		}
	}
	for _, receipt := range receipts.Applies {
		if !validUUID(receipt.Key) || keys["apply/"+receipt.Key] || !validSHA256(receipt.GrantFileSHA256) || !validSHA256(receipt.GrantSHA256) || !filepath.IsAbs(receipt.ReportPath) || len(receipt.ReportPath) > 1024 || receipt.AtMS < 0 || receipt.AtMS > protocol.MaxUint53 || !validUUID(receipt.BootID) || receipt.PreviousSession < 0 || receipt.PreviousSession > protocol.MaxUint53 || receipt.Session < 0 || receipt.Session > protocol.MaxUint53 || receipt.ActivatedMS < 0 || receipt.ActivatedMS > protocol.MaxUint53 || receipt.Recovered < 0 || receipt.Duplicate < 0 || receipt.Recovered+receipt.Duplicate > 1_000_000 || receipt.ReportCreatedMS < 0 || receipt.ReportCreatedMS > protocol.MaxUint53 {
			return errors.New("collector recovery apply receipt is invalid")
		}
		keys["apply/"+receipt.Key] = true
		if (receipt.Session == 0) != (receipt.ActivatedMS == 0) || receipt.ReportCreatedMS != 0 && receipt.Session == 0 || receipt.Complete && receipt.ReportCreatedMS == 0 || receipt.Complete && receipt.PendingACK != nil {
			return errors.New("collector recovery apply receipt state is invalid")
		}
		if receipt.ReportCreatedMS == 0 {
			activeApplies++
		}
		if receipt.PendingACK != nil {
			ack := receipt.PendingACK
			if !validUUID(ack.GrantID) || !validUUID(ack.ReplayRequestID) || !validSHA256(ack.GrantSHA256) || !validSHA256(ack.ScopeSHA256) || !ack.Durable || ack.Accepted < 0 || ack.Duplicate < 0 || ack.Rejected < 0 || ack.Accepted+ack.Duplicate+ack.Rejected != len(ack.Receipts) || len(ack.Receipts) < 1 || len(ack.Receipts) > protocol.MaxRecoveryReplayFrames {
				return errors.New("collector recovery pending acknowledgement is invalid")
			}
		}
	}
	if pendingPreviews > recoveryPendingPreviewLimit || activeApplies > recoveryActiveApplyReceiptLimit {
		return errors.New("collector recovery active receipt capacity exceeded")
	}
	return nil
}

func readPrivateRecoveryFile(path string, limit int64) ([]byte, error) {
	if err := config.ValidatePrivateFile(path); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("private recovery file exceeds bound")
	}
	return data, nil
}

func writeExactPrivateRecoveryFile(path string, data []byte, limit int64) error {
	if int64(len(data)) > limit || !filepath.IsAbs(path) {
		return errors.New("private recovery output exceeds bound")
	}
	if err := config.RejectSymlinkTree(filepath.Dir(path)); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		existing, readErr := readPrivateRecoveryFile(path, limit)
		if readErr != nil || !bytes.Equal(existing, data) {
			return errors.New("existing recovery output differs from exact retry")
		}
		return nil
	}
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func finishCollectorRecoveryReport(stdout io.Writer, jsonOutput bool, path string, report collectorRecoveryApplyReport, fail cliFailure) int {
	encoded, _ := json.Marshal(report)
	if err := writeExactPrivateRecoveryFile(path, append(encoded, '\n'), 64<<10); err != nil {
		return fail(8, "recovery_report_write_failed", "Retry with the same idempotency key. "+safeMessage(err), "retry_later")
	}
	message := fmt.Sprintf("Recovery %s: %d recovered, %d duplicate, %d remaining\nReport: %s", report.Status, report.Recovered, report.Duplicate, report.Remaining, path)
	writeCollectorRecoveryResult(stdout, jsonOutput, report, message)
	return 0
}

func writeCollectorRecoveryResult(stdout io.Writer, jsonOutput bool, value any, message string) {
	if jsonOutput {
		encoded, _ := json.Marshal(value)
		fmt.Fprintln(stdout, string(encoded))
		return
	}
	fmt.Fprintln(stdout, message)
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == string(bytes.ToLower([]byte(value)))
}
