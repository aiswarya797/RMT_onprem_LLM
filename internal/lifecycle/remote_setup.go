package lifecycle

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"time"

	"rmt.local/monitor/internal/collector/pairing"
	"rmt.local/monitor/internal/collector/scheduler"
	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/enrollment"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

type CollectorSetupResult struct {
	SchemaVersion        string `json:"schema_version"`
	Status               string `json:"status"`
	DeploymentID         string `json:"deployment_id"`
	DeploymentGeneration string `json:"deployment_generation"`
	HostID               string `json:"host_id"`
	CertificateExpiresMS int64  `json:"certificate_expires_ms"`
	CollectorState       string `json:"collector_state"`
}

type pendingRemoteEnrollment struct {
	SchemaVersion          string `json:"schema_version"`
	State                  string `json:"state"`
	DeploymentID           string `json:"deployment_id"`
	HostID                 string `json:"host_id"`
	InstallationID         string `json:"installation_id"`
	HubURL                 string `json:"hub_url"`
	HubCAFingerprintSHA256 string `json:"hub_ca_fingerprint_sha256"`
	CSRPEM                 string `json:"csr_pem"`
	IdempotencyKey         string `json:"idempotency_key"`
}

type remoteReEnrollmentJournal struct {
	SchemaVersion         string                     `json:"schema_version"`
	State                 string                     `json:"state"`
	DeploymentID          string                     `json:"deployment_id"`
	HostID                string                     `json:"host_id"`
	InstallationID        string                     `json:"installation_id"`
	PreviousGeneration    string                     `json:"previous_generation"`
	HubURL                string                     `json:"hub_url"`
	PreviousCAFingerprint string                     `json:"previous_ca_fingerprint_sha256"`
	NextCAFingerprint     string                     `json:"next_ca_fingerprint_sha256"`
	CSRPEM                string                     `json:"csr_pem"`
	IdempotencyKey        string                     `json:"idempotency_key"`
	StartedMS             int64                      `json:"started_ms"`
	Result                *enrollment.ExchangeResult `json:"result"`
}

func (m *Manager) SetupCollector(ctx context.Context, enrollmentPath string, start bool) (CollectorSetupResult, error) {
	file, err := decodeEnrollmentFile(enrollmentPath)
	if err != nil {
		return CollectorSetupResult{}, err
	}
	return m.setupCollectorFile(ctx, file, start, false)
}

// SetupCollectorPairing bootstraps the reviewed CA and enrollment identity in
// memory from the one-use pairing code. The token is never written as an
// enrollment file; the resulting collector stores only its pinned credential.
func (m *Manager) SetupCollectorPairing(ctx context.Context, hubURL, token string, start bool) (CollectorSetupResult, error) {
	file, err := enrollment.FetchBootstrapFile(ctx, hubURL, token)
	if err != nil {
		return CollectorSetupResult{}, err
	}
	return m.setupCollectorFile(ctx, file, start, false)
}

// ReEnrollCollector is an explicit trust-reset operation. It is deliberately
// separate from ordinary setup so a reviewed enrollment file can never
// overwrite an existing pairing by accident.
func (m *Manager) ReEnrollCollector(ctx context.Context, enrollmentPath string, start bool) (CollectorSetupResult, error) {
	file, err := readEnrollmentFile(enrollmentPath, m.Clock.Now())
	if err != nil {
		return CollectorSetupResult{}, err
	}
	return m.setupCollectorFile(ctx, file, start, true)
}

func (m *Manager) setupCollectorFile(ctx context.Context, file enrollment.File, start, reEnroll bool) (CollectorSetupResult, error) {
	var err error
	if reEnroll {
		return m.reEnrollCollector(ctx, file, start)
	}
	if existing, found, err := m.existingCollectorSetup(ctx, file, start); found || err != nil {
		return existing, err
	}
	if err := enrollment.ValidateFile(file, m.Clock.Now()); err != nil {
		return CollectorSetupResult{}, err
	}
	for _, directory := range []string{m.Paths.Support, m.Paths.Bin, m.Paths.Collector, m.Paths.Logs, m.Paths.Run} {
		if err := config.EnsurePrivateDir(directory); err != nil {
			return CollectorSetupResult{}, err
		}
	}
	attempt, key, err := m.loadOrCreateRemoteAttempt(file)
	if err != nil {
		return CollectorSetupResult{}, err
	}
	client, err := enrollment.NewClient(file, m.Clock.Now())
	if err != nil {
		return CollectorSetupResult{}, err
	}
	defer client.Close()
	result, err := client.Exchange(ctx, file, attempt.InstallationID, enrollment.GeneratedKey{PrivateKeyPEM: key, CSRPEM: []byte(attempt.CSRPEM)}, attempt.IdempotencyKey)
	if err != nil {
		return CollectorSetupResult{}, err
	}
	if err := config.WritePrivateFile(m.Paths.CollectorCert, []byte(result.CertificatePEM)); err != nil {
		return CollectorSetupResult{}, err
	}
	if err := config.WritePrivateFile(m.Paths.CollectorCA, []byte(file.HubCACertificatePEM)); err != nil {
		return CollectorSetupResult{}, err
	}
	if _, err := pairing.CreateEnrolled(m.Paths.Collector, result.DeploymentID, result.SecurityGeneration, attempt.InstallationID, result.HostID); err != nil {
		return CollectorSetupResult{}, err
	}
	if _, err := ensureDefaultOllamaTarget(m.Paths.Collector, result.SecurityGeneration); err != nil {
		return CollectorSetupResult{}, err
	}
	targetConfigured, err := hasActiveTarget(m.Paths.Collector, result.SecurityGeneration)
	if err != nil {
		return CollectorSetupResult{}, err
	}
	collectorConfig := map[string]any{"schema_version": domain.SchemaVersion, "deployment_id": result.DeploymentID, "deployment_generation": result.SecurityGeneration, "owner_socket": m.Paths.CollectorSocket, "target_configured": targetConfigured, "collection_enabled": true, "inference_enabled": false}
	if err := writeJSONFile(m.Paths.CollectorConfig, collectorConfig); err != nil {
		return CollectorSetupResult{}, err
	}
	remoteConfig := enrollment.RemoteConfig{SchemaVersion: domain.SchemaVersion, DeploymentID: result.DeploymentID, DeploymentGeneration: result.SecurityGeneration, HostID: result.HostID, InstallationID: attempt.InstallationID, HubURL: file.HubURL, HubCAFingerprintSHA256: result.HubCAFingerprintSHA256, CertificateExpiresMS: result.ExpiresMS}
	if err := writeJSONFile(m.Paths.RemoteCollectorConfig, remoteConfig); err != nil {
		return CollectorSetupResult{}, err
	}
	collectorArgs := m.CollectorProgramArguments()[1:]
	if err := config.WritePrivateFile(m.Paths.CollectorPlist, []byte(m.plist(CollectorLabel, m.CollectorBinary, collectorArgs, "collector"))); err != nil {
		return CollectorSetupResult{}, err
	}
	state := "not_started"
	if start {
		state, err = m.ensureLoaded(ctx, CollectorLabel, m.Paths.CollectorPlist)
		if err != nil {
			return CollectorSetupResult{}, err
		}
	}
	return CollectorSetupResult{SchemaVersion: domain.SchemaVersion, Status: "configured", DeploymentID: result.DeploymentID, DeploymentGeneration: result.SecurityGeneration, HostID: result.HostID, CertificateExpiresMS: result.ExpiresMS, CollectorState: state}, nil
}

func (m *Manager) reEnrollCollector(ctx context.Context, file enrollment.File, start bool) (CollectorSetupResult, error) {
	remote, err := readRemoteCollectorConfig(m.Paths.RemoteCollectorConfig)
	if err != nil {
		return CollectorSetupResult{}, errors.New("restored-host re-enrollment requires an existing configured collector")
	}
	if remote.DeploymentID != file.DeploymentID || remote.HostID != file.HostID || remote.HubURL != file.HubURL {
		return CollectorSetupResult{}, errors.New("reviewed re-enrollment file does not name the retained collector identity")
	}
	if remote.HubCAFingerprintSHA256 == file.HubCAFingerprintSHA256 {
		if _, err := pairing.Open(m.Paths.Collector, remote.DeploymentID, remote.DeploymentGeneration); err != nil {
			return CollectorSetupResult{}, errors.New("configured collector pairing requires explicit recovery")
		}
		transport, err := scheduler.NewRemoteTransport(m.Paths, remote.DeploymentID, remote.DeploymentGeneration)
		if err != nil {
			return CollectorSetupResult{}, errors.New("configured collector credential requires explicit recovery")
		}
		transport.Close()
		if err := removeReEnrollmentArtifacts(m.Paths); err != nil {
			return CollectorSetupResult{}, err
		}
		state := "not_started"
		if start {
			state, err = m.ensureLoaded(ctx, CollectorLabel, m.Paths.CollectorPlist)
			if err != nil {
				return CollectorSetupResult{}, err
			}
		}
		return CollectorSetupResult{SchemaVersion: domain.SchemaVersion, Status: "already_reenrolled", DeploymentID: remote.DeploymentID, DeploymentGeneration: remote.DeploymentGeneration, HostID: remote.HostID, CertificateExpiresMS: remote.CertificateExpiresMS, CollectorState: state}, nil
	}
	retained, err := pairing.ReadRetained(m.Paths.Collector, file.DeploymentID, file.HostID)
	if err != nil || retained.InstallationID != remote.InstallationID {
		return CollectorSetupResult{}, errors.New("retained pairing does not match the configured collector identity")
	}
	journal, stagedKey, retry, err := m.loadOrCreateReEnrollmentAttempt(file, remote, retained)
	if err != nil {
		return CollectorSetupResult{}, err
	}
	if journal.Result == nil {
		var client *enrollment.Client
		if retry {
			client, err = enrollment.NewRetryClient(file, m.Clock.Now())
		} else {
			client, err = enrollment.NewClient(file, m.Clock.Now())
		}
		if err != nil {
			return CollectorSetupResult{}, err
		}
		result, exchangeErr := client.Exchange(ctx, file, journal.InstallationID, enrollment.GeneratedKey{PrivateKeyPEM: stagedKey, CSRPEM: []byte(journal.CSRPEM)}, journal.IdempotencyKey)
		client.Close()
		if exchangeErr != nil {
			return CollectorSetupResult{}, exchangeErr
		}
		if result.SecurityGeneration == journal.PreviousGeneration {
			return CollectorSetupResult{}, errors.New("re-enrollment did not advance the trust generation")
		}
		journal.State = "issued"
		journal.Result = &result
		if err := writeJSONFile(m.Paths.CollectorReEnrollment, journal); err != nil {
			return CollectorSetupResult{}, err
		}
	}
	_, err = m.stopCollectorForReEnrollment(ctx)
	if err != nil {
		return CollectorSetupResult{}, err
	}
	if err := m.installReEnrollment(journal, stagedKey, file); err != nil {
		return CollectorSetupResult{}, err
	}
	if err := removeReEnrollmentArtifacts(m.Paths); err != nil {
		return CollectorSetupResult{}, err
	}
	state := "not_started"
	if start {
		state, err = m.ensureLoaded(ctx, CollectorLabel, m.Paths.CollectorPlist)
		if err != nil {
			return CollectorSetupResult{}, err
		}
	}
	result := journal.Result
	return CollectorSetupResult{SchemaVersion: domain.SchemaVersion, Status: "reenrolled", DeploymentID: result.DeploymentID, DeploymentGeneration: result.SecurityGeneration, HostID: result.HostID, CertificateExpiresMS: result.ExpiresMS, CollectorState: state}, nil
}

func readRemoteCollectorConfig(path string) (enrollment.RemoteConfig, error) {
	var remote enrollment.RemoteConfig
	if err := config.ValidatePrivateFile(path); err != nil {
		return remote, err
	}
	file, err := os.Open(path)
	if err != nil {
		return remote, err
	}
	defer file.Close()
	if err := protocol.DecodeStrictJSON(io.LimitReader(file, (64<<10)+1), 64<<10, &remote); err != nil {
		return remote, err
	}
	if remote.SchemaVersion != domain.SchemaVersion || remote.DeploymentID == "" || remote.DeploymentGeneration == "" || remote.HostID == "" || remote.InstallationID == "" || remote.HubURL == "" || remote.HubCAFingerprintSHA256 == "" {
		return remote, errors.New("remote collector configuration is invalid")
	}
	return remote, nil
}

func (m *Manager) loadOrCreateReEnrollmentAttempt(file enrollment.File, remote enrollment.RemoteConfig, retained pairing.State) (remoteReEnrollmentJournal, []byte, bool, error) {
	var journal remoteReEnrollmentJournal
	if err := config.ValidatePrivateFile(m.Paths.CollectorReEnrollment); err == nil {
		data, readErr := os.ReadFile(m.Paths.CollectorReEnrollment)
		if readErr != nil || len(data) > 64<<10 || protocol.DecodeStrictJSON(bytes.NewReader(data), 64<<10, &journal) != nil {
			return journal, nil, true, errors.New("re-enrollment journal requires recovery")
		}
		if err := validateReEnrollmentJournal(journal, file, remote, retained); err != nil {
			return journal, nil, true, err
		}
		if err := config.ValidatePrivateFile(m.Paths.CollectorNextKey); err != nil {
			return journal, nil, true, errors.New("staged re-enrollment key requires recovery")
		}
		key, err := os.ReadFile(m.Paths.CollectorNextKey)
		if err != nil || len(key) > 64<<10 {
			return journal, nil, true, errors.New("staged re-enrollment key requires recovery")
		}
		return journal, key, true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return journal, nil, false, err
	}
	if retained.Generation != remote.DeploymentGeneration {
		return journal, nil, false, errors.New("retained pairing generation changed without a re-enrollment journal")
	}
	if err := enrollment.ValidateFile(file, m.Clock.Now()); err != nil {
		return journal, nil, false, err
	}
	if _, err := os.Lstat(m.Paths.CollectorNextKey); err == nil {
		return journal, nil, false, errors.New("orphaned staged re-enrollment key requires recovery")
	} else if !errors.Is(err, os.ErrNotExist) {
		return journal, nil, false, err
	}
	idempotencyKey, err := domain.NewUUID()
	if err != nil {
		return journal, nil, false, err
	}
	generated, err := enrollment.GenerateKeyAndCSR(file.HostID)
	if err != nil {
		return journal, nil, false, err
	}
	journal = remoteReEnrollmentJournal{
		SchemaVersion: domain.SchemaVersion, State: "prepared", DeploymentID: file.DeploymentID, HostID: file.HostID,
		InstallationID: retained.InstallationID, PreviousGeneration: retained.Generation, HubURL: file.HubURL,
		PreviousCAFingerprint: remote.HubCAFingerprintSHA256, NextCAFingerprint: file.HubCAFingerprintSHA256,
		CSRPEM: string(generated.CSRPEM), IdempotencyKey: idempotencyKey, StartedMS: m.Clock.Now().UnixMilli(),
	}
	if err := config.WritePrivateFile(m.Paths.CollectorNextKey, generated.PrivateKeyPEM); err != nil {
		return journal, nil, false, err
	}
	if err := writeJSONFile(m.Paths.CollectorReEnrollment, journal); err != nil {
		_ = os.Remove(m.Paths.CollectorNextKey)
		return journal, nil, false, err
	}
	return journal, generated.PrivateKeyPEM, false, nil
}

func validateReEnrollmentJournal(journal remoteReEnrollmentJournal, file enrollment.File, remote enrollment.RemoteConfig, retained pairing.State) error {
	if journal.SchemaVersion != domain.SchemaVersion || (journal.State != "prepared" && journal.State != "issued") || journal.DeploymentID != file.DeploymentID || journal.HostID != file.HostID || journal.InstallationID != retained.InstallationID || journal.HubURL != file.HubURL || journal.PreviousCAFingerprint != remote.HubCAFingerprintSHA256 || journal.NextCAFingerprint != file.HubCAFingerprintSHA256 || len(journal.CSRPEM) < 64 || len(journal.CSRPEM) > 16384 || len(journal.IdempotencyKey) < 16 || len(journal.IdempotencyKey) > 128 || journal.StartedMS < 0 {
		return errors.New("re-enrollment journal identity changed")
	}
	if (journal.State == "issued") != (journal.Result != nil) {
		return errors.New("re-enrollment journal completion is ambiguous")
	}
	if journal.Result != nil && (journal.Result.DeploymentID != file.DeploymentID || journal.Result.HostID != file.HostID || journal.Result.SecurityGeneration == journal.PreviousGeneration || journal.Result.HubCAFingerprintSHA256 != file.HubCAFingerprintSHA256) {
		return errors.New("re-enrollment result conflicts with reviewed identity")
	}
	if retained.Generation != journal.PreviousGeneration && (journal.Result == nil || retained.Generation != journal.Result.SecurityGeneration) {
		return errors.New("retained pairing generation is outside the staged re-enrollment transition")
	}
	return nil
}

func (m *Manager) stopCollectorForReEnrollment(ctx context.Context) (bool, error) {
	presence, err := m.serviceState(ctx, CollectorLabel)
	if err != nil || presence == ServicePresenceUnknown {
		return false, errors.New("collector service state is unknown; re-enrollment did not modify active credentials")
	}
	if presence == ServicePresenceAbsent {
		return false, nil
	}
	target := "gui/" + strconv.Itoa(os.Getuid()) + "/" + CollectorLabel
	_, _ = m.Runner.Run(ctx, "launchctl", "bootout", target)
	after, afterErr := m.Runner.ServiceState(ctx, target)
	if afterErr != nil || after != ServicePresenceAbsent {
		return false, errors.New("collector could not be stopped for re-enrollment")
	}
	return true, nil
}

func (m *Manager) installReEnrollment(journal remoteReEnrollmentJournal, stagedKey []byte, file enrollment.File) error {
	if journal.Result == nil || journal.State != "issued" {
		return errors.New("re-enrollment has no durable certificate result")
	}
	result := *journal.Result
	if err := config.WritePrivateFile(m.Paths.CollectorKey, stagedKey); err != nil {
		return err
	}
	if err := config.WritePrivateFile(m.Paths.CollectorCert, []byte(result.CertificatePEM)); err != nil {
		return err
	}
	if err := config.WritePrivateFile(m.Paths.CollectorCA, []byte(file.HubCACertificatePEM)); err != nil {
		return err
	}
	if _, err := pairing.ReEnroll(m.Paths.Collector, journal.DeploymentID, journal.PreviousGeneration, result.SecurityGeneration, journal.InstallationID, journal.HostID); err != nil {
		return err
	}
	if _, err := ensureDefaultOllamaTarget(m.Paths.Collector, result.SecurityGeneration); err != nil {
		return err
	}
	targets, err := pairing.ReadTargets(m.Paths.Collector, result.SecurityGeneration)
	if err != nil {
		return err
	}
	targetConfigured := false
	for _, target := range targets.Targets {
		if !target.Retired {
			targetConfigured = true
		}
	}
	collectorConfig := map[string]any{"schema_version": domain.SchemaVersion, "deployment_id": result.DeploymentID, "deployment_generation": result.SecurityGeneration, "owner_socket": m.Paths.CollectorSocket, "target_configured": targetConfigured, "collection_enabled": true, "inference_enabled": false}
	if err := writeJSONFile(m.Paths.CollectorConfig, collectorConfig); err != nil {
		return err
	}
	collectorArgs := m.CollectorProgramArguments()[1:]
	if err := config.WritePrivateFile(m.Paths.CollectorPlist, []byte(m.plist(CollectorLabel, m.CollectorBinary, collectorArgs, "collector"))); err != nil {
		return err
	}
	remote := enrollment.RemoteConfig{SchemaVersion: domain.SchemaVersion, DeploymentID: result.DeploymentID, DeploymentGeneration: result.SecurityGeneration, HostID: result.HostID, InstallationID: journal.InstallationID, HubURL: file.HubURL, HubCAFingerprintSHA256: result.HubCAFingerprintSHA256, CertificateExpiresMS: result.ExpiresMS}
	return writeJSONFile(m.Paths.RemoteCollectorConfig, remote)
}

func removeReEnrollmentArtifacts(paths config.Paths) error {
	for _, path := range []string{paths.CollectorReEnrollment, paths.CollectorNextKey} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	directory, err := os.Open(paths.Collector)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func readEnrollmentFile(path string, now time.Time) (enrollment.File, error) {
	result, err := decodeEnrollmentFile(path)
	if err != nil {
		return result, err
	}
	if err := enrollment.ValidateFile(result, now); err != nil {
		return result, err
	}
	return result, nil
}

func decodeEnrollmentFile(path string) (enrollment.File, error) {
	var result enrollment.File
	if path == "" {
		return result, errors.New("enrollment file is required")
	}
	if err := config.ValidatePrivateFile(path); err != nil {
		return result, err
	}
	file, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return result, errors.New("enrollment file exceeds limit")
	}
	if err := protocol.DecodeStrictJSON(bytes.NewReader(data), 64<<10, &result); err != nil {
		return result, err
	}
	return result, nil
}

func (m *Manager) existingCollectorSetup(ctx context.Context, file enrollment.File, start bool) (CollectorSetupResult, bool, error) {
	if err := config.ValidatePrivateFile(m.Paths.RemoteCollectorConfig); errors.Is(err, os.ErrNotExist) {
		return CollectorSetupResult{}, false, nil
	} else if err != nil {
		return CollectorSetupResult{}, true, err
	}
	data, err := os.ReadFile(m.Paths.RemoteCollectorConfig)
	if err != nil || len(data) > 64<<10 {
		return CollectorSetupResult{}, true, errors.New("remote collector configuration requires recovery")
	}
	var remote enrollment.RemoteConfig
	if err := protocol.DecodeStrictJSON(bytes.NewReader(data), 64<<10, &remote); err != nil {
		var pending pendingRemoteEnrollment
		if pendingErr := protocol.DecodeStrictJSON(bytes.NewReader(data), 64<<10, &pending); pendingErr == nil && pending.SchemaVersion == domain.SchemaVersion && pending.State == "pending" {
			return CollectorSetupResult{}, false, nil
		}
		return CollectorSetupResult{}, true, errors.New("remote collector configuration requires recovery")
	}
	if remote.SchemaVersion != domain.SchemaVersion || remote.DeploymentID != file.DeploymentID || remote.HostID != file.HostID || remote.HubURL != file.HubURL || remote.HubCAFingerprintSHA256 != file.HubCAFingerprintSHA256 {
		return CollectorSetupResult{}, true, errors.New("configured remote collector identity differs from enrollment file")
	}
	transport, err := scheduler.NewRemoteTransport(m.Paths, remote.DeploymentID, remote.DeploymentGeneration)
	if err != nil {
		return CollectorSetupResult{}, true, errors.New("configured remote collector credential requires recovery")
	}
	transport.Close()
	if _, err := pairing.Open(m.Paths.Collector, remote.DeploymentID, remote.DeploymentGeneration); err != nil {
		return CollectorSetupResult{}, true, errors.New("configured remote collector pairing requires recovery")
	}
	if _, err := ensureDefaultOllamaTarget(m.Paths.Collector, remote.DeploymentGeneration); err != nil {
		return CollectorSetupResult{}, true, err
	}
	state := "not_started"
	if start {
		state, err = m.ensureLoaded(ctx, CollectorLabel, m.Paths.CollectorPlist)
		if err != nil {
			return CollectorSetupResult{}, true, err
		}
	}
	return CollectorSetupResult{SchemaVersion: domain.SchemaVersion, Status: "already_configured", DeploymentID: remote.DeploymentID, DeploymentGeneration: remote.DeploymentGeneration, HostID: remote.HostID, CertificateExpiresMS: remote.CertificateExpiresMS, CollectorState: state}, true, nil
}

func (m *Manager) loadOrCreateRemoteAttempt(file enrollment.File) (pendingRemoteEnrollment, []byte, error) {
	var attempt pendingRemoteEnrollment
	if err := config.ValidatePrivateFile(m.Paths.RemoteCollectorConfig); err == nil {
		data, readErr := os.ReadFile(m.Paths.RemoteCollectorConfig)
		if readErr != nil || len(data) > 64<<10 || protocol.DecodeStrictJSON(bytes.NewReader(data), 64<<10, &attempt) != nil {
			return attempt, nil, errors.New("pending remote enrollment requires recovery")
		}
		if attempt.SchemaVersion != domain.SchemaVersion || attempt.State != "pending" || attempt.DeploymentID != file.DeploymentID || attempt.HostID != file.HostID || attempt.HubURL != file.HubURL || attempt.HubCAFingerprintSHA256 != file.HubCAFingerprintSHA256 {
			return attempt, nil, errors.New("pending remote enrollment identity changed")
		}
		if err := config.ValidatePrivateFile(m.Paths.CollectorKey); err != nil {
			return attempt, nil, errors.New("pending remote enrollment key requires recovery")
		}
		key, err := os.ReadFile(m.Paths.CollectorKey)
		return attempt, key, err
	} else if !errors.Is(err, os.ErrNotExist) {
		return attempt, nil, err
	}
	if _, err := os.Lstat(m.Paths.CollectorKey); err == nil {
		return attempt, nil, errors.New("orphaned remote collector key requires recovery")
	} else if !errors.Is(err, os.ErrNotExist) {
		return attempt, nil, err
	}
	installationID, err := domain.NewUUID()
	if err != nil {
		return attempt, nil, err
	}
	idempotencyKey, err := domain.NewUUID()
	if err != nil {
		return attempt, nil, err
	}
	generated, err := enrollment.GenerateKeyAndCSR(file.HostID)
	if err != nil {
		return attempt, nil, err
	}
	attempt = pendingRemoteEnrollment{SchemaVersion: domain.SchemaVersion, State: "pending", DeploymentID: file.DeploymentID, HostID: file.HostID, InstallationID: installationID, HubURL: file.HubURL, HubCAFingerprintSHA256: file.HubCAFingerprintSHA256, CSRPEM: string(generated.CSRPEM), IdempotencyKey: idempotencyKey}
	if err := config.WritePrivateFile(m.Paths.CollectorKey, generated.PrivateKeyPEM); err != nil {
		return attempt, nil, err
	}
	if err := writeJSONFile(m.Paths.RemoteCollectorConfig, attempt); err != nil {
		return attempt, nil, err
	}
	return attempt, generated.PrivateKeyPEM, nil
}

func (m *Manager) targetConfigurationState(ctx context.Context) (domain.DeploymentState, error) {
	if local, err := store.OpenReadOnly(m.Paths.Database, m.Clock); err == nil {
		defer local.Close()
		return local.DeploymentState(ctx)
	}
	if err := config.ValidatePrivateFile(m.Paths.RemoteCollectorConfig); err != nil {
		return domain.DeploymentState{}, err
	}
	data, err := os.ReadFile(m.Paths.RemoteCollectorConfig)
	if err != nil || len(data) > 64<<10 {
		return domain.DeploymentState{}, errors.New("remote collector configuration unavailable")
	}
	var remote enrollment.RemoteConfig
	if err := protocol.DecodeStrictJSON(bytes.NewReader(data), 64<<10, &remote); err != nil {
		return domain.DeploymentState{}, err
	}
	if remote.SchemaVersion != domain.SchemaVersion || remote.DeploymentID == "" || remote.DeploymentGeneration == "" || remote.HostID == "" || remote.CertificateExpiresMS <= m.Clock.Now().UnixMilli() {
		return domain.DeploymentState{}, errors.New("remote collector configuration is invalid")
	}
	if _, err := pairing.Open(m.Paths.Collector, remote.DeploymentID, remote.DeploymentGeneration); err != nil {
		return domain.DeploymentState{}, err
	}
	return domain.DeploymentState{SchemaVersion: domain.SchemaVersion, DeploymentID: remote.DeploymentID, DeploymentGeneration: remote.DeploymentGeneration, RecoveryState: "normal", MutationsAllowed: true}, nil
}
