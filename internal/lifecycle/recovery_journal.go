package lifecycle

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

const maxRecoveryJournalBytes = 64 << 10

type recoveryFile struct {
	Name           string `json:"name"`
	SHA256         string `json:"sha256"`
	PreviousSHA256 string `json:"previous_sha256,omitempty"`
}

// This journal lives outside the restorable database. No key or credential
// value belongs here; only fixed file names, hashes and recovery boundaries.
type recoveryJournal struct {
	SchemaVersion        string                 `json:"schema_version"`
	TransactionID        string                 `json:"transaction_id"`
	DeploymentID         string                 `json:"deployment_id"`
	PreviousGeneration   string                 `json:"previous_generation"`
	DeploymentGeneration string                 `json:"deployment_generation"`
	RecoveryPointMS      int64                  `json:"recovery_point_ms"`
	StartedMS            int64                  `json:"started_ms"`
	CompletedMS          *int64                 `json:"completed_ms"`
	State                string                 `json:"state"`
	ManifestSHA256       string                 `json:"manifest_sha256"`
	Files                []recoveryFile         `json:"files"`
	LaterChangesUnknown  bool                   `json:"later_changes_unknown"`
	RecoveryEvidence     store.RecoveryEvidence `json:"recovery_evidence"`
}

func recoveryDirectory(paths config.Paths) string {
	return filepath.Join(paths.Support, "recovery")
}

func readRecoveryJournal(paths config.Paths) (recoveryJournal, error) {
	var journal recoveryJournal
	path := filepath.Join(recoveryDirectory(paths), "active.json")
	if err := config.ValidatePrivateFile(path); err != nil {
		return journal, err
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() > maxRecoveryJournalBytes {
		return journal, errors.New("recovery journal size is invalid")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return journal, err
	}
	if err := protocol.DecodeStrictJSON(bytes.NewReader(data), maxRecoveryJournalBytes, &journal); err != nil {
		return journal, errors.New("recovery journal is invalid")
	}
	if journal.SchemaVersion != domain.SchemaVersion || !validUUID(journal.TransactionID) || !validUUID(journal.DeploymentID) || !validUUID(journal.DeploymentGeneration) || !validUUID(journal.PreviousGeneration) || journal.PreviousGeneration == journal.DeploymentGeneration || journal.RecoveryPointMS < 0 || journal.StartedMS < journal.RecoveryPointMS || len(journal.ManifestSHA256) != 64 || len(journal.Files) == 0 || len(journal.Files) > 16 {
		return journal, errors.New("recovery journal boundary is invalid")
	}
	if journal.State != "prepared" && journal.State != "committed" {
		return journal, errors.New("recovery journal state is ambiguous")
	}
	if (journal.State == "committed") != (journal.CompletedMS != nil) {
		return journal, errors.New("recovery activation marker is ambiguous")
	}
	if journal.CompletedMS != nil && *journal.CompletedMS < journal.StartedMS {
		return journal, errors.New("recovery completion precedes preparation")
	}
	allowed := restoreFilePaths(config.Paths{})
	seen := make(map[string]bool)
	for _, file := range journal.Files {
		if _, ok := allowed[file.Name]; !ok || seen[file.Name] {
			return journal, errors.New("recovery file names are invalid")
		}
		seen[file.Name] = true
		for _, digest := range []string{file.SHA256, file.PreviousSHA256} {
			if digest == "" {
				continue
			}
			decoded, err := hex.DecodeString(digest)
			if err != nil || len(decoded) != 32 {
				return journal, errors.New("recovery file hash is invalid")
			}
		}
	}
	return journal, nil
}

// The activation marker and database must agree. Losing the external journal
// after a restore does not silently remove its recovery boundary.
func ValidateRecoveryDeployment(paths config.Paths, state domain.DeploymentState) error {
	journal, err := readRecoveryJournal(paths)
	if errors.Is(err, os.ErrNotExist) && state.RecoveryPointMS == nil {
		return nil
	}
	if err != nil || journal.State != "committed" || journal.DeploymentID != state.DeploymentID || journal.DeploymentGeneration != state.DeploymentGeneration {
		return errors.New("database and external recovery journal disagree; offline recovery inspection is required")
	}
	return nil
}

// RequireRecoveryReady runs under an installation lease before opening the
// database. An interrupted replacement cannot accidentally start admission.
func RequireRecoveryReady(paths config.Paths) error {
	journal, err := readRecoveryJournal(paths)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("recovery journal cannot be verified; inspect offline recovery before starting the monitor")
	}
	if journal.State != "committed" {
		return errors.New("offline restore is incomplete; resume the recorded recovery transaction before starting the monitor")
	}
	return nil
}

func writeRecoveryJournal(paths config.Paths, journal recoveryJournal) error {
	return writeJSONFile(filepath.Join(recoveryDirectory(paths), "active.json"), journal)
}
