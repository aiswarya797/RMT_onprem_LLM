package lifecycle

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
)

// Inspection reads only the external journal. It remains available when a
// prepared activation intentionally prevents opening the product database.
type RecoveryInspection struct {
	SchemaVersion        string   `json:"schema_version"`
	State                string   `json:"state"`
	JournalPath          string   `json:"journal_path"`
	TransactionID        string   `json:"transaction_id,omitempty"`
	DeploymentID         string   `json:"deployment_id,omitempty"`
	PreviousGeneration   string   `json:"previous_generation,omitempty"`
	DeploymentGeneration string   `json:"deployment_generation,omitempty"`
	RecoveryPointMS      *int64   `json:"recovery_point_ms"`
	ResumeArgv           []string `json:"resume_argv"`
	LaterChangesUnknown  bool     `json:"later_changes_unknown"`
}

func runRecoveryInspectCLI(args []string, stdout io.Writer, manager *Manager, jsonOutput bool, fail cliFailure) int {
	if len(args) == 0 || args[0] != "inspect" || !onlyFlags(args[1:], "--json") {
		return fail(2, "invalid_command", "Use: llm-monitor recovery inspect [--json]", "fix_input")
	}
	result := RecoveryInspection{SchemaVersion: domain.SchemaVersion, State: "no_journal", JournalPath: filepath.Join(recoveryDirectory(manager.Paths), "active.json"), ResumeArgv: []string{}, LaterChangesUnknown: true}
	journal, err := readRecoveryJournal(manager.Paths)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fail(8, "recovery_journal_invalid", "The external recovery journal could not be verified. Preserve the installation and recovery directory; no automatic resume is safe.", "use_local_owner_command")
	}
	if err == nil {
		result.State, result.TransactionID, result.DeploymentID = journal.State, journal.TransactionID, journal.DeploymentID
		result.PreviousGeneration, result.DeploymentGeneration = journal.PreviousGeneration, journal.DeploymentGeneration
		result.RecoveryPointMS = &journal.RecoveryPointMS
		if journal.State == "prepared" {
			result.ResumeArgv = []string{"llm-monitor", "--installation-root", manager.Paths.Home, "--runtime-dir", manager.Paths.Run, "restore", "--resume-transaction", journal.TransactionID, "--confirm-deployment", journal.DeploymentID, "--deployment-generation", journal.PreviousGeneration, "--confirm-recovery-point-ms", strconv.FormatInt(journal.RecoveryPointMS, 10)}
		}
	}
	if jsonOutput {
		_ = protocol.WriteJSON(stdout, result)
	} else {
		fmt.Fprintf(stdout, "Recovery journal: %s\nState: %s. Later changes may be missing.\n", result.JournalPath, result.State)
		if result.RecoveryPointMS != nil {
			fmt.Fprintf(stdout, "Transaction: %s\nRecovery point: %d ms\n", result.TransactionID, *result.RecoveryPointMS)
		}
		if len(result.ResumeArgv) > 0 {
			quoted := make([]string, len(result.ResumeArgv))
			for i, value := range result.ResumeArgv {
				quoted[i] = "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
			}
			fmt.Fprintf(stdout, "Review this recovery point, then resume the preserved transaction:\n%s\n", strings.Join(quoted, " "))
		} else if result.State == "no_journal" {
			fmt.Fprintln(stdout, "No verified recovery transaction is available. This does not establish that the database is safe to start or that no recovery record was lost.")
		}
	}
	return 0
}
