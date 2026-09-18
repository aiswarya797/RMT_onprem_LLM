package lifecycle

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/enrollment"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/query"
	"rmt.local/monitor/internal/store"
)

type hostEnrollmentCLIResult struct {
	SchemaVersion  string `json:"schema_version"`
	Status         string `json:"status"`
	HostID         string `json:"host_id"`
	EnrollmentFile string `json:"enrollment_file"`
	ExpiresMS      int64  `json:"expires_ms"`
}

type enrollmentCreateRequestCLI struct {
	HostDisplayName   string  `json:"host_display_name"`
	ExpiresInSeconds  int     `json:"expires_in_seconds"`
	ReplacementHostID *string `json:"replacement_host_id,omitempty"`
}

func runHostsCLI(ctx context.Context, args []string, stdout, stderr io.Writer, manager *Manager, fail cliFailure) int {
	if len(args) < 1 || (args[0] != "enroll" && args[0] != "revoke") {
		return fail(2, "invalid_command", "Use: llm-monitor hosts enroll|revoke", "fix_input")
	}
	fs := flag.NewFlagSet("hosts "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	tokenFile := fs.String("token-file", "", "private 0600 administrator API token")
	outputFile := fs.String("output-enrollment-file", "", "private 0600 enrollment file")
	displayName := fs.String("name", "", "remote Mac display name")
	hostID := fs.String("host", "", "host ID")
	generation := fs.String("deployment-generation", "", "reviewed deployment generation")
	idempotencyKey := fs.String("idempotency-key", "", "retry identity")
	jsonOutput := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || *tokenFile == "" || *generation == "" || len(*idempotencyKey) < 16 || len(*idempotencyKey) > 128 {
		return fail(2, "invalid_input", "Host change requires --token-file, --deployment-generation and --idempotency-key.", "fix_input")
	}
	bearer, err := readPrivateBearer(*tokenFile)
	if err != nil {
		return fail(4, "token_file_rejected", safeMessage(err), "authenticate")
	}
	client, baseURL, err := manager.localAPIClient()
	if err != nil {
		return fail(5, "hub_unreachable", safeMessage(err), "retry_later")
	}
	defer client.CloseIdleConnections()
	switch args[0] {
	case "enroll":
		if strings.TrimSpace(*displayName) == "" || len(strings.TrimSpace(*displayName)) > 128 || *outputFile == "" || filepath.Clean(*outputFile) == filepath.Clean(*tokenFile) || (*hostID != "" && !validUUID(*hostID)) {
			return fail(2, "invalid_input", "enroll requires --name and --output-enrollment-file.", "fix_input")
		}
		var issued store.EnrollmentToken
		body := enrollmentCreateRequestCLI{HostDisplayName: strings.TrimSpace(*displayName), ExpiresInSeconds: 600}
		if *hostID != "" {
			body.ReplacementHostID = hostID
		}
		if apiErr := doBearerAPI(ctx, client, baseURL, http.MethodPost, "/api/v1/enrollments", bearer, *generation, *idempotencyKey, body, &issued); apiErr != nil {
			return writeCLIApiError(apiErr, fail)
		}
		if err := config.ValidatePrivateFile(manager.Paths.CACert); err != nil {
			return fail(8, "hub_ca_unavailable", safeMessage(err), "use_local_owner_command")
		}
		caPEM, err := os.ReadFile(manager.Paths.CACert)
		if err != nil {
			return fail(8, "hub_ca_unavailable", safeMessage(err), "use_local_owner_command")
		}
		fingerprint, err := enrollment.FingerprintCertificatePEM(caPEM)
		if err != nil || fingerprint != issued.HubCAFingerprintSHA256 {
			return fail(8, "hub_ca_mismatch", "The issued enrollment does not match the installed collector CA.", "review_current_state")
		}
		deploymentID, err := manager.localDeploymentID()
		if err != nil {
			return fail(8, "deployment_state_unavailable", safeMessage(err), "review_current_state")
		}
		file := enrollment.File{SchemaVersion: domain.SchemaVersion, DeploymentID: deploymentID, HostID: issued.HostID, HubURL: issued.HubURL, HubCAFingerprintSHA256: fingerprint, HubCACertificatePEM: string(caPEM), Token: issued.Token, ExpiresMS: issued.ExpiresMS}
		if err := enrollment.ValidateFile(file, manager.Clock.Now()); err != nil {
			return fail(8, "invalid_api_response", "The hub returned an invalid enrollment file payload.", "retry_later")
		}
		if err := writeJSONFile(*outputFile, file); err != nil {
			return fail(8, "enrollment_file_write_failed", safeMessage(err), "fix_input")
		}
		result := hostEnrollmentCLIResult{SchemaVersion: domain.SchemaVersion, Status: "created", HostID: issued.HostID, EnrollmentFile: *outputFile, ExpiresMS: issued.ExpiresMS}
		if *jsonOutput {
			_ = protocol.WriteJSON(stdout, result)
		} else {
			fmt.Fprintf(stdout, "Enrollment file saved to %s. The one-use bearer was not printed.\n", *outputFile)
		}
		return 0
	case "revoke":
		if *hostID == "" || *outputFile != "" || *displayName != "" {
			return fail(2, "invalid_input", "revoke requires --host and does not accept enrollment output options.", "fix_input")
		}
		var result query.Host
		if apiErr := doBearerAPI(ctx, client, baseURL, http.MethodPost, "/api/v1/hosts/"+*hostID+"/revoke", bearer, *generation, *idempotencyKey, nil, &result); apiErr != nil {
			return writeCLIApiError(apiErr, fail)
		}
		if *jsonOutput {
			_ = protocol.WriteJSON(stdout, result)
		} else {
			fmt.Fprintf(stdout, "Collector credentials revoked for host %s.\n", result.ID)
		}
		return 0
	}
	return fail(2, "invalid_command", "Unknown host command.", "fix_input")
}

func (m *Manager) localDeploymentID() (string, error) {
	if err := config.ValidatePrivateFile(m.Paths.HubConfig); err != nil {
		return "", err
	}
	data, err := os.ReadFile(m.Paths.HubConfig)
	if err != nil || len(data) > 64<<10 {
		return "", errors.New("hub configuration unavailable")
	}
	var saved savedHubConfig
	if err := protocol.DecodeStrictJSON(strings.NewReader(string(data)), 64<<10, &saved); err != nil || saved.SchemaVersion != domain.SchemaVersion || saved.DeploymentID == "" {
		return "", errors.New("hub configuration identity is invalid")
	}
	return saved.DeploymentID, nil
}
