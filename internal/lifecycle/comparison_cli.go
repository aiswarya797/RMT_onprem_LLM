package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

const comparisonCLIImportMaximumBytes int64 = 8 << 20

func runComparisonCLI(ctx context.Context, args []string, stdout, stderr io.Writer, manager *Manager, fail cliFailure) int {
	if len(args) < 2 {
		return fail(2, "invalid_command", "Use probe import or compare preview|create|show|attach.", "fix_input")
	}
	command := args[0] + " " + args[1]
	valid := command == "probe import" || command == "compare preview" || command == "compare create" || command == "compare show" || command == "compare attach"
	if !valid {
		return fail(2, "invalid_command", "Use probe import or compare preview|create|show|attach.", "fix_input")
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	token := fs.String("token-file", "", "private API token file")
	session := fs.String("session-file", "", "private session file")
	generation := fs.String("deployment-generation", "", "reviewed deployment generation for mutations")
	key := fs.String("idempotency-key", "", "exact mutation retry key")
	inputFile := fs.String("input-file", "", "private normalized probe-import JSON file, at most 8 MiB")
	interventionFile := fs.String("intervention-file", "", "private declared-intervention JSON file")
	id := fs.String("id", "", "saved comparison ID")
	incident := fs.String("incident", "", "investigation ID to attach")
	scope := fs.String("scope", "", "comparison scope/target ID")
	metric := fs.String("metric", "", "request metric ID")
	before := fs.String("before", "", "before run ID")
	after := fs.String("after", "", "after run ID")
	jsonOutput := fs.Bool("json", false, "versioned JSON result")
	if len(args) == 3 && args[2] == "--help" {
		fs.SetOutput(stdout)
		fmt.Fprintln(stdout, "llm-monitor "+command)
		fs.PrintDefaults()
		return 0
	}
	if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 0 {
		return fail(2, "invalid_input", "Invalid import or comparison option; use --help.", "fix_input")
	}
	allowed := map[string]bool{"token-file": true, "session-file": true, "json": true}
	mutation := command == "probe import" || command == "compare create" || command == "compare attach"
	if mutation {
		allowed["deployment-generation"], allowed["idempotency-key"] = true, true
	}
	switch command {
	case "probe import":
		allowed["input-file"] = true
	case "compare preview", "compare create":
		allowed["scope"], allowed["metric"], allowed["before"], allowed["after"] = true, true, true, true
		if command == "compare create" {
			allowed["intervention-file"] = true
		}
	case "compare show":
		allowed["id"] = true
	case "compare attach":
		allowed["id"], allowed["incident"] = true, true
	}
	invalid := false
	fs.Visit(func(option *flag.Flag) { invalid = invalid || !allowed[option.Name] })
	if invalid {
		return fail(2, "invalid_input", "An option does not apply to this operation.", "fix_input")
	}

	var body any
	method := http.MethodGet
	path := ""
	var importRaw []byte
	switch command {
	case "probe import":
		if *inputFile == "" || *generation == "" || len(*key) < 16 || len(*key) > 128 {
			return fail(2, "invalid_input", "probe import requires --input-file, --deployment-generation and --idempotency-key.", "fix_input")
		}
		data, err := readProbeImportFile(*inputFile)
		if err != nil {
			return fail(2, "invalid_probe_import", "The input file is not a bounded complete normalized probe import.", "fix_input")
		}
		importRaw = data
		var decoded store.ProbeImport
		if protocol.DecodeStrictJSONWithCeiling(bytes.NewReader(data), int64(len(data)), comparisonCLIImportMaximumBytes, &decoded) != nil {
			return fail(2, "invalid_probe_import", "The input file is not a bounded complete normalized probe import.", "fix_input")
		}
		body, method, path = json.RawMessage(data), http.MethodPost, "/api/v1/probes"
	case "compare preview", "compare create":
		if !validUUID(*scope) || !validUUID(*before) || !validUUID(*after) || !validComparisonMetric(*metric) || *before == *after {
			return fail(2, "invalid_input", "Provide distinct valid --scope, --metric, --before and --after values.", "fix_input")
		}
		request := store.RequestComparison{ComparisonKind: "request_run", ScopeID: *scope, MetricID: *metric, BeforeRunID: *before, AfterRunID: *after}
		if command == "compare preview" {
			parameters := url.Values{"comparison_kind": {request.ComparisonKind}, "scope_id": {request.ScopeID}, "metric_id": {request.MetricID}, "before_run_id": {request.BeforeRunID}, "after_run_id": {request.AfterRunID}}
			path = "/api/v1/comparisons/preview?" + parameters.Encode()
		} else {
			if *generation == "" || len(*key) < 16 || len(*key) > 128 {
				return fail(2, "invalid_input", "compare create requires --deployment-generation and --idempotency-key.", "fix_input")
			}
			if *interventionFile != "" {
				var intervention store.DeclaredIntervention
				data, err := readBoundedPrivateJSON(*interventionFile, 64<<10, &intervention)
				if err != nil || data == nil {
					return fail(2, "invalid_intervention", "The declared intervention file is invalid or not a private bounded JSON file.", "fix_input")
				}
				request.DeclaredIntervention = &intervention
			}
			body, method, path = request, http.MethodPost, "/api/v1/comparisons"
		}
	case "compare show":
		if !validUUID(*id) {
			return fail(2, "invalid_input", "compare show requires a valid --id.", "fix_input")
		}
		path = "/api/v1/comparisons/" + url.PathEscape(*id)
	case "compare attach":
		if !validUUID(*id) || !validUUID(*incident) || *generation == "" || len(*key) < 16 || len(*key) > 128 {
			return fail(2, "invalid_input", "compare attach requires --id, --incident, --deployment-generation and --idempotency-key.", "fix_input")
		}
		body, method, path = struct {
			ResourceID string `json:"resource_id"`
		}{*id}, http.MethodPost, "/api/v1/incidents/"+url.PathEscape(*incident)+"/comparisons"
	}

	client, origin, err := manager.localAPIClient()
	if err != nil {
		return fail(5, "hub_unreachable", safeMessage(err), "retry_later")
	}
	defer client.CloseIdleConnections()
	credential, err := readCLIAuthentication(*token, *session, origin.String(), manager.Clock.Now().UnixMilli())
	if err != nil {
		return fail(4, "credential_file_rejected", safeMessage(err), "authenticate")
	}
	var result json.RawMessage
	requestLimit := int64(64 << 10)
	if command == "probe import" {
		requestLimit = comparisonCLIImportMaximumBytes
		_ = importRaw
	}
	if apiErr := doBoundedAuthenticatedAPIBody(ctx, client, origin, method, path, credential, *generation, *key, body, &result, requestLimit, 2<<20); apiErr != nil {
		return writeCLIApiError(apiErr, fail)
	}
	if *jsonOutput {
		fmt.Fprintln(stdout, string(result))
		return 0
	}
	var formatted bytes.Buffer
	if err := json.Indent(&formatted, result, "", "  "); err != nil {
		return fail(8, "invalid_api_response", "Hub returned invalid JSON.", "retry_later")
	}
	fmt.Fprintln(stdout, formatted.String())
	return 0
}

func readProbeImportFile(path string) ([]byte, error) {
	return readBoundedPrivateJSON(path, comparisonCLIImportMaximumBytes, nil)
}

func readBoundedPrivateJSON(path string, limit int64, target any) ([]byte, error) {
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
		return nil, errors.New("private JSON exceeds its bound")
	}
	if target != nil && protocol.DecodeStrictJSONWithCeiling(bytes.NewReader(data), int64(len(data)), limit, target) != nil {
		return nil, errors.New("private JSON is invalid")
	}
	return data, nil
}

func validComparisonMetric(value string) bool {
	switch value {
	case "request.client.first_byte_ms", "request.client.first_content_ms", "request.client.total_ms", "request.runtime.total_duration_ms", "request.runtime.load_duration_ms", "request.runtime.prompt_eval_duration_ms", "request.runtime.eval_duration_ms", "request.runtime.prompt_tokens", "request.runtime.output_tokens":
		return true
	default:
		return false
	}
}
