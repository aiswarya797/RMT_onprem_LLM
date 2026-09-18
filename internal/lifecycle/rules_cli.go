package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"rmt.local/monitor/internal/protocol"
)

// Rule edits send a complete reviewed definition, including its expected
// revision. No read-modify-write lookup can change the body of an exact retry.
func runRulesCLI(ctx context.Context, args []string, stdout, stderr io.Writer, manager *Manager, fail cliFailure) int {
	if len(args) < 2 {
		return fail(2, "invalid_command", "Use rules list|show|create|edit|disable.", "fix_input")
	}
	operation := args[1]
	switch operation {
	case "list", "show", "create", "edit", "disable":
	default:
		return fail(2, "invalid_command", "Use rules list|show|create|edit|disable.", "fix_input")
	}
	fs := flag.NewFlagSet("rules "+operation, flag.ContinueOnError)
	fs.SetOutput(stderr)
	token := fs.String("token-file", "", "private API token file")
	session := fs.String("session-file", "", "private session file")
	id := fs.String("id", "", "rule ID")
	definition := fs.String("definition-file", "", "reviewed rule definition JSON, at most 64 KiB; include expected_revision")
	generation := fs.String("deployment-generation", "", "reviewed deployment generation")
	key := fs.String("idempotency-key", "", "exact mutation retry identity")
	jsonOutput := fs.Bool("json", false, "versioned JSON result")
	if len(args) == 3 && args[2] == "--help" {
		fs.SetOutput(stdout)
		fmt.Fprintln(stdout, "llm-monitor rules "+operation)
		fs.PrintDefaults()
		return 0
	}
	if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 0 {
		return fail(2, "invalid_input", "Invalid rule option; use --help.", "fix_input")
	}
	mutation := operation == "create" || operation == "edit" || operation == "disable"
	needsID := operation == "show" || operation == "edit" || operation == "disable"
	allowed := map[string]bool{"token-file": true, "session-file": true, "json": true}
	if mutation {
		allowed["definition-file"], allowed["deployment-generation"], allowed["idempotency-key"] = true, true, true
	}
	if needsID {
		allowed["id"] = true
	}
	invalid := false
	fs.Visit(func(f *flag.Flag) { invalid = invalid || !allowed[f.Name] })
	if invalid || (needsID && !validUUID(*id)) || (mutation && (!validUUID(*generation) || len(*key) < 16 || len(*key) > 128 || strings.ContainsAny(*key, " \t\r\n"))) {
		return fail(2, "invalid_input", "Provide applicable options and the reviewed identity, generation and retry key.", "fix_input")
	}
	method, path := http.MethodGet, "/api/v1/rules"
	if needsID {
		path += "/" + *id
	}
	var body any
	if mutation {
		data, err := readRuleDefinition(*definition, operation)
		if err != nil {
			return fail(2, "invalid_rule_definition", "Provide a bounded JSON rule definition with the expected revision; disable requires enabled=false.", "fix_input")
		}
		body = data
		method = http.MethodPut
		if operation == "create" {
			method = http.MethodPost
		}
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
	if apiErr := doBoundedAuthenticatedAPI(ctx, client, origin, method, path, credential, *generation, *key, body, &result, 1<<20); apiErr != nil {
		return writeCLIApiError(apiErr, fail)
	}
	if *jsonOutput {
		fmt.Fprintln(stdout, string(result))
	} else {
		var formatted bytes.Buffer
		if json.Indent(&formatted, result, "", "  ") != nil {
			return fail(8, "invalid_api_response", "Hub returned invalid JSON.", "retry_later")
		}
		fmt.Fprintln(stdout, formatted.String())
	}
	return 0
}

func readRuleDefinition(path, operation string) (json.RawMessage, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return nil, fmt.Errorf("invalid rule file")
	}
	var body json.RawMessage
	if err := protocol.DecodeStrictJSON(file, 64<<10, &body); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || fields == nil {
		return nil, fmt.Errorf("rule object required")
	}
	if operation == "disable" && !bytes.Equal(bytes.TrimSpace(fields["enabled"]), []byte("false")) {
		return nil, fmt.Errorf("disable requires enabled=false")
	}
	return body, nil
}
