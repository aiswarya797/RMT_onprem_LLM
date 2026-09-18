package lifecycle

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"

	"rmt.local/monitor/internal/config"
)

func runNotificationsCLI(ctx context.Context, args []string, stdout, stderr io.Writer, m *Manager, fail cliFailure) int {
	if len(args) < 2 {
		return fail(2, "invalid_command", "Use destinations list|show|create|edit|remove|test or deliveries show|retry.", "fix_input")
	}
	group, op := args[0], args[1]
	valid := group == "destinations" && (op == "list" || op == "show" || op == "create" || op == "edit" || op == "remove" || op == "test") || group == "deliveries" && (op == "show" || op == "retry")
	if !valid {
		return fail(2, "invalid_command", "Unsupported notification operation.", "fix_input")
	}
	fs := flag.NewFlagSet(group+" "+op, flag.ContinueOnError)
	fs.SetOutput(stderr)
	token := fs.String("token-file", "", "private API token file")
	session := fs.String("session-file", "", "private session file")
	id := fs.String("id", "", "destination or delivery ID")
	definition := fs.String("definition-file", "", "private reviewed JSON file including secret_input; at most 64 KiB")
	revision := fs.Int64("expected-revision", 0, "reviewed destination revision for remove or test")
	generation := fs.String("deployment-generation", "", "reviewed deployment generation")
	key := fs.String("idempotency-key", "", "exact retry identity")
	_ = fs.Bool("json", false, "JSON result")
	if len(args) == 3 && args[2] == "--help" {
		fs.SetOutput(stdout)
		fs.PrintDefaults()
		return 0
	}
	if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 0 {
		return fail(2, "invalid_input", "Invalid notification option; use --help.", "fix_input")
	}
	mutation := op != "show" && op != "list"
	needsID := op != "list" && op != "create"
	needsFile := op == "create" || op == "edit"
	allowed := map[string]bool{"token-file": true, "session-file": true, "json": true}
	if mutation {
		allowed["deployment-generation"], allowed["idempotency-key"] = true, true
	}
	if needsID {
		allowed["id"] = true
	}
	if needsFile {
		allowed["definition-file"] = true
	}
	if op == "remove" || op == "test" {
		allowed["expected-revision"] = true
	}
	invalid := false
	fs.Visit(func(f *flag.Flag) { invalid = invalid || !allowed[f.Name] })
	if invalid || needsID && !validUUID(*id) || mutation && (!validUUID(*generation) || len(*key) < 16 || len(*key) > 128) || (op == "remove" || op == "test") && *revision < 1 {
		return fail(2, "invalid_input", "Provide only applicable options and the reviewed identities, revision and retry key.", "fix_input")
	}
	path, method := "/api/v1/"+group, http.MethodGet
	if needsID {
		path += "/" + *id
	}
	var body any
	if needsFile {
		if config.ValidatePrivateFile(*definition) != nil {
			return fail(2, "private_definition_required", "Destination definitions must be user-owned regular files with 0600 permissions.", "fix_input")
		}
		data, err := readRuleDefinition(*definition, op)
		if err != nil {
			return fail(2, "invalid_destination_definition", "Provide a bounded destination JSON file with expected_revision and secret_input.", "fix_input")
		}
		body = data
		method = http.MethodPut
		if op == "create" {
			method = http.MethodPost
		}
	}
	if op == "remove" {
		method = http.MethodDelete
	}
	if op == "test" {
		method = http.MethodPost
		path += "/tests"
	}
	if op == "retry" {
		method = http.MethodPost
		path += "/retry"
	}
	client, origin, err := m.localAPIClient()
	if err != nil {
		return fail(5, "hub_unreachable", safeMessage(err), "retry_later")
	}
	defer client.CloseIdleConnections()
	credential, err := readCLIAuthentication(*token, *session, origin.String(), m.Clock.Now().UnixMilli())
	if err != nil {
		return fail(4, "credential_file_rejected", safeMessage(err), "authenticate")
	}
	var result json.RawMessage
	var output any = &result
	var revisions []int64
	if op == "remove" || op == "test" {
		revisions = []int64{*revision}
	}
	if op == "remove" {
		output = nil
	}
	if apiErr := doBoundedAuthenticatedAPI(ctx, client, origin, method, path, credential, *generation, *key, body, output, 1<<20, revisions...); apiErr != nil {
		return writeCLIApiError(apiErr, fail)
	}
	if output == nil {
		fmt.Fprintln(stdout, `{"schema_version":"1.0","status":"removed"}`)
	} else {
		fmt.Fprintln(stdout, string(result))
	}
	return 0
}
