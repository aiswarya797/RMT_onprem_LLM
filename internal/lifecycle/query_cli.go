package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Read commands use the same authenticated, bounded responses as the UI.
// They never start a collector check or an inference request.
func runQueryCLI(ctx context.Context, args []string, stdout, stderr io.Writer, manager *Manager, fail cliFailure) int {
	if len(args) < 2 {
		return fail(2, "invalid_command", "A read operation is required.", "fix_input")
	}
	command := args[0] + " " + args[1]
	paths := map[string]string{
		"hosts list": "/api/v1/hosts", "hosts show": "/api/v1/hosts/",
		"targets check": "/api/v1/targets/", "history catalog": "/api/v1/history/catalog",
		"series query":        "/api/v1/series",
		"monitor-health show": "/api/v1/monitor-health/summary",
	}
	path, ok := paths[command]
	if !ok {
		return fail(2, "invalid_command", "Unknown read operation.", "fix_input")
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	token := fs.String("token-file", "", "private API token file")
	session := fs.String("session-file", "", "private session file")
	id := fs.String("id", "", "host or target ID")
	scope := fs.String("scope", "", "retained history scope ID")
	metric := fs.String("metric", "", "versioned metric ID")
	start := fs.String("start", "", "absolute RFC3339 start")
	end := fs.String("end", "", "absolute RFC3339 end")
	resolution := fs.String("resolution", "auto", "auto, raw, minute or hour")
	jsonOutput := fs.Bool("json", false, "versioned JSON result")
	if len(args) == 3 && args[2] == "--help" {
		fs.SetOutput(stdout)
		fmt.Fprintln(stdout, "llm-monitor "+command)
		fs.PrintDefaults()
		return 0
	}
	if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 0 {
		return fail(2, "invalid_input", "Invalid read option; use --help.", "fix_input")
	}
	allowed := map[string]bool{"token-file": true, "session-file": true, "json": true}
	if command == "series query" {
		for _, key := range []string{"scope", "metric", "start", "end", "resolution"} {
			allowed[key] = true
		}
	} else if command == "hosts show" || command == "targets check" {
		allowed["id"] = true
	}
	invalid := false
	fs.Visit(func(f *flag.Flag) { invalid = invalid || !allowed[f.Name] })
	if invalid {
		return fail(2, "invalid_input", "An option does not apply to this read operation.", "fix_input")
	}
	if command == "hosts show" || command == "targets check" {
		if !validUUID(*id) {
			return fail(2, "invalid_input", "Provide a valid --id.", "fix_input")
		}
		path += *id
	}
	if command == "series query" {
		from, fromErr := time.Parse(time.RFC3339Nano, *start)
		to, toErr := time.Parse(time.RFC3339Nano, *end)
		if fromErr != nil || toErr != nil || !to.After(from) || *scope == "" || len(*scope) > 64 || *metric == "" || len(*metric) > 128 || (*resolution != "auto" && *resolution != "raw" && *resolution != "minute" && *resolution != "hour") {
			return fail(2, "invalid_input", "Provide scope, metric, absolute start/end and a supported resolution.", "fix_input")
		}
		params := url.Values{"scope": {*scope}, "metric": {*metric}, "start": {from.UTC().Format(time.RFC3339Nano)}, "end": {to.UTC().Format(time.RFC3339Nano)}, "resolution": {*resolution}}
		path += "?" + params.Encode()
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
	if apiErr := doBoundedAuthenticatedAPI(ctx, client, origin, http.MethodGet, path, credential, "", "", nil, &result, 2<<20); apiErr != nil {
		return writeCLIApiError(apiErr, fail)
	}
	if *jsonOutput {
		fmt.Fprintln(stdout, string(result))
	} else {
		var formatted bytes.Buffer
		if err := json.Indent(&formatted, result, "", "  "); err != nil {
			return fail(8, "invalid_api_response", "Hub returned invalid JSON.", "retry_later")
		}
		fmt.Fprintln(stdout, formatted.String())
	}
	return 0
}
