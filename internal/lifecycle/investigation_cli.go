package lifecycle

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"rmt.local/monitor/internal/investigation"
	"rmt.local/monitor/internal/protocol"
)

func runInvestigationCLI(ctx context.Context, args []string, stdout, stderr io.Writer, manager *Manager, fail cliFailure) int {
	if len(args) < 2 {
		return fail(2, "invalid_command", "Use incidents list|show|create|update|close|reopen|acknowledge|mute|unmute or annotations list|create|edit.", "fix_input")
	}
	command := args[0] + " " + args[1]
	switch command {
	case "incidents list", "incidents show", "incidents create", "incidents update", "incidents close", "incidents reopen", "incidents acknowledge", "incidents mute", "incidents unmute", "annotations list", "annotations create", "annotations edit":
	default:
		return fail(2, "invalid_command", "Use incidents list|show|create|update|close|reopen|acknowledge|mute|unmute or annotations list|create|edit.", "fix_input")
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	token := fs.String("token-file", "", "private API token file")
	session := fs.String("session-file", "", "private session file")
	generation := fs.String("deployment-generation", "", "reviewed deployment generation for mutations")
	key := fs.String("idempotency-key", "", "exact mutation retry key")
	id := fs.String("id", "", "incident or annotation ID")
	incidentID := fs.String("incident", "", "incident ID for a new annotation")
	cursor := fs.String("cursor", "", "next_cursor from a prior page")
	limit := fs.Int("limit", 100, "page size, 1 through 100")
	title := fs.String("title", "", "manual investigation title")
	workflowState := fs.String("workflow-state", "", "manual investigation state: open or closed")
	scopeKind := fs.String("scope-kind", "", "host, runtime, model or process")
	scope := fs.String("scope", "", "retained scope ID")
	start := fs.String("start", "", "absolute RFC3339 focus start")
	end := fs.String("end", "", "absolute RFC3339 focus end")
	declaredTime := fs.String("declared-time", "", "operator-declared RFC3339 event time")
	note := fs.String("text", "", "plaintext operator note")
	revision := fs.Int64("expected-revision", 0, "incident or annotation revision being edited")
	transition := fs.Int64("observed-transition-seq", 0, "observed alert transition sequence to acknowledge")
	muteReason := fs.String("reason", "", "plain-text reason for a delivery mute")
	muteExpiry := fs.String("expires", "", "absolute RFC3339 mute expiry, within 24 hours")
	jsonOutput := fs.Bool("json", false, "versioned JSON result")
	if len(args) == 3 && args[2] == "--help" {
		fs.SetOutput(stdout)
		fmt.Fprintln(stdout, "llm-monitor "+command)
		fs.PrintDefaults()
		return 0
	}
	if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 0 {
		return fail(2, "invalid_input", "Invalid investigation option; use --help.", "fix_input")
	}
	allowed := map[string]bool{"token-file": true, "session-file": true, "json": true}
	for _, name := range map[string][]string{
		"incidents list":        {"cursor", "limit"},
		"annotations list":      {"incident", "cursor", "limit"},
		"incidents show":        {"id"},
		"incidents create":      {"title", "scope-kind", "scope", "start", "end", "deployment-generation", "idempotency-key"},
		"incidents update":      {"id", "expected-revision", "title", "workflow-state", "deployment-generation", "idempotency-key"},
		"incidents close":       {"id", "expected-revision", "deployment-generation", "idempotency-key"},
		"incidents reopen":      {"id", "expected-revision", "deployment-generation", "idempotency-key"},
		"incidents acknowledge": {"id", "observed-transition-seq", "deployment-generation", "idempotency-key"},
		"incidents mute":        {"id", "reason", "expires", "deployment-generation", "idempotency-key"},
		"incidents unmute":      {"id", "deployment-generation", "idempotency-key"},
		"annotations create":    {"incident", "declared-time", "text", "deployment-generation", "idempotency-key"},
		"annotations edit":      {"id", "expected-revision", "text", "deployment-generation", "idempotency-key"},
	}[command] {
		allowed[name] = true
	}
	invalidFlag, titleProvided := false, false
	fs.Visit(func(f *flag.Flag) {
		invalidFlag = invalidFlag || !allowed[f.Name]
		titleProvided = titleProvided || f.Name == "title"
	})
	if invalidFlag {
		return fail(2, "invalid_input", "An option does not apply to this operation.", "fix_input")
	}
	method, path := http.MethodGet, "/api/v1/incidents"
	var body any
	switch command {
	case "incidents list", "annotations list":
		if *limit < 1 || *limit > 100 || len(*cursor) > 512 || (command == "annotations list" && (*incidentID == "" || len(*incidentID) > 64)) {
			return fail(2, "invalid_input", "Provide a valid page limit/cursor and an incident ID for annotations.", "fix_input")
		}
		if command == "annotations list" {
			path += "/" + url.PathEscape(*incidentID) + "/annotations"
		}
		params := url.Values{"limit": {strconv.Itoa(*limit)}}
		if *cursor != "" {
			params.Set("cursor", *cursor)
		}
		path += "?" + params.Encode()
	case "incidents show":
		if *id == "" || len(*id) > 64 {
			return fail(2, "invalid_input", "Provide --id.", "fix_input")
		}
		path += "/" + url.PathEscape(*id)
	case "incidents create":
		from, fromErr := time.Parse(time.RFC3339Nano, *start)
		to, toErr := time.Parse(time.RFC3339Nano, *end)
		if fromErr != nil || toErr != nil || !to.After(from) || strings.TrimSpace(*title) == "" || utf8.RuneCountInString(*title) > 160 || *scope == "" || len(*scope) > 64 || (*scopeKind != "host" && *scopeKind != "runtime" && *scopeKind != "model" && *scopeKind != "process") {
			return fail(2, "invalid_input", "Provide a title, retained scope kind/ID and absolute start/end range.", "fix_input")
		}
		method = http.MethodPost
		body = struct {
			Title string              `json:"title"`
			Scope investigation.Scope `json:"scope"`
			Start string              `json:"start"`
			End   string              `json:"end"`
		}{*title, investigation.Scope{Kind: *scopeKind, ID: *scope}, from.UTC().Format(time.RFC3339Nano), to.UTC().Format(time.RFC3339Nano)}
	case "incidents update", "incidents close", "incidents reopen":
		if !validUUID(*id) || *revision < 1 {
			return fail(2, "invalid_input", "Provide --id and --expected-revision.", "fix_input")
		}
		if command == "incidents close" {
			*workflowState = "closed"
		}
		if command == "incidents reopen" {
			*workflowState = "open"
		}
		if (!titleProvided && *workflowState == "") || (titleProvided && (strings.TrimSpace(*title) == "" || utf8.RuneCountInString(*title) > 160)) || (*workflowState != "" && *workflowState != "open" && *workflowState != "closed") {
			return fail(2, "invalid_input", "Provide a bounded title or open/closed workflow state.", "fix_input")
		}
		change := map[string]any{"expected_revision": *revision}
		if *title != "" {
			change["title"] = *title
		}
		if *workflowState != "" {
			change["workflow_state"] = *workflowState
		}
		method, path, body = http.MethodPatch, path+"/"+*id, change
	case "incidents acknowledge", "incidents mute", "incidents unmute":
		if !validUUID(*id) {
			return fail(2, "invalid_input", "Provide a valid alert incident --id.", "fix_input")
		}
		path += "/" + *id
		switch command {
		case "incidents acknowledge":
			if *transition < 1 {
				return fail(2, "invalid_input", "Provide --observed-transition-seq from the reviewed alert state.", "fix_input")
			}
			method, path = http.MethodPost, path+"/acknowledgements"
			body = struct {
				Sequence int64 `json:"observed_transition_seq"`
			}{*transition}
		case "incidents mute":
			expires, err := time.Parse(time.RFC3339Nano, *muteExpiry)
			if err != nil || expires.UnixMilli() < 0 || strings.TrimSpace(*muteReason) == "" || utf8.RuneCountInString(*muteReason) > 256 {
				return fail(2, "invalid_input", "Provide a bounded --reason and absolute --expires time within 24 hours. The hub validates the current expiry limit.", "fix_input")
			}
			method, path = http.MethodPost, path+"/mute"
			body = struct {
				Reason    string `json:"reason"`
				ExpiresMS int64  `json:"expires_ms"`
			}{*muteReason, expires.UnixMilli()}
		case "incidents unmute":
			method, path = http.MethodDelete, path+"/mute"
		}
	case "annotations create":
		declared, err := time.Parse(time.RFC3339Nano, *declaredTime)
		if err != nil || declared.UnixMilli() < 0 || *incidentID == "" || len(*incidentID) > 64 || strings.TrimSpace(*note) == "" || len(*note) > 2048 {
			return fail(2, "invalid_input", "Provide --incident, --declared-time and bounded --text.", "fix_input")
		}
		method, path = http.MethodPost, "/api/v1/annotations"
		body = struct {
			IncidentID string `json:"incident_id"`
			DeclaredMS int64  `json:"declared_time_ms"`
			Text       string `json:"text"`
		}{*incidentID, declared.UnixMilli(), *note}
	case "annotations edit":
		if *id == "" || len(*id) > 64 || *revision < 1 || strings.TrimSpace(*note) == "" || len(*note) > 2048 {
			return fail(2, "invalid_input", "Provide --id, --expected-revision and bounded --text.", "fix_input")
		}
		method, path = http.MethodPatch, "/api/v1/annotations/"+url.PathEscape(*id)
		body = struct {
			ExpectedRevision int64  `json:"expected_revision"`
			Text             string `json:"text"`
		}{*revision, *note}
	}
	if method != http.MethodGet && (*generation == "" || len(*key) < 16 || len(*key) > 128) {
		return fail(2, "invalid_input", "Mutations require --deployment-generation and a 16–128 byte --idempotency-key.", "fix_input")
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
		_ = protocol.WriteJSON(stdout, result)
	} else {
		var value any
		if json.Unmarshal(result, &value) != nil {
			return fail(8, "invalid_api_response", "Hub returned an invalid result.", "retry_later")
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(value)
	}
	return 0
}
