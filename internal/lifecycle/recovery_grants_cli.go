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
	"os"
	"path/filepath"

	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/protocol"
)

func runRecoveryGrantsCLI(ctx context.Context, args []string, stdout, stderr io.Writer, manager *Manager, fail cliFailure) int {
	if len(args) == 0 || (args[0] != "create" && args[0] != "list" && args[0] != "show" && args[0] != "revoke") {
		return fail(2, "invalid_command", "Use recovery grants create|list|show|revoke.", "fix_input")
	}
	fs := flag.NewFlagSet("recovery grants "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	token := fs.String("token-file", "", "private administrator API token file")
	session := fs.String("session-file", "", "private administrator session file")
	manifestPath := fs.String("manifest", "", "reviewed private recovery manifest")
	id := fs.String("grant", "", "recovery grant ID")
	out := fs.String("out", "", "new private grant output file")
	generation := fs.String("deployment-generation", "", "reviewed current generation")
	key := fs.String("idempotency-key", "", "exact mutation retry key")
	jsonOutput := fs.Bool("json", false, "versioned JSON result")
	if len(args) == 2 && args[1] == "--help" {
		fs.SetOutput(stdout)
		fs.PrintDefaults()
		return 0
	}
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		return fail(2, "invalid_input", "Invalid grant option.", "fix_input")
	}
	allowed := map[string]bool{"token-file": true, "session-file": true, "json": true}
	for _, name := range map[string][]string{"create": {"manifest", "out", "deployment-generation", "idempotency-key"}, "show": {"grant", "out"}, "revoke": {"grant", "deployment-generation", "idempotency-key"}}[args[0]] {
		allowed[name] = true
	}
	invalid := false
	fs.Visit(func(f *flag.Flag) { invalid = invalid || !allowed[f.Name] })
	if invalid {
		return fail(2, "invalid_input", "An option does not apply to this grant operation.", "fix_input")
	}
	method, path := http.MethodGet, "/api/v1/recovery-grants"
	var body any
	if args[0] == "create" || args[0] == "revoke" {
		if !validUUID(*generation) || len(*key) < 16 || len(*key) > 128 {
			return fail(2, "invalid_input", "Provide current --deployment-generation and a 16–128 byte --idempotency-key.", "fix_input")
		}
		method = http.MethodPost
	}
	if args[0] == "show" || args[0] == "revoke" {
		if !validUUID(*id) {
			return fail(2, "invalid_input", "Provide a valid --grant ID.", "fix_input")
		}
		path += "/" + *id
		if args[0] == "revoke" {
			path += "/revoke"
		}
	}
	if args[0] == "create" {
		if !filepath.IsAbs(*out) || len(*out) > 1024 {
			return fail(2, "invalid_input", "Provide a new absolute --out path.", "fix_input")
		}
		if err := config.ValidatePrivateFile(*manifestPath); err != nil {
			return fail(2, "manifest_rejected", safeMessage(err), "fix_input")
		}
		file, err := os.Open(*manifestPath)
		if err != nil {
			return fail(2, "manifest_rejected", safeMessage(err), "fix_input")
		}
		manifest, err := protocol.DecodeRecoveryManifest(file)
		file.Close()
		if err != nil {
			return fail(2, "manifest_rejected", "Recovery manifest is invalid or exceeds 64 KiB.", "fix_input")
		}
		body = struct {
			Manifest   protocol.RecoveryManifest `json:"manifest"`
			Generation string                    `json:"deployment_generation"`
		}{manifest, *generation}
	}
	if *out != "" {
		if !filepath.IsAbs(*out) || len(*out) > 1024 {
			return fail(2, "invalid_input", "Grant output must be an absolute path.", "fix_input")
		}
		if err := config.RejectSymlinkTree(filepath.Dir(*out)); err != nil {
			return fail(2, "output_rejected", safeMessage(err), "fix_input")
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
	if args[0] != "list" {
		grant, err := protocol.DecodeRecoveryGrant(bytes.NewReader(result))
		if err != nil {
			return fail(8, "invalid_api_response", "Hub returned an invalid grant acknowledgement.", "retry_later")
		}
		if *out != "" {
			encoded, _ := json.Marshal(grant)
			if err := writeRecoveryGrantFile(*out, append(encoded, '\n')); err != nil {
				return fail(8, "grant_file_write_failed", "The grant exists at the hub but could not be saved. Retry with the same key or use grants show --out.", "fix_input")
			}
		}
	}
	if *jsonOutput {
		fmt.Fprintln(stdout, string(result))
	} else {
		var formatted bytes.Buffer
		_ = json.Indent(&formatted, result, "", "  ")
		fmt.Fprintln(stdout, formatted.String())
		if *out != "" {
			fmt.Fprintln(stdout, "Grant file: "+*out)
		}
	}
	return 0
}

func writeRecoveryGrantFile(path string, data []byte) error {
	if len(data) > 1<<20 {
		return errors.New("grant output exceeds bound")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		if err := config.ValidatePrivateFile(path); err != nil {
			return err
		}
		existing, err := os.Open(path)
		if err != nil {
			return err
		}
		defer existing.Close()
		stored, err := io.ReadAll(io.LimitReader(existing, 1<<20+1))
		if err != nil || !bytes.Equal(stored, data) {
			return errors.New("existing grant output differs")
		}
		return nil
	}
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
