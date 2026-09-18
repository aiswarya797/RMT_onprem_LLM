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
	"strings"

	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
)

type cliAuthentication struct{ Bearer, Cookie, CSRF string }

func (a cliAuthentication) apply(request *http.Request) {
	if a.Bearer != "" {
		request.Header.Set("Authorization", "Bearer "+a.Bearer)
	} else if a.Cookie != "" {
		request.AddCookie(&http.Cookie{Name: "rmt_session", Value: a.Cookie})
		request.Header.Set("X-CSRF-Token", a.CSRF)
		request.Header.Set("Origin", request.URL.Scheme+"://"+request.URL.Host)
	}
}

type cliSessionFile struct {
	SchemaVersion string         `json:"schema_version"`
	Origin        string         `json:"origin"`
	Cookie        string         `json:"cookie"`
	Session       domain.Session `json:"session"`
}

type authSessionResult struct {
	SchemaVersion string      `json:"schema_version"`
	Status        string      `json:"status"`
	SessionFile   string      `json:"session_file"`
	User          domain.User `json:"user"`
	ExpiresMS     int64       `json:"expires_ms"`
}

func readCLIAuthentication(tokenPath, sessionPath, origin string, nowMS int64) (cliAuthentication, error) {
	if (tokenPath == "") == (sessionPath == "") {
		return cliAuthentication{}, errors.New("provide exactly one private --token-file or --session-file")
	}
	if tokenPath != "" {
		token, err := readPrivateBearer(tokenPath)
		return cliAuthentication{Bearer: token}, err
	}
	file, err := readCLISession(sessionPath, origin)
	if err != nil {
		return cliAuthentication{}, err
	}
	if file.Session.ExpiresMS <= nowMS {
		return cliAuthentication{}, errors.New("the saved session expired; sign in again")
	}
	return cliAuthentication{Cookie: file.Cookie, CSRF: file.Session.CSRFToken}, nil
}

func readCLISession(path, origin string) (cliSessionFile, error) {
	var value cliSessionFile
	if err := config.ValidatePrivateFile(path); err != nil {
		return value, err
	}
	file, err := os.Open(path)
	if err != nil {
		return value, err
	}
	defer file.Close()
	if err := protocol.DecodeStrictJSON(file, 8<<10, &value); err != nil {
		return value, errors.New("invalid bounded session file")
	}
	if value.SchemaVersion != domain.SchemaVersion || value.Origin != origin || !validCLISession(value) {
		return value, errors.New("session file does not match this local hub or is invalid")
	}
	return value, nil
}

func validCLISession(value cliSessionFile) bool {
	user := value.Session.User
	return validCLISecret(value.Cookie) && validCLISecret(value.Session.CSRFToken) && user.ID != "" && user.TrustGeneration != "" && value.Session.ExpiresMS > 0 && !user.Disabled && !user.HistoricalRestored && (user.Role == "admin" || user.Role == "viewer")
}

func validCLISecret(value string) bool {
	if len(value) < 32 || len(value) > 512 {
		return false
	}
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

func runAuthSessionCLI(ctx context.Context, args []string, stdout, stderr io.Writer, manager *Manager, fail cliFailure) int {
	fs := flag.NewFlagSet("auth "+args[0], flag.ContinueOnError)
	// Do not echo an unsupported password argument through flag diagnostics.
	fs.SetOutput(io.Discard)
	username := fs.String("username", "", "account name")
	passwordStdin := fs.Bool("password-stdin", false, "read password from standard input")
	sessionPath := fs.String("session-file", "", "private session file")
	jsonOutput := fs.Bool("json", false, "JSON output")
	if len(args) == 2 && args[1] == "--help" {
		fs.SetOutput(stdout)
		fmt.Fprintln(stdout, "llm-monitor auth "+args[0]+": use a private session file; passwords are read only from standard input.")
		fs.PrintDefaults()
		return 0
	}
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || !filepath.IsAbs(*sessionPath) || len(*sessionPath) > 1024 {
		return fail(2, "invalid_input", "Use auth login --username NAME --password-stdin --session-file ABSOLUTE_PATH, or auth logout --session-file ABSOLUTE_PATH.", "fix_input")
	}
	if args[0] == "login" && (!*passwordStdin || strings.TrimSpace(*username) == "" || len(*username) > 128) || args[0] == "logout" && (*passwordStdin || *username != "") {
		return fail(2, "invalid_input", "Login requires --username and --password-stdin; logout accepts neither.", "fix_input")
	}
	client, origin, err := manager.localAPIClient()
	if err != nil {
		return fail(5, "hub_unreachable", "The configured local hub is unavailable.", "retry_later")
	}
	defer client.CloseIdleConnections()
	var saved cliSessionFile
	if args[0] == "login" {
		if _, err := os.Lstat(*sessionPath); !errors.Is(err, os.ErrNotExist) {
			return fail(2, "session_file_exists", "Choose a new session file or sign out the existing session first.", "fix_input")
		}
		if err := config.RejectSymlinkTree(filepath.Dir(*sessionPath)); err != nil {
			return fail(2, "session_file_rejected", "The session destination must have an existing nonsymlink parent directory.", "fix_input")
		}
		input := manager.Input
		if input == nil {
			input = os.Stdin
		}
		password, err := io.ReadAll(io.LimitReader(input, 1027))
		if err != nil || len(password) > 1026 {
			return fail(2, "invalid_input", "Password input exceeds its bound or could not be read.", "fix_input")
		}
		password = bytes.TrimSuffix(bytes.TrimSuffix(password, []byte("\n")), []byte("\r"))
		if len(password) < 12 || len(password) > 1024 {
			return fail(2, "invalid_input", "Password must be 12 through 1024 bytes.", "fix_input")
		}
		body, _ := json.Marshal(struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}{*username, string(password)})
		clear(password)
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, origin.String()+"/api/v1/auth/sessions", bytes.NewReader(body))
		if err != nil {
			return fail(8, "request_failed", "Could not prepare local sign-in.", "retry_later")
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", origin.String())
		response, err := client.Do(request)
		clear(body)
		if err != nil {
			return fail(5, "hub_unreachable", "The local hub could not complete sign-in.", "retry_later")
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			var apiError domain.APIError
			if protocol.DecodeStrictJSON(response.Body, 64<<10, &apiError) != nil || apiError.Code == "" {
				return fail(4, "login_rejected", "The local hub rejected sign-in.", "authenticate")
			}
			return writeCLIApiError(&apiError, fail)
		}
		saved.SchemaVersion, saved.Origin = domain.SchemaVersion, origin.String()
		if protocol.DecodeStrictJSON(response.Body, 8<<10, &saved.Session) != nil {
			return fail(8, "invalid_api_response", "Hub returned an invalid session response.", "retry_later")
		}
		for _, cookie := range response.Cookies() {
			if cookie.Name == "rmt_session" {
				saved.Cookie = cookie.Value
			}
		}
		if !validCLISession(saved) || saved.Session.ExpiresMS <= manager.Clock.Now().UnixMilli() {
			return fail(8, "invalid_api_response", "Hub returned an invalid session acknowledgement.", "retry_later")
		}
		encoded, _ := json.Marshal(saved)
		if err := writeNewCredentialFile(*sessionPath, encoded); err != nil {
			credential := cliAuthentication{Cookie: saved.Cookie, CSRF: saved.Session.CSRFToken}
			_ = doAuthenticatedAPI(ctx, client, origin, http.MethodDelete, "/api/v1/auth/session", credential, "", "", nil, nil)
			return fail(8, "session_file_write_failed", "The session file could not be saved. Sign-in was not completed; use a writable new path.", "fix_input")
		}
	} else {
		saved, err = readCLISession(*sessionPath, origin.String())
		if err != nil {
			return fail(4, "session_file_rejected", safeMessage(err), "authenticate")
		}
		credential := cliAuthentication{Cookie: saved.Cookie, CSRF: saved.Session.CSRFToken}
		if apiError := doAuthenticatedAPI(ctx, client, origin, http.MethodDelete, "/api/v1/auth/session", credential, "", "", nil, nil); apiError != nil && apiError.Code != "session_expired" {
			return writeCLIApiError(apiError, fail)
		}
		if err := os.Remove(*sessionPath); err != nil {
			return fail(8, "session_file_remove_failed", "The session is revoked, but its local credential file could not be removed.", "fix_input")
		}
	}
	status := "signed_in"
	if args[0] == "logout" {
		status = "signed_out"
	}
	result := authSessionResult{SchemaVersion: domain.SchemaVersion, Status: status, SessionFile: *sessionPath, User: saved.Session.User, ExpiresMS: saved.Session.ExpiresMS}
	if *jsonOutput {
		_ = protocol.WriteJSON(stdout, result)
	} else {
		fmt.Fprintf(stdout, "%s: %s (%s). Session file: %s\n", status, result.User.Name, result.User.Role, result.SessionFile)
	}
	return 0
}

func writeNewCredentialFile(path string, encoded []byte) error {
	if !filepath.IsAbs(path) || len(encoded) > 8<<10 {
		return errors.New("invalid credential destination or size")
	}
	if err := config.RejectSymlinkTree(filepath.Dir(path)); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
