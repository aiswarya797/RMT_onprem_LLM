package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

type cliFailure func(code int, safeCode, message, recovery string) int

type authTokenCLIResult struct {
	SchemaVersion string               `json:"schema_version"`
	Status        string               `json:"status"`
	TokenFile     string               `json:"token_file,omitempty"`
	Record        store.APITokenRecord `json:"record"`
}

type apiTokenCreateBody struct {
	DisplayName      string `json:"display_name"`
	ExpiresInSeconds int64  `json:"expires_in_seconds"`
}

type apiTokenListBody struct {
	Items []store.APITokenRecord `json:"items"`
}

type apiTokenRevokeBody struct {
	ID        string `json:"id"`
	RevokedMS int64  `json:"revoked_ms"`
}

func runAuthTokenCLI(ctx context.Context, args []string, stdout, stderr io.Writer, manager *Manager, fail cliFailure) int {
	if len(args) < 2 || args[0] != "token" || (args[1] != "create" && args[1] != "list" && args[1] != "revoke") {
		return fail(2, "invalid_command", "Use: llm-monitor auth token create|list|revoke", "fix_input")
	}
	fs := flag.NewFlagSet("auth token "+args[1], flag.ContinueOnError)
	fs.SetOutput(stderr)
	tokenFile := fs.String("token-file", "", "private 0600 API token file")
	sessionFile := fs.String("session-file", "", "private 0600 session file from auth login")
	outputTokenFile := fs.String("output-token-file", "", "private 0600 destination for the new token")
	displayName := fs.String("name", "", "token display name")
	expires := fs.Duration("expires", 0, "explicit token lifetime, from 5m through 2160h")
	tokenID := fs.String("token", "", "token ID to revoke")
	generation := fs.String("deployment-generation", "", "reviewed deployment generation")
	idempotencyKey := fs.String("idempotency-key", "", "retry identity")
	jsonOutput := fs.Bool("json", false, "JSON output")
	if len(args) == 3 && args[2] == "--help" {
		fs.SetOutput(stdout)
		fmt.Fprintln(stdout, "llm-monitor auth token "+args[1])
		fs.PrintDefaults()
		return 0
	}
	if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 0 {
		return fail(2, "invalid_input", "Invalid API token option.", "fix_input")
	}
	client, baseURL, err := manager.localAPIClient()
	if err != nil {
		return fail(5, "hub_unreachable", safeMessage(err), "retry_later")
	}
	defer client.CloseIdleConnections()
	credential, err := readCLIAuthentication(*tokenFile, *sessionFile, baseURL.String(), manager.Clock.Now().UnixMilli())
	if err != nil {
		return fail(4, "credential_file_rejected", safeMessage(err), "authenticate")
	}
	switch args[1] {
	case "list":
		if *outputTokenFile != "" || *displayName != "" || *expires != 0 || *tokenID != "" || *generation != "" || *idempotencyKey != "" {
			return fail(2, "invalid_input", "auth token list accepts --token-file or --session-file, plus --json.", "fix_input")
		}
		var result apiTokenListBody
		if apiErr := doAuthenticatedAPI(ctx, client, baseURL, http.MethodGet, "/api/v1/auth/tokens", credential, "", "", nil, &result); apiErr != nil {
			return writeCLIApiError(apiErr, fail)
		}
		if *jsonOutput {
			_ = protocol.WriteJSON(stdout, result)
		} else {
			for _, item := range result.Items {
				state := "active"
				if item.RevokedMS != nil {
					state = "revoked"
				} else if item.ExpiresMS <= manager.Clock.Now().UnixMilli() {
					state = "expired"
				}
				fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\t%s\n", item.ID, item.Username, item.DisplayName, item.Scope, state)
			}
		}
		return 0
	case "create":
		if *outputTokenFile == "" || strings.TrimSpace(*displayName) == "" || *expires < 5*time.Minute || *expires > store.APITokenMaxValidity || *tokenID != "" || *generation == "" || len(*idempotencyKey) < 16 || len(*idempotencyKey) > 128 {
			return fail(2, "invalid_input", "create requires --name, --expires, --output-token-file, --deployment-generation and --idempotency-key.", "fix_input")
		}
		body := apiTokenCreateBody{DisplayName: strings.TrimSpace(*displayName), ExpiresInSeconds: int64(*expires / time.Second)}
		var result store.APITokenOnce
		if apiErr := doAuthenticatedAPI(ctx, client, baseURL, http.MethodPost, "/api/v1/auth/tokens", credential, *generation, *idempotencyKey, body, &result); apiErr != nil {
			return writeCLIApiError(apiErr, fail)
		}
		if len(result.Token) < 32 || result.Record.ID == "" {
			return fail(8, "invalid_api_response", "Hub returned an invalid API token response.", "retry_later")
		}
		if err := config.WritePrivateFile(*outputTokenFile, []byte(result.Token+"\n")); err != nil {
			return fail(8, "token_file_write_failed", safeMessage(err), "fix_input")
		}
		output := authTokenCLIResult{SchemaVersion: domain.SchemaVersion, Status: "created", TokenFile: *outputTokenFile, Record: result.Record}
		if *jsonOutput {
			_ = protocol.WriteJSON(stdout, output)
		} else {
			fmt.Fprintf(stdout, "API token saved to %s. The bearer value was not printed.\n", *outputTokenFile)
		}
		return 0
	case "revoke":
		if *tokenID == "" || *outputTokenFile != "" || *displayName != "" || *expires != 0 || *generation == "" || len(*idempotencyKey) < 16 || len(*idempotencyKey) > 128 {
			return fail(2, "invalid_input", "revoke requires --token, --deployment-generation and --idempotency-key.", "fix_input")
		}
		var result apiTokenRevokeBody
		if apiErr := doAuthenticatedAPI(ctx, client, baseURL, http.MethodDelete, "/api/v1/auth/tokens/"+url.PathEscape(*tokenID), credential, *generation, *idempotencyKey, nil, &result); apiErr != nil {
			return writeCLIApiError(apiErr, fail)
		}
		if *jsonOutput {
			_ = protocol.WriteJSON(stdout, result)
		} else {
			fmt.Fprintf(stdout, "API token %s revoked.\n", result.ID)
		}
		return 0
	}
	return fail(2, "invalid_command", "Unknown API token command.", "fix_input")
}

func readPrivateBearer(path string) (string, error) {
	if err := config.ValidatePrivateFile(path); err != nil {
		return "", err
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 1025))
	if err != nil || len(data) > 1024 {
		return "", errors.New("API token file exceeds 1024 bytes")
	}
	token := strings.TrimSpace(string(data))
	if len(token) < 32 || len(token) > 512 || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("API token file contains an invalid bearer")
	}
	return token, nil
}

func (m *Manager) localAPIClient() (*http.Client, *url.URL, error) {
	address := m.ListenAddress
	if !m.ListenAddressExplicit {
		if err := config.ValidatePrivateFile(m.Paths.HubConfig); err != nil {
			return nil, nil, err
		}
		data, err := os.ReadFile(m.Paths.HubConfig)
		if err != nil {
			return nil, nil, err
		}
		if len(data) > 64<<10 {
			return nil, nil, errors.New("hub configuration exceeds bound")
		}
		var saved savedHubConfig
		if err := protocol.DecodeStrictJSON(bytes.NewReader(data), 64<<10, &saved); err != nil {
			return nil, nil, err
		}
		if saved.SchemaVersion != domain.SchemaVersion || saved.DeploymentID == "" || saved.Database != m.Paths.Database || saved.InferenceEnabled {
			return nil, nil, errors.New("hub configuration identity is invalid")
		}
		address = saved.Listen
	}
	if err := validateListenAddress(address); err != nil {
		return nil, nil, err
	}
	baseURL, _ := url.Parse("http://" + address)
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{Proxy: nil, DialContext: dialer.DialContext, DisableCompression: true, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("API redirects are disabled") }}
	return client, baseURL, nil
}

func doBearerAPI(ctx context.Context, client *http.Client, baseURL *url.URL, method, path, bearer, generation, idempotencyKey string, body, result any) *domain.APIError {
	return doAuthenticatedAPI(ctx, client, baseURL, method, path, cliAuthentication{Bearer: bearer}, generation, idempotencyKey, body, result)
}

func doAuthenticatedAPI(ctx context.Context, client *http.Client, baseURL *url.URL, method, path string, credential cliAuthentication, generation, idempotencyKey string, body, result any) *domain.APIError {
	return doBoundedAuthenticatedAPI(ctx, client, baseURL, method, path, credential, generation, idempotencyKey, body, result, 64<<10)
}

func doBoundedAuthenticatedAPI(ctx context.Context, client *http.Client, baseURL *url.URL, method, path string, credential cliAuthentication, generation, idempotencyKey string, body, result any, responseLimit int64, expectedRevision ...int64) *domain.APIError {
	return doBoundedAuthenticatedAPIBody(ctx, client, baseURL, method, path, credential, generation, idempotencyKey, body, result, 64<<10, responseLimit, expectedRevision...)
}

func doBoundedAuthenticatedAPIBody(ctx context.Context, client *http.Client, baseURL *url.URL, method, path string, credential cliAuthentication, generation, idempotencyKey string, body, result any, requestLimit, responseLimit int64, expectedRevision ...int64) *domain.APIError {
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if requestLimit < 1 || responseLimit < 1 || err != nil || int64(len(encoded)) > requestLimit {
			return &domain.APIError{Code: "invalid_input", Message: "API request exceeds its bound.", RecoveryAction: "fix_input", CLIExitCode: 2}
		}
	}
	if requestLimit < 1 || responseLimit < 1 {
		return &domain.APIError{Code: "invalid_input", Message: "API request bounds are invalid.", RecoveryAction: "fix_input", CLIExitCode: 2}
	}
	endpoint := *baseURL
	relative, err := url.ParseRequestURI(path)
	if err != nil || relative.IsAbs() || relative.Host != "" || !strings.HasPrefix(relative.Path, "/api/v1/") {
		return &domain.APIError{Code: "invalid_input", Message: "Invalid local API path.", RecoveryAction: "fix_input", CLIExitCode: 2}
	}
	endpoint.Path, endpoint.RawPath, endpoint.RawQuery = relative.Path, relative.RawPath, relative.RawQuery
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(encoded))
	if err != nil {
		return &domain.APIError{Code: "request_failed", Message: "API request could not be created.", RecoveryAction: "retry_later", CLIExitCode: 8}
	}
	credential.apply(request)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if generation != "" {
		request.Header.Set("If-Deployment-Generation", generation)
	}
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	if len(expectedRevision) > 0 {
		if len(expectedRevision) != 1 || expectedRevision[0] < 1 {
			return &domain.APIError{Code: "invalid_input", Message: "A positive expected revision is required.", RecoveryAction: "fix_input", CLIExitCode: 2}
		}
		request.Header.Set("If-Match", fmt.Sprint(expectedRevision[0]))
	}
	response, err := client.Do(request)
	if err != nil {
		return &domain.APIError{Code: "hub_unreachable", Message: "The local hub API is unreachable.", RecoveryAction: "retry_later", CLIExitCode: 5, Retryable: true}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		var apiError domain.APIError
		if protocol.DecodeStrictJSON(response.Body, 64<<10, &apiError) != nil || apiError.Code == "" || apiError.CLIExitCode < 2 || apiError.CLIExitCode > 8 {
			return &domain.APIError{Code: "invalid_api_response", Message: fmt.Sprintf("Hub rejected the request with HTTP %d.", response.StatusCode), RecoveryAction: "retry_later", CLIExitCode: 8}
		}
		return &apiError
	}
	if result == nil && response.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := protocol.DecodeStrictJSON(response.Body, responseLimit, result); err != nil {
		return &domain.APIError{Code: "invalid_api_response", Message: "Hub returned an invalid bounded response.", RecoveryAction: "retry_later", CLIExitCode: 8}
	}
	return nil
}

func writeCLIApiError(value *domain.APIError, fail cliFailure) int {
	if value == nil {
		return 0
	}
	code := value.CLIExitCode
	if code < 2 || code > 8 {
		code = 8
	}
	return fail(code, value.Code, value.Message, value.RecoveryAction)
}
