package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

const maxSignedInt64 = uint64(^uint64(0) >> 1)

var errRedirectDisabled = errors.New("redirects are disabled")

// Client talks only to one configured literal loopback endpoint. It has no
// generic request method, so callers cannot turn it into a proxy or invoke a
// mutating Ollama route.
type Client struct {
	baseURL    *url.URL
	httpClient *http.Client
	requestMu  sync.Mutex
}

func NewClient(endpoint string) (*Client, error) {
	baseURL, err := validateEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.MaxConnsPerHost = 1
	transport.MaxIdleConnsPerHost = 1
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errRedirectDisabled
			},
		},
	}, nil
}

func validateEndpoint(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, &AdapterError{Kind: ErrorInvalidTarget, Op: "endpoint", Err: err}
	}
	if parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, &AdapterError{Kind: ErrorInvalidTarget, Op: "endpoint", Err: errors.New("target must be an HTTP loopback origin without credentials, path, query, or fragment")}
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if ip == nil || !(ip.Equal(net.IPv4(127, 0, 0, 1)) || ip.Equal(net.IPv6loopback)) {
		return nil, &AdapterError{Kind: ErrorInvalidTarget, Op: "endpoint", Err: errors.New("target host must be 127.0.0.1 or ::1")}
	}
	port := parsed.Port()
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil || value == 0 {
		return nil, &AdapterError{Kind: ErrorInvalidTarget, Op: "endpoint", Err: errors.New("target requires an explicit port between 1 and 65535")}
	}
	parsed.Path = ""
	return parsed, nil
}

func (c *Client) Root(ctx context.Context) (RootObservation, error) {
	body, err := c.do(ctx, http.MethodGet, "/", nil, RootBodyLimit, "root")
	if err != nil {
		return RootObservation{}, err
	}
	message := strings.TrimSpace(string(body))
	if message != "Ollama is running" || len(message) > MaxStringBytes || !utf8.ValidString(message) {
		return RootObservation{}, &AdapterError{Kind: ErrorProtocol, Op: "root", Err: errors.New("invalid bounded root response")}
	}
	return RootObservation{Reachable: true}, nil
}

func (c *Client) Version(ctx context.Context) (RuntimeVersion, error) {
	body, err := c.do(ctx, http.MethodGet, "/api/version", nil, VersionBodyLimit, "version")
	if err != nil {
		return RuntimeVersion{}, err
	}
	var response struct {
		Version string `json:"version"`
	}
	if err := strictDecode(body, &response); err != nil {
		return RuntimeVersion{}, withOp("version", err)
	}
	if response.Version == "" {
		return RuntimeVersion{}, &AdapterError{Kind: ErrorProtocol, Op: "version", Err: errors.New("version is missing")}
	}
	if err := validateAdmittedString("version", response.Version, true); err != nil {
		return RuntimeVersion{}, &AdapterError{Kind: ErrorLimitExceeded, Op: "version", Err: err}
	}
	return RuntimeVersion{
		Version:            response.Version,
		SourcePinID:        sourcePinForVersion(response.Version),
		CompatibilityState: CompatibilityUnverified,
	}, nil
}

func (c *Client) LoadedModels(ctx context.Context) (ModelInventory, error) {
	body, err := c.do(ctx, http.MethodGet, "/api/ps", nil, InventoryBodyLimit, "loaded-models")
	if err != nil {
		return ModelInventory{}, err
	}
	return decodeModels(body, true, MaxLoadedModels)
}

func (c *Client) Tags(ctx context.Context) (ModelInventory, error) {
	body, err := c.do(ctx, http.MethodGet, "/api/tags", nil, InventoryBodyLimit, "tags")
	if err != nil {
		return ModelInventory{}, err
	}
	return decodeModels(body, false, MaxArrayItems)
}

// Show reads metadata for the already selected local model. The request body
// contains only its bounded alias; returned templates, messages, system text,
// model_info and other arbitrary fields are never admitted to ModelInfo.
func (c *Client) Show(ctx context.Context, selectedAlias string, selectedDigest *string) (ModelInfo, error) {
	if selectedAlias == "" || len(selectedAlias) > MaxStringBytes || !utf8.ValidString(selectedAlias) {
		return ModelInfo{}, &AdapterError{Kind: ErrorInvalidTarget, Op: "show", Err: errors.New("selected model alias is invalid")}
	}
	requestBody, err := json.Marshal(struct {
		Model string `json:"model"`
	}{Model: selectedAlias})
	if err != nil {
		return ModelInfo{}, &AdapterError{Kind: ErrorMalformed, Op: "show", Err: err}
	}
	body, err := c.do(ctx, http.MethodPost, "/api/show", requestBody, InventoryBodyLimit, "show")
	if err != nil {
		return ModelInfo{}, err
	}
	return decodeShow(body, selectedAlias, selectedDigest)
}

func (c *Client) do(ctx context.Context, method, path string, requestBody []byte, limit int64, op string) ([]byte, error) {
	if !c.requestMu.TryLock() {
		return nil, &AdapterError{Kind: ErrorBusy, Op: op, Err: errors.New("another request for this target is still active")}
	}
	defer c.requestMu.Unlock()

	requestContext, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	requestURL := *c.baseURL
	requestURL.Path = path
	var reader io.Reader
	if requestBody != nil {
		reader = bytes.NewReader(requestBody)
	}
	request, err := http.NewRequestWithContext(requestContext, method, requestURL.String(), reader)
	if err != nil {
		return nil, &AdapterError{Kind: ErrorInvalidTarget, Op: op, Err: err}
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "llm-monitor/ollama-readonly-v1")
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		if errors.Is(err, errRedirectDisabled) {
			return nil, &AdapterError{Kind: ErrorProtocol, Op: op, Err: err}
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, &AdapterError{Kind: ErrorTimeout, Op: op, Err: err}
		}
		return nil, &AdapterError{Kind: ErrorUnreachable, Op: op, Err: err}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, RootBodyLimit))
		return nil, &AdapterError{Kind: ErrorProtocol, Op: op, Err: fmt.Errorf("unexpected HTTP status %d", response.StatusCode)}
	}
	body, err := readBounded(response.Body, limit)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, &AdapterError{Kind: ErrorTimeout, Op: op, Err: err}
		}
		return nil, withOp(op, err)
	}
	return body, nil
}

func sourcePinForVersion(version string) string {
	switch version {
	case "0.34.0":
		return "ollama-0.34.0-source"
	case "0.12.10":
		return "ollama-0.12.10-source"
	default:
		return "runtime-version-unverified"
	}
}

func withOp(op string, err error) error {
	var adapterErr *AdapterError
	if errors.As(err, &adapterErr) {
		return &AdapterError{Kind: adapterErr.Kind, Op: op, Err: adapterErr.Err}
	}
	return &AdapterError{Kind: ErrorMalformed, Op: op, Err: err}
}
