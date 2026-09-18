package enrollment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
)

type File struct {
	SchemaVersion          string `json:"schema_version"`
	DeploymentID           string `json:"deployment_id"`
	HostID                 string `json:"host_id"`
	HubURL                 string `json:"hub_url"`
	HubCAFingerprintSHA256 string `json:"hub_ca_fingerprint_sha256"`
	HubCACertificatePEM    string `json:"hub_ca_certificate_pem"`
	Token                  string `json:"token"`
	ExpiresMS              int64  `json:"expires_ms"`
}

type RemoteConfig struct {
	SchemaVersion          string `json:"schema_version"`
	DeploymentID           string `json:"deployment_id"`
	DeploymentGeneration   string `json:"deployment_generation"`
	HostID                 string `json:"host_id"`
	InstallationID         string `json:"installation_id"`
	HubURL                 string `json:"hub_url"`
	HubCAFingerprintSHA256 string `json:"hub_ca_fingerprint_sha256"`
	CertificateExpiresMS   int64  `json:"certificate_expires_ms"`
}

type Client struct {
	httpClient    *http.Client
	baseURL       *url.URL
	caPEM         []byte
	caFingerprint string
}

func ValidateFile(file File, now time.Time) error {
	return validateFile(file, now, true)
}

func validateFile(file File, now time.Time, requireFresh bool) error {
	if file.SchemaVersion != domain.SchemaVersion || !validUUID(file.DeploymentID) || !validUUID(file.HostID) || !validSHA256(file.HubCAFingerprintSHA256) || len(file.Token) < 32 || len(file.Token) > 256 || strings.ContainsAny(file.Token, " \t\r\n") {
		return errors.New("invalid enrollment file identity")
	}
	if file.ExpiresMS <= 0 || (requireFresh && (file.ExpiresMS <= now.UnixMilli() || file.ExpiresMS > now.Add(TokenValidity).UnixMilli())) {
		return errors.New("enrollment file expired or outside the ten-minute window")
	}
	parsed, err := parseHubURL(file.HubURL)
	if err != nil {
		return err
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return errors.New("hub URL must not contain a path")
	}
	fingerprint, err := FingerprintCertificatePEM([]byte(file.HubCACertificatePEM))
	if err != nil || fingerprint != file.HubCAFingerprintSHA256 {
		return errors.New("hub CA certificate does not match reviewed fingerprint")
	}
	return nil
}

func NewClient(file File, now time.Time) (*Client, error) {
	return newClient(file, now, true)
}

// FetchBootstrapFile performs the single trust-bootstrap request used by the
// generated collector pairing command. At this point the collector has not
// received the hub CA yet, so the bounded request cannot use normal server
// verification. The response immediately supplies and validates the CA
// fingerprint; every subsequent request uses NewClient with pinned roots.
func FetchBootstrapFile(ctx context.Context, hubURL, token string) (File, error) {
	var file File
	requested, err := parseHubURL(hubURL)
	if err != nil {
		return file, err
	}
	if len(token) < 32 || len(token) > 256 || strings.ContainsAny(token, " \t\r\n") {
		return file, errors.New("invalid pairing code")
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{
		Proxy:               nil,
		DialContext:         dialer.DialContext,
		DisableCompression:  true,
		MaxConnsPerHost:     1,
		MaxIdleConnsPerHost: 1,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			ServerName:         requested.Hostname(),
			InsecureSkipVerify: true, // The one-use response is the reviewed CA bootstrap; later traffic is pinned.
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("pairing redirects are disabled")
		},
	}
	defer transport.CloseIdleConnections()
	endpoint := *requested
	endpoint.Path = "/collector/v1/bootstrap"
	endpoint.RawPath = ""
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return file, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Encoding", "identity")
	response, err := client.Do(request)
	if err != nil {
		return file, fmt.Errorf("could not reach the master at %s: %w", requested.Host, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return file, fmt.Errorf("pairing request rejected with HTTP %d", response.StatusCode)
	}
	if err := protocol.DecodeStrictJSON(io.LimitReader(response.Body, (64<<10)+1), 64<<10, &file); err != nil {
		return file, err
	}
	if err := ValidateFile(file, time.Now()); err != nil {
		return file, err
	}
	returned, err := parseHubURL(file.HubURL)
	if err != nil || !strings.EqualFold(returned.Scheme, requested.Scheme) || !strings.EqualFold(returned.Hostname(), requested.Hostname()) || returned.Port() != requested.Port() {
		return File{}, errors.New("pairing response changed the reviewed master endpoint")
	}
	return file, nil
}

// NewRetryClient validates every pinned identity field but lets the hub decide
// whether an expired one-use token is still eligible for its exact durable
// receipt. It is only used with a persisted enrollment attempt.
func NewRetryClient(file File, now time.Time) (*Client, error) {
	return newClient(file, now, false)
}

func newClient(file File, now time.Time, requireFresh bool) (*Client, error) {
	if err := validateFile(file, now, requireFresh); err != nil {
		return nil, err
	}
	baseURL, _ := parseHubURL(file.HubURL)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(file.HubCACertificatePEM)) {
		return nil, errors.New("invalid hub CA certificate")
	}
	serverName := baseURL.Hostname()
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{
		Proxy:               nil,
		DialContext:         dialer.DialContext,
		DisableCompression:  true,
		MaxConnsPerHost:     1,
		MaxIdleConnsPerHost: 1,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: serverName},
	}
	return &Client{httpClient: &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("enrollment redirects are disabled") }}, baseURL: baseURL, caPEM: []byte(file.HubCACertificatePEM), caFingerprint: file.HubCAFingerprintSHA256}, nil
}

func (c *Client) Close() {
	if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

func (c *Client) Exchange(ctx context.Context, file File, installationID string, generated GeneratedKey, idempotencyKey string) (ExchangeResult, error) {
	if c == nil || c.httpClient == nil || !validUUID(installationID) || len(idempotencyKey) < 16 || len(idempotencyKey) > 128 {
		return ExchangeResult{}, errors.New("invalid enrollment exchange input")
	}
	requestValue := ExchangeRequest{Protocol: domain.ProtocolVersion, DeploymentID: file.DeploymentID, HostID: file.HostID, InstallationID: installationID, CSRPEM: string(generated.CSRPEM), HubCAFingerprintSHA256: file.HubCAFingerprintSHA256}
	body, err := json.Marshal(requestValue)
	if err != nil || len(body) > 32<<10 {
		return ExchangeResult{}, errors.New("enrollment request exceeds bound")
	}
	endpoint := *c.baseURL
	endpoint.Path = "/collector/v1/enrollments"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return ExchangeResult{}, err
	}
	request.Header.Set("Authorization", "Bearer "+file.Token)
	request.Header.Set("Idempotency-Key", idempotencyKey)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Content-Encoding", "identity")
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return ExchangeResult{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ExchangeResult{}, fmt.Errorf("enrollment rejected with HTTP %d", response.StatusCode)
	}
	var result ExchangeResult
	if err := protocol.DecodeStrictJSON(response.Body, 64<<10, &result); err != nil {
		return ExchangeResult{}, err
	}
	if err := verifyExchangeResult(file, installationID, generated.PrivateKeyPEM, result); err != nil {
		return ExchangeResult{}, err
	}
	return result, nil
}

func verifyExchangeResult(file File, installationID string, privateKeyPEM []byte, result ExchangeResult) error {
	if result.Protocol != domain.ProtocolVersion || result.DeploymentID != file.DeploymentID || result.HostID != file.HostID || !validUUID(result.SecurityGeneration) || result.HubCAFingerprintSHA256 != file.HubCAFingerprintSHA256 || result.ExpiresMS <= time.Now().UnixMilli() || len(result.CertificateChainPEM) < 1 || len(result.CertificateChainPEM) > 4 {
		return errors.New("enrollment response conflicts with reviewed identity")
	}
	if result.CertificateChainPEM[0] != string(file.HubCACertificatePEM) {
		return errors.New("enrollment response changed the pinned CA")
	}
	leafBlock, rest := pem.Decode([]byte(result.CertificatePEM))
	if leafBlock == nil || leafBlock.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return errors.New("invalid collector certificate")
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil || leaf.NotAfter.UnixMilli() != result.ExpiresMS {
		return errors.New("collector certificate expiry mismatch")
	}
	identity, err := ParseCollectorIdentity(leaf)
	if err != nil || identity.DeploymentID != file.DeploymentID || identity.HostID != file.HostID || identity.SecurityGeneration != result.SecurityGeneration {
		return errors.New("collector certificate identity mismatch")
	}
	keyBlock, keyRest := pem.Decode(privateKeyPEM)
	if keyBlock == nil || len(strings.TrimSpace(string(keyRest))) != 0 {
		return errors.New("invalid generated collector key")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	privateKey, ok := parsedKey.(*ecdsa.PrivateKey)
	if err != nil || !ok || !privateKey.PublicKey.Equal(leaf.PublicKey) {
		return errors.New("collector certificate does not match generated key")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(file.HubCACertificatePEM)) {
		return errors.New("invalid pinned CA")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return errors.New("collector certificate chain verification failed")
	}
	_ = installationID // installation identity is request-bound in the durable receipt, not encoded into the certificate.
	return nil
}

// VerifyCredentialResult validates a renewed certificate against the already
// pinned remote configuration and the collector's existing private key.
func VerifyCredentialResult(remote RemoteConfig, privateKeyPEM, caPEM []byte, result ExchangeResult, now time.Time) error {
	file := File{
		SchemaVersion: domain.SchemaVersion, DeploymentID: remote.DeploymentID, HostID: remote.HostID,
		HubURL: remote.HubURL, HubCAFingerprintSHA256: remote.HubCAFingerprintSHA256,
		HubCACertificatePEM: string(caPEM), Token: strings.Repeat("x", 32), ExpiresMS: now.Add(TokenValidity).UnixMilli(),
	}
	if err := verifyExchangeResult(file, remote.InstallationID, privateKeyPEM, result); err != nil {
		return err
	}
	if result.SecurityGeneration != remote.DeploymentGeneration || result.ExpiresMS <= now.UnixMilli() {
		return errors.New("renewed collector certificate conflicts with active generation")
	}
	return nil
}

func parseHubURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Port() == "" {
		return nil, errors.New("hub URL must be an explicit https host and port")
	}
	if parsed.Hostname() == "" || strings.ContainsAny(parsed.Hostname(), "\x00/\\") {
		return nil, errors.New("invalid hub host")
	}
	return parsed, nil
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}
