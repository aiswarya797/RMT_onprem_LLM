package enrollment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"rmt.local/monitor/internal/domain"
)

const (
	TokenValidity       = 10 * time.Minute
	CertificateValidity = 90 * 24 * time.Hour
	RenewBefore         = 30 * 24 * time.Hour
	RotationOverlap     = 7 * 24 * time.Hour
)

var ErrInvalidCertificateIdentity = errors.New("invalid collector certificate identity")

type Identity struct {
	DeploymentID       string
	HostID             string
	SecurityGeneration string
}

type ExchangeRequest struct {
	Protocol               string `json:"protocol"`
	DeploymentID           string `json:"deployment_id"`
	HostID                 string `json:"host_id"`
	InstallationID         string `json:"installation_id"`
	CSRPEM                 string `json:"csr_pem"`
	HubCAFingerprintSHA256 string `json:"hub_ca_fingerprint_sha256"`
}

type ExchangeResult struct {
	Protocol               string   `json:"protocol"`
	DeploymentID           string   `json:"deployment_id"`
	HostID                 string   `json:"host_id"`
	SecurityGeneration     string   `json:"security_generation"`
	CertificatePEM         string   `json:"certificate_pem"`
	CertificateChainPEM    []string `json:"certificate_chain_pem"`
	ExpiresMS              int64    `json:"expires_ms"`
	HubCAFingerprintSHA256 string   `json:"hub_ca_fingerprint_sha256"`
}

type GeneratedKey struct {
	PrivateKeyPEM []byte
	CSRPEM        []byte
}

type Authority struct {
	certificate    *x509.Certificate
	privateKey     *ecdsa.PrivateKey
	certificatePEM string
	clock          domain.Clock
}

func NewToken() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate enrollment token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	return token, HashToken(token), nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func FingerprintCertificatePEM(certificatePEM []byte) (string, error) {
	block, rest := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return "", errors.New("invalid certificate PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}
	sum := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(sum[:]), nil
}

func GenerateKeyAndCSR(hostID string) (GeneratedKey, error) {
	if !validUUID(hostID) {
		return GeneratedKey{}, errors.New("invalid reserved host ID")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return GeneratedKey{}, fmt.Errorf("generate collector key: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return GeneratedKey{}, fmt.Errorf("marshal collector key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: hostID}}, key)
	if err != nil {
		return GeneratedKey{}, fmt.Errorf("create collector CSR: %w", err)
	}
	return GeneratedKey{
		PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		CSRPEM:        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
	}, nil
}

func CSRForPrivateKey(hostID string, privateKeyPEM []byte) ([]byte, error) {
	if !validUUID(hostID) {
		return nil, errors.New("invalid reserved host ID")
	}
	keyBlock, rest := pem.Decode(privateKeyPEM)
	if keyBlock == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("invalid collector private key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	key, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("collector private key must be ECDSA P-256")
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: hostID}}, key)
	if err != nil {
		return nil, fmt.Errorf("create collector CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

func NewAuthority(certificatePEM, privateKeyPEM []byte, clock domain.Clock) (*Authority, error) {
	certBlock, certRest := pem.Decode(certificatePEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" || len(strings.TrimSpace(string(certRest))) != 0 {
		return nil, errors.New("invalid CA certificate PEM")
	}
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("certificate is not a signing CA")
	}
	keyBlock, keyRest := pem.Decode(privateKeyPEM)
	if keyBlock == nil || len(strings.TrimSpace(string(keyRest))) != 0 {
		return nil, errors.New("invalid CA private key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA private key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || !key.PublicKey.Equal(certificate.PublicKey) {
		return nil, errors.New("CA key does not match certificate")
	}
	if clock == nil {
		clock = domain.RealClock{}
	}
	return &Authority{certificate: certificate, privateKey: key, certificatePEM: string(certificatePEM), clock: clock}, nil
}

func (a *Authority) FingerprintSHA256() string {
	sum := sha256.Sum256(a.certificate.Raw)
	return hex.EncodeToString(sum[:])
}

// CertificatePEM is used only for the one-use pairing bootstrap response.
// The collector pins this exact certificate before it attempts the mTLS
// enrollment exchange.
func (a *Authority) CertificatePEM() string {
	if a == nil {
		return ""
	}
	return a.certificatePEM
}

func (a *Authority) SignCollectorCSR(identity Identity, csrPEM string) (ExchangeResult, string, string, error) {
	if !validIdentity(identity) {
		return ExchangeResult{}, "", "", ErrInvalidCertificateIdentity
	}
	block, rest := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(strings.TrimSpace(string(rest))) != 0 {
		return ExchangeResult{}, "", "", errors.New("invalid collector CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return ExchangeResult{}, "", "", errors.New("invalid collector CSR signature")
	}
	publicKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return ExchangeResult{}, "", "", errors.New("collector CSR must use ECDSA P-256")
	}
	if csr.Subject.CommonName != identity.HostID || len(csr.DNSNames) != 0 || len(csr.IPAddresses) != 0 || len(csr.URIs) != 0 || len(csr.EmailAddresses) != 0 || len(csr.Extensions) != 0 || len(csr.ExtraExtensions) != 0 {
		return ExchangeResult{}, "", "", errors.New("collector CSR contains unsupported identity fields")
	}
	serialBytes := make([]byte, 16)
	if _, err := rand.Read(serialBytes); err != nil {
		return ExchangeResult{}, "", "", fmt.Errorf("generate certificate serial: %w", err)
	}
	serial := new(big.Int).SetBytes(serialBytes)
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	identityURI, _ := url.Parse(identityURN(identity))
	now := a.clock.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: identity.HostID, Organization: []string{identity.DeploymentID}, OrganizationalUnit: []string{identity.SecurityGeneration}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(CertificateValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:                  []*url.URL{identityURI},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.certificate, csr.PublicKey, a.privateKey)
	if err != nil {
		return ExchangeResult{}, "", "", fmt.Errorf("sign collector certificate: %w", err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	fingerprint, _ := FingerprintCertificatePEM(leafPEM)
	return ExchangeResult{
		Protocol: domain.ProtocolVersion, DeploymentID: identity.DeploymentID, HostID: identity.HostID,
		SecurityGeneration: identity.SecurityGeneration, CertificatePEM: string(leafPEM),
		CertificateChainPEM: []string{a.certificatePEM}, ExpiresMS: template.NotAfter.UnixMilli(),
		HubCAFingerprintSHA256: a.FingerprintSHA256(),
	}, serial.Text(16), fingerprint, nil
}

func ParseCollectorIdentity(certificate *x509.Certificate) (Identity, error) {
	if certificate == nil || len(certificate.URIs) != 1 || len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		return Identity{}, ErrInvalidCertificateIdentity
	}
	parts := strings.Split(certificate.URIs[0].String(), ":")
	if len(parts) != 6 || parts[0] != "urn" || parts[1] != "rmt" || parts[2] != "collector" {
		return Identity{}, ErrInvalidCertificateIdentity
	}
	identity := Identity{DeploymentID: parts[3], HostID: parts[4], SecurityGeneration: parts[5]}
	if !validIdentity(identity) || certificate.Subject.CommonName != identity.HostID || len(certificate.Subject.Organization) != 1 || certificate.Subject.Organization[0] != identity.DeploymentID || len(certificate.Subject.OrganizationalUnit) != 1 || certificate.Subject.OrganizationalUnit[0] != identity.SecurityGeneration {
		return Identity{}, ErrInvalidCertificateIdentity
	}
	return identity, nil
}

func CertificateFingerprint(certificate *x509.Certificate) string {
	if certificate == nil {
		return ""
	}
	sum := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(sum[:])
}

func identityURN(identity Identity) string {
	return "urn:rmt:collector:" + identity.DeploymentID + ":" + identity.HostID + ":" + identity.SecurityGeneration
}

func validIdentity(identity Identity) bool {
	return validUUID(identity.DeploymentID) && validUUID(identity.HostID) && validUUID(identity.SecurityGeneration)
}

func validUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, r := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if r != '-' {
				return false
			}
			continue
		}
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return value[14] >= '1' && value[14] <= '5' && strings.ContainsRune("89abAB", rune(value[19]))
}
