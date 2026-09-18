package lifecycle

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"time"

	"rmt.local/monitor/internal/collector/remote"
	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/enrollment"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

func ValidateCollectorListenAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("collector listener requires a literal private IP and explicit port")
	}
	ip, err := netip.ParseAddr(host)
	number, portErr := strconv.Atoi(port)
	if err != nil || ip.Zone() != "" || (!ip.IsLoopback() && !ip.IsPrivate()) || portErr != nil || number < 1 || number > 65535 || port != strconv.Itoa(number) {
		return errors.New("collector listener requires a literal loopback or private IP and port 1–65535")
	}
	return nil
}

func (m *Manager) validateCollectorListenChange(state domain.DeploymentState, created bool) error {
	if m.CollectorListenAddress != "" {
		if err := ValidateCollectorListenAddress(m.CollectorListenAddress); err != nil {
			return err
		}
		if m.CollectorListenAddress == m.ListenAddress {
			return errors.New("collector TLS and browser listeners require different ports")
		}
	}
	if !created && m.collectorListenChanged && (m.ConfirmDeployment != state.DeploymentID || m.ConfirmGeneration != state.DeploymentGeneration || !state.MutationsAllowed) {
		return errors.New("changing the collector listener requires current --confirm-deployment and --deployment-generation")
	}
	return nil
}

func readTLSFile(path string) ([]byte, error) {
	if err := config.ValidatePrivateFile(path); err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() > 32<<10 {
		return nil, errors.New("TLS file is unavailable or exceeds its limit")
	}
	return os.ReadFile(path)
}

// Reuse the hub key and CA. A leaf-only replacement is one durable atomic file
// update; interruption cannot install a mismatched private key/certificate pair.
func ensureRemoteHubCertificate(paths config.Paths, address string, now time.Time) error {
	if err := ValidateCollectorListenAddress(address); err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(address)
	caPEM, err := readTLSFile(paths.CACert)
	if err != nil {
		return err
	}
	caKeyPEM, err := readTLSFile(paths.CAKey)
	if err != nil {
		return err
	}
	if _, err := enrollment.NewAuthority(caPEM, caKeyPEM, fixedCertificateClock{now}); err != nil {
		return err
	}
	keyPEM, err := readTLSFile(paths.HubKey)
	if err != nil {
		return err
	}
	certPEM, err := readTLSFile(paths.HubCert)
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return errors.New("existing hub key and certificate require recovery")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return errors.New("invalid hub CA")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil && leaf.NotAfter.After(now.Add(30*24*time.Hour)) {
		return nil
	}
	caBlock, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return err
	}
	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return errors.New("invalid CA key")
	}
	keyValue, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}
	caKey, ok := keyValue.(*ecdsa.PrivateKey)
	if !ok {
		return errors.New("unsupported CA key")
	}
	hubKey, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return errors.New("unsupported hub key")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	expires := now.AddDate(1, 0, 0)
	if expires.After(ca.NotAfter) {
		expires = ca.NotAfter
	}
	if !expires.After(now.Add(30 * 24 * time.Hour)) {
		return errors.New("CA renewal required before enabling collectors")
	}
	certificate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "LLM Monitor Collector Endpoint"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: expires, IPAddresses: []net.IP{net.ParseIP(host)}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, certificate, ca, &hubKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	return config.WritePrivateFile(paths.HubCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

type fixedCertificateClock struct{ now time.Time }

func (c fixedCertificateClock) Now() time.Time { return c.now }

// RemoteCollectorServer returns nil when remote collection was not explicitly
// enabled by the installing user. It never opens a listener by itself.
func RemoteCollectorServer(paths config.Paths, st *store.Store, clock domain.Clock) (*http.Server, error) {
	if !config.ExperimentalFeaturesEnabled() {
		return nil, nil
	}
	data, err := readTLSFile(paths.HubConfig)
	if err != nil {
		return nil, err
	}
	var saved savedHubConfig
	if err := protocol.DecodeStrictJSON(bytes.NewReader(data), 32<<10, &saved); err != nil {
		return nil, err
	}
	if saved.CollectorListen == "" {
		return nil, nil
	}
	if err := ValidateCollectorListenAddress(saved.CollectorListen); err != nil {
		return nil, err
	}
	caPEM, err := readTLSFile(paths.CACert)
	if err != nil {
		return nil, err
	}
	caKeyPEM, err := readTLSFile(paths.CAKey)
	if err != nil {
		return nil, err
	}
	authority, err := enrollment.NewAuthority(caPEM, caKeyPEM, clock)
	if err != nil {
		return nil, err
	}
	certPEM, err := readTLSFile(paths.HubCert)
	if err != nil {
		return nil, err
	}
	keyPEM, err := readTLSFile(paths.HubKey)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("invalid collector CA")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(saved.CollectorListen)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host, CurrentTime: clock.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, fmt.Errorf("collector endpoint certificate requires local setup: %w", err)
	}
	tlsConfig, err := remote.ServerTLSConfig(pair, roots)
	if err != nil {
		return nil, err
	}
	handler, err := remote.NewHandler(st, authority)
	if err != nil {
		return nil, err
	}
	return remote.NewServer(saved.CollectorListen, handler, tlsConfig)
}
