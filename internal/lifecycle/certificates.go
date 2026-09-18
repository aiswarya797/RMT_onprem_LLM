package lifecycle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"

	"rmt.local/monitor/internal/config"
)

func ensureLocalCA(paths config.Paths, now time.Time) (bool, error) {
	all := []string{paths.CAKey, paths.CACert, paths.HubKey, paths.HubCert}
	present := 0
	for _, path := range all {
		if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm() == 0o600 {
			present++
		} else if err != nil && !os.IsNotExist(err) {
			return false, err
		}
	}
	if present == len(all) {
		return false, nil
	}
	if present != 0 {
		return false, os.ErrInvalid
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return false, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return false, err
	}
	ca := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "LLM Monitor Local CA"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return false, err
	}
	hubKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return false, err
	}
	hubSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return false, err
	}
	hub := &x509.Certificate{SerialNumber: hubSerial, Subject: pkix.Name{CommonName: "LLM Monitor Local Hub"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(1, 0, 0), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	hubDER, err := x509.CreateCertificate(rand.Reader, hub, ca, &hubKey.PublicKey, caKey)
	if err != nil {
		return false, err
	}
	caKeyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return false, err
	}
	hubKeyDER, err := x509.MarshalPKCS8PrivateKey(hubKey)
	if err != nil {
		return false, err
	}
	files := []struct {
		path string
		data []byte
	}{
		{paths.CAKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caKeyDER})},
		{paths.CACert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})},
		{paths.HubKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: hubKeyDER})},
		{paths.HubCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: hubDER})},
	}
	for _, file := range files {
		if err := config.WritePrivateFile(file.path, file.data); err != nil {
			return false, err
		}
	}
	return true, nil
}
