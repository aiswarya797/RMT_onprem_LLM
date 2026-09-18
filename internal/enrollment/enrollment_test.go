package enrollment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"rmt.local/monitor/internal/domain"
)

type testClock struct{ now time.Time }

func (c testClock) Now() time.Time { return c.now }

func testAuthority(t *testing.T, now time.Time) (*Authority, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	authority, err := NewAuthority(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), testClock{now})
	if err != nil {
		t.Fatal(err)
	}
	return authority, certificatePEM
}

func TestAuthorityBindsCollectorTupleAndGeneratedKey(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	authority, _ := testAuthority(t, now)
	identity := Identity{DeploymentID: "10000000-0000-4000-8000-000000000001", HostID: "20000000-0000-4000-8000-000000000001", SecurityGeneration: "30000000-0000-4000-8000-000000000001"}
	generated, err := GenerateKeyAndCSR(identity.HostID)
	if err != nil {
		t.Fatal(err)
	}
	result, serial, fingerprint, err := authority.SignCollectorCSR(identity, string(generated.CSRPEM))
	if err != nil {
		t.Fatal(err)
	}
	if serial == "" || len(fingerprint) != 64 || result.ExpiresMS != now.Add(CertificateValidity).UnixMilli() || result.HubCAFingerprintSHA256 != authority.FingerprintSHA256() {
		t.Fatalf("result=%+v serial=%s fingerprint=%s", result, serial, fingerprint)
	}
	block, _ := pem.Decode([]byte(result.CertificatePEM))
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCollectorIdentity(certificate)
	if err != nil || parsed != identity {
		t.Fatalf("identity=%+v err=%v", parsed, err)
	}
	wrong := identity
	wrong.HostID = "20000000-0000-4000-8000-000000000002"
	if _, _, _, err := authority.SignCollectorCSR(wrong, string(generated.CSRPEM)); err == nil {
		t.Fatal("CSR common name was rebound to another host")
	}
}

func TestEnrollmentFileRequiresExactCAExpiryAndExplicitHTTPSPort(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	authority, caPEM := testAuthority(t, now)
	file := File{SchemaVersion: domain.SchemaVersion, DeploymentID: "10000000-0000-4000-8000-000000000001", HostID: "20000000-0000-4000-8000-000000000001", HubURL: "https://monitor.example:9444", HubCAFingerprintSHA256: authority.FingerprintSHA256(), HubCACertificatePEM: string(caPEM), Token: strings.Repeat("t", 43), ExpiresMS: now.Add(TokenValidity).UnixMilli()}
	if err := ValidateFile(file, now); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*File){
		"wrong fingerprint": func(v *File) { v.HubCAFingerprintSHA256 = strings.Repeat("0", 64) },
		"expired":           func(v *File) { v.ExpiresMS = now.UnixMilli() },
		"cleartext":         func(v *File) { v.HubURL = "http://monitor.example:9444" },
		"implicit port":     func(v *File) { v.HubURL = "https://monitor.example" },
		"userinfo":          func(v *File) { v.HubURL = "https://user@monitor.example:9444" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := file
			mutate(&changed)
			if ValidateFile(changed, now) == nil {
				t.Fatal("invalid enrollment file accepted")
			}
		})
	}
}
