package remote

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/enrollment"
	"rmt.local/monitor/internal/protocol"
	"rmt.local/monitor/internal/store"
)

type remoteTestClock struct{ now time.Time }

func (c *remoteTestClock) Now() time.Time { return c.now }

func TestEnrollmentAuthenticatesBeforeDecodeAndBindsMTLSAdmission(t *testing.T) {
	clock := &remoteTestClock{now: time.Now().UTC().Truncate(time.Second)}
	authority := remoteTestAuthority(t, clock)
	st, err := store.Open(t.TempDir()+"/monitor.sqlite3", clock)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	state, _, err := st.EnsureDeployment(context.Background(), "test")
	if err != nil {
		t.Fatal(err)
	}
	bootstrapHash := strings.Repeat("f", 64)
	if err := st.PutFirstAdminBootstrap(context.Background(), bootstrapHash, clock.now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	admin, err := st.ConsumeBootstrapAndCreateAdmin(context.Background(), bootstrapHash, "admin", strings.Repeat("p", 32))
	if err != nil {
		t.Fatal(err)
	}
	actor := store.SessionRecord{User: admin, DeploymentID: state.DeploymentID, Generation: state.DeploymentGeneration, ExpiresMS: clock.now.Add(time.Hour).UnixMilli()}
	token, tokenHash, _ := enrollment.NewToken()
	hostID, _ := domain.NewUUID()
	_, err = st.ReserveCollectorEnrollment(context.Background(), actor, tokenHash, hostID, "Remote Mac", "https://monitor.example:9444", authority.FingerprintSHA256())
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(st, authority)
	if err != nil {
		t.Fatal(err)
	}

	request := func(token string, body []byte) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/collector/v1/enrollments", bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Idempotency-Key", "00000000-0000-4000-8000-000000000001")
		handler.ServeHTTP(recorder, r)
		return recorder
	}
	if got := request(strings.Repeat("x", 43), []byte(`{"not":`)); got.Code != http.StatusUnauthorized {
		t.Fatalf("unknown token malformed body status=%d", got.Code)
	}
	if got := request(token, []byte(`{"not":`)); got.Code != http.StatusUnprocessableEntity {
		t.Fatalf("valid token malformed body status=%d", got.Code)
	}
	generated, err := enrollment.GenerateKeyAndCSR(hostID)
	if err != nil {
		t.Fatal(err)
	}
	installationID, _ := domain.NewUUID()
	exchange := enrollment.ExchangeRequest{Protocol: domain.ProtocolVersion, DeploymentID: state.DeploymentID, HostID: hostID, InstallationID: installationID, CSRPEM: string(generated.CSRPEM), HubCAFingerprintSHA256: authority.FingerprintSHA256()}
	body, _ := json.Marshal(exchange)
	first := request(token, body)
	if first.Code != http.StatusOK {
		t.Fatalf("exchange status=%d body=%s", first.Code, first.Body.String())
	}
	var result enrollment.ExchangeResult
	if err := json.Unmarshal(first.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	retry := request(token, body)
	if retry.Code != http.StatusOK || retry.Body.String() != first.Body.String() {
		t.Fatalf("lost-response retry status=%d equal=%t", retry.Code, retry.Body.String() == first.Body.String())
	}
	changed := exchange
	changed.InstallationID, _ = domain.NewUUID()
	changedBody, _ := json.Marshal(changed)
	if got := request(token, changedBody); got.Code != http.StatusConflict {
		t.Fatalf("changed retry status=%d", got.Code)
	}

	leafBlock, _ := pem.Decode([]byte(result.CertificatePEM))
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	tlsState := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, authorityCertificate(t, authority)}}}
	sessionRequest := protocol.SessionActivation{Protocol: domain.ProtocolVersion, DeploymentID: state.DeploymentID, HostID: hostID, SecurityGeneration: state.DeploymentGeneration, ActivationRequestID: fixtureUUID(7), CollectorBootID: fixtureUUID(8), ExpectedPreviousGeneration: 0}
	sessionBody, _ := json.Marshal(sessionRequest)
	activate := func() *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/collector/v1/sessions", bytes.NewReader(sessionBody))
		r.TLS = tlsState
		handler.ServeHTTP(recorder, r)
		return recorder
	}
	if got := activate(); got.Code != http.StatusOK {
		t.Fatalf("mTLS activation status=%d body=%s", got.Code, got.Body.String())
	}
	hostSourceID := fixtureUUID(9)
	inventory := protocol.CollectorInventory{Protocol: domain.ProtocolVersion, DeploymentID: state.DeploymentID, HostID: hostID, SecurityGeneration: state.DeploymentGeneration, SessionGeneration: 1, CollectorBootID: sessionRequest.CollectorBootID, InventoryRevision: strings.Repeat("b", 64), Sources: []protocol.InventorySource{{SourceID: hostSourceID, Kind: "host", CapabilityRevision: domain.RegistryRevision, Active: true}}, Targets: []protocol.InventoryTarget{}, Models: []protocol.InventoryModel{}}
	inventoryBody, _ := json.Marshal(inventory)
	inventoryRecorder := httptest.NewRecorder()
	inventoryRequest := httptest.NewRequest(http.MethodPost, "/collector/v1/inventory", bytes.NewReader(inventoryBody))
	inventoryRequest.TLS = tlsState
	handler.ServeHTTP(inventoryRecorder, inventoryRequest)
	if inventoryRecorder.Code != http.StatusOK {
		t.Fatalf("mTLS inventory status=%d body=%s", inventoryRecorder.Code, inventoryRecorder.Body.String())
	}
	oldStatus := protocol.SourceStatus{Protocol: domain.ProtocolVersion, DeploymentID: state.DeploymentID, HostID: hostID, SecurityGeneration: state.DeploymentGeneration, SessionGeneration: 1, CollectorBootID: sessionRequest.CollectorBootID, Sequence: 0, ObservedWallMS: clock.now.Add(-61 * time.Second).UnixMilli(), Heartbeat: "fresh", Sources: []protocol.SourceState{{SourceID: hostSourceID, State: "fresh", FailureCount: 0}}, LossIntervals: []protocol.LossInterval{}}
	statusBody, _ := json.Marshal(oldStatus)
	statusRecorder := httptest.NewRecorder()
	statusRequest := httptest.NewRequest(http.MethodPost, "/collector/v1/status", bytes.NewReader(statusBody))
	statusRequest.TLS = tlsState
	handler.ServeHTTP(statusRecorder, statusRequest)
	if statusRecorder.Code != http.StatusGone {
		t.Fatalf("uncommitted old status=%d body=%s", statusRecorder.Code, statusRecorder.Body.String())
	}
	clock.now = clock.now.Add(61 * 24 * time.Hour)
	renewalCSR, err := enrollment.CSRForPrivateKey(hostID, generated.PrivateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	renewal := enrollment.ExchangeRequest{Protocol: domain.ProtocolVersion, DeploymentID: state.DeploymentID, HostID: hostID, InstallationID: installationID, CSRPEM: string(renewalCSR), HubCAFingerprintSHA256: authority.FingerprintSHA256()}
	renewalBody, _ := json.Marshal(renewal)
	renew := func() *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/collector/v1/credentials/renew", bytes.NewReader(renewalBody))
		request.Header.Set("Idempotency-Key", "00000000-0000-4000-8000-000000000011")
		request.TLS = tlsState
		handler.ServeHTTP(recorder, request)
		return recorder
	}
	firstRenewal := renew()
	if firstRenewal.Code != http.StatusOK {
		t.Fatalf("credential renewal status=%d body=%s", firstRenewal.Code, firstRenewal.Body.String())
	}
	retryRenewal := renew()
	if retryRenewal.Code != http.StatusOK || retryRenewal.Body.String() != firstRenewal.Body.String() {
		t.Fatalf("credential renewal retry status=%d equal=%t", retryRenewal.Code, retryRenewal.Body.String() == firstRenewal.Body.String())
	}
	oldCredentialRequest := func() *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/collector/v1/time", nil)
		request.TLS = tlsState
		handler.ServeHTTP(recorder, request)
		return recorder
	}
	clock.now = clock.now.Add(6 * 24 * time.Hour)
	if got := oldCredentialRequest(); got.Code != http.StatusOK {
		t.Fatalf("old credential rejected during overlap status=%d", got.Code)
	}
	clock.now = clock.now.Add(2 * 24 * time.Hour)
	if got := oldCredentialRequest(); got.Code != http.StatusUnauthorized {
		t.Fatalf("old credential accepted after overlap status=%d", got.Code)
	}
	var renewed enrollment.ExchangeResult
	if err := json.Unmarshal(firstRenewal.Body.Bytes(), &renewed); err != nil {
		t.Fatal(err)
	}
	renewedBlock, _ := pem.Decode([]byte(renewed.CertificatePEM))
	renewedLeaf, err := x509.ParseCertificate(renewedBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	tlsState = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{renewedLeaf}, VerifiedChains: [][]*x509.Certificate{{renewedLeaf, authorityCertificate(t, authority)}}}
	if err := st.RevokeCollectorCredentials(context.Background(), actor, hostID); err != nil {
		t.Fatal(err)
	}
	if got := activate(); got.Code != http.StatusUnauthorized {
		t.Fatalf("revoked certificate status=%d", got.Code)
	}
}

func TestPairingBootstrapReturnsPinnedEnrollmentFile(t *testing.T) {
	clock := &remoteTestClock{now: time.Now().UTC().Truncate(time.Second)}
	authority := remoteTestAuthority(t, clock)
	st, err := store.Open(t.TempDir()+"/monitor.sqlite3", clock)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	state, _, err := st.EnsureDeployment(context.Background(), "test")
	if err != nil {
		t.Fatal(err)
	}
	bootstrapHash := strings.Repeat("e", 64)
	if err := st.PutFirstAdminBootstrap(context.Background(), bootstrapHash, clock.now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	admin, err := st.ConsumeBootstrapAndCreateAdmin(context.Background(), bootstrapHash, "admin", strings.Repeat("p", 32))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(st, authority)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	token, tokenHash, err := enrollment.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	hostID, err := domain.NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	actor := store.SessionRecord{User: admin, DeploymentID: state.DeploymentID, Generation: state.DeploymentGeneration, ExpiresMS: clock.now.Add(time.Hour).UnixMilli()}
	if _, err := st.ReserveCollectorEnrollment(context.Background(), actor, tokenHash, hostID, "Remote Mac", server.URL, authority.FingerprintSHA256()); err != nil {
		t.Fatal(err)
	}

	file, err := enrollment.FetchBootstrapFile(context.Background(), server.URL, token)
	if err != nil {
		t.Fatal(err)
	}
	if file.DeploymentID != state.DeploymentID || file.HostID != hostID || file.HubURL != server.URL || file.Token != token || file.HubCAFingerprintSHA256 != authority.FingerprintSHA256() {
		t.Fatalf("pairing file=%#v", file)
	}
	if err := enrollment.ValidateFile(file, time.Now()); err != nil {
		t.Fatalf("returned file is not locally valid: %v", err)
	}
	if _, err := enrollment.FetchBootstrapFile(context.Background(), server.URL, strings.Repeat("x", 40)); err == nil {
		t.Fatal("unknown pairing code was accepted")
	}
}

func remoteTestAuthority(t *testing.T, clock *remoteTestClock) *enrollment.Authority {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Remote test CA"}, NotBefore: clock.now.Add(-time.Hour), NotAfter: clock.now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	authority, err := enrollment.NewAuthority(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), clock)
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func authorityCertificate(t *testing.T, authority *enrollment.Authority) *x509.Certificate {
	t.Helper()
	// The leaf already passed the authority signature during issuance. A nonempty
	// VerifiedChains marker models net/http after TLS verification for this
	// handler-level revocation/ownership test.
	return &x509.Certificate{Subject: pkix.Name{CommonName: authority.FingerprintSHA256()}}
}

func fixtureUUID(suffix byte) string {
	return "00000000-0000-4000-8000-00000000000" + string('0'+suffix)
}
