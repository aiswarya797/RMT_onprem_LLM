package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/enrollment"
)

type enrollmentTestClock struct{ now time.Time }

func (c *enrollmentTestClock) Now() time.Time { return c.now }

func newEnrollmentStore(t *testing.T) (*Store, *enrollmentTestClock, SessionRecord) {
	t.Helper()
	clock := &enrollmentTestClock{now: time.Now().UTC().Truncate(time.Second)}
	st, err := Open(t.TempDir()+"/monitor.sqlite3", clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	state, _, err := st.EnsureDeployment(context.Background(), "test")
	if err != nil {
		t.Fatal(err)
	}
	userID, _ := domain.NewUUID()
	now := clock.Now().UnixMilli()
	if _, err := st.db.Exec(`INSERT INTO users(id,deployment_id,name,argon2_hash,role,disabled,trust_generation,historical_restored,version,created_ms,updated_ms) VALUES(?,?,?,'00000000000000000000000000000000','admin',0,?,0,1,?,?)`, userID, state.DeploymentID, "admin", state.DeploymentGeneration, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.MeasureAndRecordCapacity(context.Background(), state.DeploymentID, now, ExternalCapacityUsage{}); err != nil {
		t.Fatal(err)
	}
	user := domain.User{ID: userID, Revision: 1, Name: "admin", Role: "admin", TrustGeneration: state.DeploymentGeneration}
	return st, clock, SessionRecord{User: user, DeploymentID: state.DeploymentID, Generation: state.DeploymentGeneration, ExpiresMS: now + int64(time.Hour/time.Millisecond)}
}

func TestEnrollmentConsumptionIsAtomicSingleUseAndReceiptBacked(t *testing.T) {
	st, clock, admin := newEnrollmentStore(t)
	token, tokenHash, err := enrollment.NewToken()
	if err != nil || token == "" {
		t.Fatal(err)
	}
	hostID, _ := domain.NewUUID()
	caFingerprint := strings.Repeat("a", 64)
	reservation, err := st.ReserveCollectorEnrollment(context.Background(), admin, tokenHash, hostID, "Remote Mac", "https://monitor.example:9444", caFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := st.CollectorEnrollmentStatus(context.Background(), admin.DeploymentID, hostID)
	if err != nil || pending.State != "waiting" || pending.DisplayName != "Remote Mac" || pending.ConnectedMS != nil {
		t.Fatalf("pending enrollment status=%#v err=%v", pending, err)
	}
	authorized, err := st.AuthenticateCollectorEnrollment(context.Background(), tokenHash)
	if err != nil || authorized != reservation {
		t.Fatalf("authorization=%+v err=%v", authorized, err)
	}
	installationID, _ := domain.NewUUID()
	request := enrollment.ExchangeRequest{Protocol: domain.ProtocolVersion, DeploymentID: admin.DeploymentID, HostID: hostID, InstallationID: installationID, CSRPEM: "-----BEGIN CERTIFICATE REQUEST-----\n" + strings.Repeat("A", 80), HubCAFingerprintSHA256: caFingerprint}
	requestHash, _ := CanonicalEnrollmentRequestHash(request)
	issued := 0
	issue := func(identity enrollment.Identity, _ string) (enrollment.ExchangeResult, string, string, error) {
		issued++
		return enrollment.ExchangeResult{Protocol: domain.ProtocolVersion, DeploymentID: identity.DeploymentID, HostID: identity.HostID, SecurityGeneration: identity.SecurityGeneration, CertificatePEM: "-----BEGIN CERTIFICATE-----\npublic", CertificateChainPEM: []string{"-----BEGIN CERTIFICATE-----\nca"}, ExpiresMS: clock.Now().Add(enrollment.CertificateValidity).UnixMilli(), HubCAFingerprintSHA256: caFingerprint}, "01", strings.Repeat("b", 64), nil
	}
	first, err := st.RedeemCollectorEnrollment(context.Background(), authorized, "00000000-0000-4000-8000-000000000001", requestHash, request, issue)
	if err != nil {
		t.Fatal(err)
	}
	second, err := st.RedeemCollectorEnrollment(context.Background(), authorized, "00000000-0000-4000-8000-000000000001", requestHash, request, issue)
	if err != nil || first.CertificatePEM != second.CertificatePEM || issued != 1 {
		t.Fatalf("retry=%+v issued=%d err=%v", second, issued, err)
	}
	connected, err := st.CollectorEnrollmentStatus(context.Background(), admin.DeploymentID, hostID)
	if err != nil || connected.State != "connected" || connected.ConnectedMS == nil {
		t.Fatalf("connected enrollment status=%#v err=%v", connected, err)
	}
	request.InstallationID, _ = domain.NewUUID()
	changedHash, _ := CanonicalEnrollmentRequestHash(request)
	if _, err := st.RedeemCollectorEnrollment(context.Background(), authorized, "00000000-0000-4000-8000-000000000002", changedHash, request, issue); !errors.Is(err, ErrEnrollmentConflict) {
		t.Fatalf("changed retry error=%v", err)
	}
	var hosts, credentials, receipts int
	_ = st.db.QueryRow(`SELECT count(*) FROM hosts WHERE id=?`, hostID).Scan(&hosts)
	_ = st.db.QueryRow(`SELECT count(*) FROM collector_credentials WHERE host_id=?`, hostID).Scan(&credentials)
	_ = st.db.QueryRow(`SELECT count(*) FROM idempotency_receipts WHERE actor_user_id=?`, admin.User.ID).Scan(&receipts)
	if hosts != 1 || credentials != 1 || receipts != 1 {
		t.Fatalf("hosts=%d credentials=%d receipts=%d", hosts, credentials, receipts)
	}
}

func TestEnrollmentIssueIsIdempotentWithoutPersistingBearerSecret(t *testing.T) {
	st, _, admin := newEnrollmentStore(t)
	token := "derived-enrollment-token-000000000000000000000000"
	requestHash := strings.Repeat("7", 64)
	key := "00000000-0000-4000-8000-000000000071"
	first, err := st.IssueCollectorEnrollment(context.Background(), admin, key, requestHash, token, "Remote Mac", "https://127.0.0.1:9444", strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	retry, err := st.IssueCollectorEnrollment(context.Background(), admin, key, requestHash, token, "Remote Mac", "https://127.0.0.1:9444", strings.Repeat("a", 64))
	if err != nil || retry != first {
		t.Fatalf("exact issue retry changed result: first=%#v retry=%#v err=%v", first, retry, err)
	}
	if _, err := st.IssueCollectorEnrollment(context.Background(), admin, key, strings.Repeat("8", 64), token, "Changed", "https://127.0.0.1:9444", strings.Repeat("a", 64)); !errors.Is(err, ErrEnrollmentConflict) {
		t.Fatalf("changed issue retry err=%v", err)
	}
	var receiptJSON, auditJSON string
	if err := st.db.QueryRow(`SELECT result_json FROM idempotency_receipts WHERE deployment_id=? AND actor_user_id=? AND idempotency_key=?`, admin.DeploymentID, admin.User.ID, key).Scan(&receiptJSON); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRow(`SELECT allowlisted_detail_json FROM audit WHERE deployment_id=? AND action='collector.enrollment.issue' AND resource_id=?`, admin.DeploymentID, first.HostID).Scan(&auditJSON); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(receiptJSON, token) || strings.Contains(auditJSON, token) || !strings.Contains(receiptJSON, enrollment.HashToken(token)) {
		t.Fatalf("secret persistence boundary failed: receipt=%s audit=%s", receiptJSON, auditJSON)
	}
}

func TestRestoredHostReEnrollmentPreservesIdentityAndRejectsOldCredential(t *testing.T) {
	st, clock, admin := newEnrollmentStore(t)
	_, tokenHash, _ := enrollment.NewToken()
	hostID, installationID := mustEnrollmentUUID(t), mustEnrollmentUUID(t)
	caFingerprint := strings.Repeat("a", 64)
	reservation, err := st.ReserveCollectorEnrollment(context.Background(), admin, tokenHash, hostID, "Retained Mac", "https://127.0.0.1:9444", caFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	request := enrollment.ExchangeRequest{Protocol: domain.ProtocolVersion, DeploymentID: admin.DeploymentID, HostID: hostID, InstallationID: installationID, CSRPEM: "-----BEGIN CERTIFICATE REQUEST-----\n" + strings.Repeat("A", 80), HubCAFingerprintSHA256: caFingerprint}
	requestHash, _ := CanonicalEnrollmentRequestHash(request)
	oldExpiry := clock.Now().Add(enrollment.CertificateValidity).UnixMilli()
	oldIssue := func(identity enrollment.Identity, _ string) (enrollment.ExchangeResult, string, string, error) {
		return enrollment.ExchangeResult{Protocol: domain.ProtocolVersion, DeploymentID: identity.DeploymentID, HostID: identity.HostID, SecurityGeneration: identity.SecurityGeneration, CertificatePEM: "old-public", CertificateChainPEM: []string{"old-ca"}, ExpiresMS: oldExpiry, HubCAFingerprintSHA256: caFingerprint}, "old-serial", strings.Repeat("b", 64), nil
	}
	if _, err := st.RedeemCollectorEnrollment(context.Background(), reservation, mustEnrollmentUUID(t), requestHash, request, oldIssue); err != nil {
		t.Fatal(err)
	}
	oldCredential := CredentialIdentity{Serial: "old-serial", FingerprintSHA256: strings.Repeat("b", 64), DeploymentID: admin.DeploymentID, HostID: hostID, SecurityGeneration: admin.Generation, ExpiresMS: oldExpiry}
	if err := st.AuthenticateCollectorCredential(context.Background(), oldCredential); err != nil {
		t.Fatal(err)
	}
	if _, err := st.IssueCollectorEnrollment(context.Background(), admin, mustEnrollmentUUID(t), strings.Repeat("1", 64), strings.Repeat("x", 40), "Active", "https://127.0.0.1:9444", caFingerprint, hostID); !errors.Is(err, ErrReEnrollmentDenied) {
		t.Fatalf("active host replacement admitted: %v", err)
	}

	newGeneration := mustEnrollmentUUID(t)
	now := clock.Now().UnixMilli()
	if _, err := st.db.Exec(`INSERT INTO deployment_generations(deployment_id,generation,reason,activated_ms) VALUES(?,?,'restore_bootstrap',?)`, admin.DeploymentID, newGeneration, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE deployments SET deployment_generation=?,recovery_state='normal',updated_ms=? WHERE id=?`, newGeneration, now, admin.DeploymentID); err != nil {
		t.Fatal(err)
	}
	newAdminID := mustEnrollmentUUID(t)
	if _, err := st.db.Exec(`INSERT INTO users(id,deployment_id,name,argon2_hash,role,disabled,trust_generation,historical_restored,version,created_ms,updated_ms) VALUES(?,?,?,'00000000000000000000000000000000','admin',0,?,0,1,?,?)`, newAdminID, admin.DeploymentID, "restored-admin", newGeneration, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE collector_credentials SET revoked_ms=? WHERE deployment_id=? AND host_id=?`, now, admin.DeploymentID, hostID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE collector_sessions SET superseded_ms=COALESCE(superseded_ms,?) WHERE deployment_id=? AND host_id=?`, now, admin.DeploymentID, hostID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE hosts SET current_session_generation=0,last_boot_id=NULL,retired_ms=?,updated_ms=? WHERE deployment_id=? AND id=?`, now, now, admin.DeploymentID, hostID); err != nil {
		t.Fatal(err)
	}
	admin.Generation = newGeneration
	admin.User = domain.User{ID: newAdminID, Revision: 1, Name: "restored-admin", Role: "admin", TrustGeneration: newGeneration}
	if _, err := st.IssueCollectorEnrollment(context.Background(), admin, mustEnrollmentUUID(t), strings.Repeat("2", 64), strings.Repeat("y", 40), "Foreign", "https://127.0.0.1:9444", strings.Repeat("c", 64), mustEnrollmentUUID(t)); !errors.Is(err, ErrReEnrollmentDenied) {
		t.Fatalf("foreign retained host admitted: %v", err)
	}

	reToken := strings.Repeat("r", 40)
	reKey := mustEnrollmentUUID(t)
	reHash := strings.Repeat("3", 64)
	issued, err := st.IssueCollectorEnrollment(context.Background(), admin, reKey, reHash, reToken, "Retained Mac", "https://127.0.0.1:9444", strings.Repeat("c", 64), hostID)
	if err != nil || issued.HostID != hostID {
		t.Fatalf("issue restored-host enrollment=%#v err=%v", issued, err)
	}
	retry, err := st.IssueCollectorEnrollment(context.Background(), admin, reKey, reHash, reToken, "Retained Mac", "https://127.0.0.1:9444", strings.Repeat("c", 64), hostID)
	if err != nil || retry != issued {
		t.Fatalf("re-enrollment issue retry changed result: %#v err=%v", retry, err)
	}
	authorized, err := st.AuthenticateCollectorEnrollment(context.Background(), enrollment.HashToken(reToken))
	if err != nil || !authorized.ReEnrollment || authorized.RetainedInstallationID != installationID {
		t.Fatalf("restored-host authorization=%#v err=%v", authorized, err)
	}
	wrongInstall := request
	wrongInstall.InstallationID = mustEnrollmentUUID(t)
	wrongInstall.HubCAFingerprintSHA256 = strings.Repeat("c", 64)
	wrongHash, _ := CanonicalEnrollmentRequestHash(wrongInstall)
	if _, err := st.RedeemCollectorEnrollment(context.Background(), authorized, mustEnrollmentUUID(t), wrongHash, wrongInstall, oldIssue); !errors.Is(err, ErrEnrollmentConflict) {
		t.Fatalf("changed installation identity admitted: %v", err)
	}

	request.HubCAFingerprintSHA256 = strings.Repeat("c", 64)
	requestHash, _ = CanonicalEnrollmentRequestHash(request)
	newExpiry := clock.Now().Add(enrollment.CertificateValidity).UnixMilli()
	newIssue := func(identity enrollment.Identity, _ string) (enrollment.ExchangeResult, string, string, error) {
		return enrollment.ExchangeResult{Protocol: domain.ProtocolVersion, DeploymentID: identity.DeploymentID, HostID: identity.HostID, SecurityGeneration: identity.SecurityGeneration, CertificatePEM: "new-public", CertificateChainPEM: []string{"new-ca"}, ExpiresMS: newExpiry, HubCAFingerprintSHA256: strings.Repeat("c", 64)}, "new-serial", strings.Repeat("d", 64), nil
	}
	first, err := st.RedeemCollectorEnrollment(context.Background(), authorized, mustEnrollmentUUID(t), requestHash, request, newIssue)
	if err != nil {
		t.Fatal(err)
	}
	second, err := st.RedeemCollectorEnrollment(context.Background(), authorized, mustEnrollmentUUID(t), requestHash, request, newIssue)
	if err != nil || second.CertificatePEM != first.CertificatePEM {
		t.Fatalf("re-enrollment redeem retry changed result: %#v err=%v", second, err)
	}
	var gotInstallation string
	var retired *int64
	if err := st.db.QueryRow(`SELECT installation_uuid,retired_ms FROM hosts WHERE deployment_id=? AND id=?`, admin.DeploymentID, hostID).Scan(&gotInstallation, &retired); err != nil || gotInstallation != installationID || retired != nil {
		t.Fatalf("retained host identity changed: installation=%s retired=%v err=%v", gotInstallation, retired, err)
	}
	if err := st.AuthenticateCollectorCredential(context.Background(), oldCredential); !errors.Is(err, ErrCredentialRevoked) {
		t.Fatalf("old restored credential accepted: %v", err)
	}
	newCredential := CredentialIdentity{Serial: "new-serial", FingerprintSHA256: strings.Repeat("d", 64), DeploymentID: admin.DeploymentID, HostID: hostID, SecurityGeneration: newGeneration, ExpiresMS: newExpiry}
	if err := st.AuthenticateCollectorCredential(context.Background(), newCredential); err != nil {
		t.Fatalf("new restored credential rejected: %v", err)
	}
}

func mustEnrollmentUUID(t *testing.T) string {
	t.Helper()
	value, err := domain.NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestLocalRestoredHostReEnrollmentIsOwnerBoundAndIdempotent(t *testing.T) {
	st, clock, admin := newEnrollmentStore(t)
	hostID, installationID := mustEnrollmentUUID(t), mustEnrollmentUUID(t)
	owner := TrustedOwnerContext{DeploymentID: admin.DeploymentID, SecurityGeneration: admin.Generation, InstallingUID: 501, VerifiedOSOwner: true}
	registration := LocalHostRegistration{HostID: hostID, InstallationUUID: installationID, DisplayName: "This Mac", Capabilities: map[string]bool{"ollama": true}}
	if err := st.RegisterLocalHost(context.Background(), owner, registration); err != nil {
		t.Fatal(err)
	}
	previousGeneration := admin.Generation
	newGeneration := mustEnrollmentUUID(t)
	now := clock.Now().UnixMilli()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO deployment_generations(deployment_id,generation,reason,activated_ms) VALUES(?,?,'restore_bootstrap',?)`, []any{admin.DeploymentID, newGeneration, now}},
		{`UPDATE deployments SET deployment_generation=?,recovery_state='normal',updated_ms=? WHERE id=?`, []any{newGeneration, now, admin.DeploymentID}},
		{`UPDATE hosts SET current_session_generation=0,last_boot_id=NULL,retired_ms=?,updated_ms=? WHERE deployment_id=? AND id=?`, []any{now, now, admin.DeploymentID, hostID}},
	}
	for _, statement := range statements {
		if _, err := st.db.Exec(statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	newOwner := TrustedOwnerContext{DeploymentID: admin.DeploymentID, SecurityGeneration: newGeneration, InstallingUID: 501, VerifiedOSOwner: true}
	if err := st.ReEnrollLocalHost(context.Background(), newOwner, registration, previousGeneration); err != nil {
		t.Fatal(err)
	}
	if err := st.ReEnrollLocalHost(context.Background(), newOwner, registration, previousGeneration); err != nil {
		t.Fatalf("exact local re-enrollment retry failed: %v", err)
	}
	var gotInstallation string
	var retired *int64
	if err := st.db.QueryRow(`SELECT installation_uuid,retired_ms FROM hosts WHERE deployment_id=? AND id=?`, admin.DeploymentID, hostID).Scan(&gotInstallation, &retired); err != nil || gotInstallation != installationID || retired != nil {
		t.Fatalf("local retained identity changed: installation=%s retired=%v err=%v", gotInstallation, retired, err)
	}
	wrong := newOwner
	wrong.VerifiedOSOwner = false
	if err := st.ReEnrollLocalHost(context.Background(), wrong, registration, previousGeneration); !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("unverified local owner admitted: %v", err)
	}
}

func TestEnrollmentExpiryHostCapCredentialRevocationAndTwoHostRefresh(t *testing.T) {
	st, clock, admin := newEnrollmentStore(t)
	firstHost, _ := domain.NewUUID()
	firstInstall, _ := domain.NewUUID()
	owner := TrustedOwnerContext{DeploymentID: admin.DeploymentID, SecurityGeneration: admin.Generation, InstallingUID: 501, VerifiedOSOwner: true}
	if err := st.RegisterLocalHost(context.Background(), owner, LocalHostRegistration{HostID: firstHost, InstallationUUID: firstInstall, DisplayName: "First", Capabilities: map[string]bool{}}); err != nil {
		t.Fatal(err)
	}
	secondHost, _ := domain.NewUUID()
	secondInstall, _ := domain.NewUUID()
	if err := st.RegisterLocalHost(context.Background(), owner, LocalHostRegistration{HostID: secondHost, InstallationUUID: secondInstall, DisplayName: "Second", Capabilities: map[string]bool{}}); err != nil {
		t.Fatal(err)
	}
	if err := st.RegisterLocalHost(context.Background(), owner, LocalHostRegistration{HostID: firstHost, InstallationUUID: firstInstall, DisplayName: "First refreshed", Capabilities: map[string]bool{}}); err != nil {
		t.Fatalf("idempotent refresh at cap: %v", err)
	}
	_, tokenHash, _ := enrollment.NewToken()
	reservedHost, _ := domain.NewUUID()
	if _, err := st.ReserveCollectorEnrollment(context.Background(), admin, tokenHash, reservedHost, "Third", "https://monitor.example:9444", strings.Repeat("a", 64)); !errors.Is(err, ErrHostLimit) {
		t.Fatalf("host cap error=%v", err)
	}
	if _, err := st.db.Exec(`DELETE FROM hosts WHERE id=?`, secondHost); err != nil {
		t.Fatal(err)
	}
	reservation, err := st.ReserveCollectorEnrollment(context.Background(), admin, tokenHash, reservedHost, "Second", "https://monitor.example:9444", strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	clock.now = time.UnixMilli(reservation.ExpiresMS)
	if _, err := st.AuthenticateCollectorEnrollment(context.Background(), tokenHash); !errors.Is(err, ErrEnrollmentExpired) {
		t.Fatalf("expiry error=%v", err)
	}
	clock.now = clock.now.Add(-time.Minute)
	if _, err := st.db.Exec(`INSERT INTO collector_credentials(serial,deployment_id,host_id,cert_fingerprint_sha256,issued_ms,expires_ms,revoked_ms) VALUES('abcd',?,?,?,?,?,NULL)`, admin.DeploymentID, firstHost, strings.Repeat("b", 64), clock.Now().UnixMilli(), clock.Now().Add(time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	credential := CredentialIdentity{Serial: "abcd", FingerprintSHA256: strings.Repeat("b", 64), DeploymentID: admin.DeploymentID, HostID: firstHost, SecurityGeneration: admin.Generation}
	if err := st.AuthenticateCollectorCredential(context.Background(), credential); err != nil {
		t.Fatal(err)
	}
	if err := st.RevokeCollectorCredentials(context.Background(), admin, firstHost); err != nil {
		t.Fatal(err)
	}
	if err := st.AuthenticateCollectorCredential(context.Background(), credential); !errors.Is(err, ErrCredentialRevoked) {
		t.Fatalf("revoked credential error=%v", err)
	}
}

func TestCollectorCredentialRenewalIsIdempotentAndOverlapBounded(t *testing.T) {
	st, clock, admin := newEnrollmentStore(t)
	token, tokenHash, _ := enrollment.NewToken()
	hostID, _ := domain.NewUUID()
	installationID, _ := domain.NewUUID()
	caFingerprint := strings.Repeat("a", 64)
	reservation, err := st.ReserveCollectorEnrollment(context.Background(), admin, tokenHash, hostID, "Remote Mac", "https://127.0.0.1:9444", caFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	generated, err := enrollment.GenerateKeyAndCSR(hostID)
	if err != nil {
		t.Fatal(err)
	}
	request := enrollment.ExchangeRequest{Protocol: domain.ProtocolVersion, DeploymentID: admin.DeploymentID, HostID: hostID, InstallationID: installationID, CSRPEM: string(generated.CSRPEM), HubCAFingerprintSHA256: caFingerprint}
	requestHash, _ := CanonicalEnrollmentRequestHash(request)
	initialExpires := clock.Now().Add(29 * 24 * time.Hour).UnixMilli()
	initialIssue := func(identity enrollment.Identity, _ string) (enrollment.ExchangeResult, string, string, error) {
		return enrollment.ExchangeResult{Protocol: domain.ProtocolVersion, DeploymentID: identity.DeploymentID, HostID: identity.HostID, SecurityGeneration: identity.SecurityGeneration, CertificatePEM: "public-initial", CertificateChainPEM: []string{"ca"}, ExpiresMS: initialExpires, HubCAFingerprintSHA256: caFingerprint}, "01", strings.Repeat("b", 64), nil
	}
	if _, err := st.RedeemCollectorEnrollment(context.Background(), reservation, "00000000-0000-4000-8000-000000000121", requestHash, request, initialIssue); err != nil {
		t.Fatal(err)
	}
	current := CredentialIdentity{Serial: "01", FingerprintSHA256: strings.Repeat("b", 64), DeploymentID: admin.DeploymentID, HostID: hostID, SecurityGeneration: admin.Generation, ExpiresMS: initialExpires}
	renewedExpires := clock.Now().Add(enrollment.CertificateValidity).UnixMilli()
	issueCount := 0
	renewIssue := func(identity enrollment.Identity, _ string) (enrollment.ExchangeResult, string, string, error) {
		issueCount++
		return enrollment.ExchangeResult{Protocol: domain.ProtocolVersion, DeploymentID: identity.DeploymentID, HostID: identity.HostID, SecurityGeneration: identity.SecurityGeneration, CertificatePEM: "public-renewed", CertificateChainPEM: []string{"ca"}, ExpiresMS: renewedExpires, HubCAFingerprintSHA256: caFingerprint}, "02", strings.Repeat("c", 64), nil
	}
	first, err := st.RenewCollectorCredential(context.Background(), current, "00000000-0000-4000-8000-000000000122", requestHash, request, renewIssue)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := st.RenewCollectorCredential(context.Background(), current, "00000000-0000-4000-8000-000000000122", requestHash, request, renewIssue)
	if err != nil || retry.CertificatePEM != first.CertificatePEM || issueCount != 1 {
		t.Fatalf("renewal retry=%#v issue_count=%d err=%v", retry, issueCount, err)
	}
	var oldRevoked int64
	if err := st.db.QueryRow(`SELECT revoked_ms FROM collector_credentials WHERE serial='01'`).Scan(&oldRevoked); err != nil || oldRevoked != clock.Now().Add(enrollment.RotationOverlap).UnixMilli() {
		t.Fatalf("old overlap=%d err=%v", oldRevoked, err)
	}
	clock.now = clock.now.Add(6 * 24 * time.Hour)
	if err := st.AuthenticateCollectorCredential(context.Background(), current); err != nil {
		t.Fatalf("old credential rejected inside overlap: %v", err)
	}
	clock.now = clock.now.Add(2 * 24 * time.Hour)
	if err := st.AuthenticateCollectorCredential(context.Background(), current); !errors.Is(err, ErrCredentialRevoked) {
		t.Fatalf("old credential accepted outside overlap: %v", err)
	}
	newCredential := CredentialIdentity{Serial: "02", FingerprintSHA256: strings.Repeat("c", 64), DeploymentID: admin.DeploymentID, HostID: hostID, SecurityGeneration: admin.Generation, ExpiresMS: renewedExpires}
	if err := st.AuthenticateCollectorCredential(context.Background(), newCredential); err != nil {
		t.Fatalf("renewed credential rejected: %v", err)
	}
	if _, err := st.RenewCollectorCredential(context.Background(), newCredential, "00000000-0000-4000-8000-000000000123", requestHash, request, renewIssue); !errors.Is(err, ErrCredentialRenewalNotDue) {
		t.Fatalf("early renewal error=%v", err)
	}
	_ = token
}
