package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"rmt.local/monitor/internal/domain"
)

func TestWebhookTLSHMACRetryAndRedirectRefusal(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef"
	payload := []byte(`{"schema_version":"alert-notification-1","state":"firing"}`)
	now := time.Unix(1800000000, 0)
	status := 200
	requests := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		body, _ := io.ReadAll(io.LimitReader(r.Body, 65537))
		if string(body) != string(payload) || r.Header.Get("Idempotency-Key") != key || r.Header.Get("X-LLM-Monitor-Timestamp") != "1800000000" {
			t.Error("payload or identity changed")
		}
		mac := hmac.New(sha256.New, []byte("hmac-test-canary"))
		mac.Write([]byte("1800000000."))
		mac.Write(payload)
		if r.Header.Get("X-LLM-Monitor-Signature") != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
			t.Error("wrong signature")
		}
		w.Header().Set("Retry-After", "999999")
		w.Header().Set("Location", "/never-follow")
		w.WriteHeader(status)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	transport := Transport{Roots: roots, Now: func() time.Time { return now }}
	c := domain.NotificationConfig{Webhook: &domain.WebhookDestination{HTTPSURL: server.URL, HMACEnabled: true}}
	for _, tc := range []struct {
		status             int
		success, permanent bool
		retry              time.Duration
	}{{200, true, false, 0}, {429, false, false, 30 * time.Minute}, {500, false, false, 0}, {401, false, true, 0}, {302, false, true, 0}} {
		status = tc.status
		before := requests
		r := transport.Send(context.Background(), "webhook", c, "hmac-test-canary", payload, key)
		if r.Succeeded != tc.success || r.Permanent != tc.permanent || r.RetryAfter != tc.retry || requests != before+1 {
			t.Fatalf("status %d: %+v / requests %d", status, r, requests-before)
		}
		if tc.success && (r.ReceiverACKMS == nil || *r.ReceiverACKMS != now.UnixMilli()) {
			t.Fatal("receiver acknowledgement missing")
		}
	}
}

func TestWebhookCancellationAndInvalidConfigurationDoNotSend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := domain.NotificationConfig{Webhook: &domain.WebhookDestination{HTTPSURL: "https://127.0.0.1:1"}}
	r := (Transport{}).Send(ctx, "webhook", c, "", []byte(`{}`), "0123456789abcdef")
	if r.Succeeded || r.SafeCode != "notification_timeout_or_cancelled" {
		t.Fatalf("cancel: %+v", r)
	}
	c.Webhook.HTTPSURL = "http://127.0.0.1:1"
	r = (Transport{}).Send(context.Background(), "webhook", c, "", []byte(`{}`), "0123456789abcdef")
	if !r.Permanent || r.SafeCode != "notification_configuration_invalid" {
		t.Fatalf("plaintext: %+v", r)
	}
}
