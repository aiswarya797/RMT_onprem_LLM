// Package notify sends only durable, sanitized notification payloads to an
// explicitly configured receiver. It never logs credentials or receiver bodies.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"rmt.local/monitor/internal/domain"
)

type Result struct {
	Succeeded     bool
	Permanent     bool
	SafeCode      string
	RetryAfter    time.Duration
	ReceiverACKMS *int64
}

type Transport struct {
	// Roots is nil in production, using the operating system trust store.
	Roots *x509.CertPool
	Now   func() time.Time
}

func (t Transport) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t Transport) Send(ctx context.Context, kind string, c domain.NotificationConfig, secret string, payload []byte, key string) Result {
	if domain.ValidateNotificationConfig(kind, c) != nil || len(payload) == 0 || len(payload) > 65536 || !json.Valid(payload) || len(key) < 16 || len(key) > 128 || strings.IndexFunc(key, func(r rune) bool { return r < 33 || r > 126 }) >= 0 || len(secret) > 4096 || (c.NeedsSecret() && secret == "") {
		return Result{Permanent: true, SafeCode: "notification_configuration_invalid"}
	}
	if kind == "webhook" {
		return t.webhook(ctx, *c.Webhook, secret, payload, key)
	}
	return t.smtp(ctx, *c.SMTP, secret, payload, key)
}

func (t Transport) acknowledged() Result {
	at := t.now().UnixMilli()
	return Result{Succeeded: true, ReceiverACKMS: &at}
}

func (t Transport) webhook(ctx context.Context, c domain.WebhookDestination, secret string, payload []byte, key string) Result {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.HTTPSURL, bytes.NewReader(payload))
	if err != nil {
		return Result{Permanent: true, SafeCode: "notification_configuration_invalid"}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", key)
	if c.HMACEnabled {
		stamp := strconv.FormatInt(t.now().Unix(), 10)
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write([]byte(stamp + "."))
		_, _ = mac.Write(payload)
		req.Header.Set("X-LLM-Monitor-Timestamp", stamp)
		req.Header.Set("X-LLM-Monitor-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	// No ambient proxy, redirects, automatic retries or reusable connection to a
	// previous destination revision. TLS authenticates the configured hostname.
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: t.Roots}, DisableKeepAlives: true, MaxResponseHeaderBytes: 16 << 10}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return transportFailure(ctx, err)
	}
	defer resp.Body.Close()
	// A status is the receiver acknowledgement; never retain an arbitrary body.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return t.acknowledged()
	}
	result := Result{SafeCode: "webhook_transient_failure"}
	if resp.StatusCode == 429 {
		result.RetryAfter = retryAfter(resp.Header.Get("Retry-After"), t.now())
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 500 && resp.StatusCode != 408 && resp.StatusCode != 429 {
		result.Permanent, result.SafeCode = true, "webhook_receiver_rejected"
	}
	return result
}

func retryAfter(value string, now time.Time) time.Duration {
	var d time.Duration
	if n, err := strconv.ParseInt(value, 10, 64); err == nil {
		if n > 1800 {
			return 30 * time.Minute
		}
		if n > 0 {
			d = time.Duration(n) * time.Second
		}
	} else if at, err := http.ParseTime(value); err == nil {
		d = at.Sub(now)
	}
	if d < 0 {
		return 0
	}
	if d > 30*time.Minute {
		return 30 * time.Minute
	}
	return d
}

func transportFailure(ctx context.Context, err error) Result {
	if ctx.Err() != nil {
		return Result{SafeCode: "notification_timeout_or_cancelled"}
	}
	var certificate x509.CertificateInvalidError
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	if errors.As(err, &certificate) || errors.As(err, &authority) || errors.As(err, &hostname) {
		return Result{Permanent: true, SafeCode: "notification_tls_verification_failed"}
	}
	var reply *textproto.Error
	if errors.As(err, &reply) {
		return Result{Permanent: reply.Code >= 500, SafeCode: "smtp_receiver_rejected"}
	}
	return Result{SafeCode: "notification_connection_failed"}
}

func (t Transport) smtp(ctx context.Context, c domain.SMTPDestination, secret string, payload []byte, key string) Result {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	address := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: c.Host, RootCAs: t.Roots}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return transportFailure(ctx, err)
	}
	var conn net.Conn = &boundedSMTPConn{Conn: raw, remaining: 256 << 10}
	if c.TLSMode == "implicit_tls" {
		conn = tls.Client(conn, tlsConfig)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	client, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		return transportFailure(ctx, err)
	}
	defer client.Close()
	if err = client.Hello("llm-monitor.local"); err != nil {
		return transportFailure(ctx, err)
	}
	if c.TLSMode == "starttls_required" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return Result{Permanent: true, SafeCode: "smtp_starttls_required"}
		}
		if err = client.StartTLS(tlsConfig); err != nil {
			return transportFailure(ctx, err)
		}
	}
	if c.Username != nil {
		if err = client.Auth(smtp.PlainAuth("", *c.Username, secret, c.Host)); err != nil {
			return transportFailure(ctx, err)
		}
	}
	if err = client.Mail(c.From); err != nil {
		return transportFailure(ctx, err)
	}
	if err = client.Rcpt(c.To); err != nil {
		return transportFailure(ctx, err)
	}
	writer, err := client.Data()
	if err != nil {
		return transportFailure(ctx, err)
	}
	message := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: LLM Monitor notification\r\nMIME-Version: 1.0\r\nContent-Type: application/json; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\nX-LLM-Monitor-Idempotency-Key: %s\r\n\r\n", c.From, c.To, key)
	if _, err = io.WriteString(writer, message); err != nil {
		return transportFailure(ctx, err)
	}
	encoded := base64.StdEncoding.EncodeToString(payload)
	for len(encoded) > 0 {
		n := min(76, len(encoded))
		if _, err = io.WriteString(writer, encoded[:n]+"\r\n"); err != nil {
			return transportFailure(ctx, err)
		}
		encoded = encoded[n:]
	}
	if err = writer.Close(); err != nil {
		return transportFailure(ctx, err)
	}
	// DATA's final 2xx accepts the message. A later QUIT failure cannot undo it.
	return t.acknowledged()
}

type boundedSMTPConn struct {
	net.Conn
	remaining int
}

func (c *boundedSMTPConn) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, io.ErrUnexpectedEOF
	}
	if len(p) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.Conn.Read(p)
	c.remaining -= n
	return n, err
}
