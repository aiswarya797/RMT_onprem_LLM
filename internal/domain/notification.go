package domain

import (
	"errors"
	"net"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

type NotificationConfig struct {
	Webhook *WebhookDestination `json:"webhook"`
	SMTP    *SMTPDestination    `json:"smtp"`
}

type WebhookDestination struct {
	HTTPSURL    string `json:"https_url"`
	HMACEnabled bool   `json:"hmac_enabled"`
}

type SMTPDestination struct {
	Host     string  `json:"host"`
	Port     int     `json:"port"`
	TLSMode  string  `json:"tls_mode"`
	From     string  `json:"from"`
	To       string  `json:"to"`
	Username *string `json:"username"`
}

var ErrNotificationConfig = errors.New("invalid notification configuration")

func (c NotificationConfig) NeedsSecret() bool {
	return c.Webhook != nil && c.Webhook.HMACEnabled || c.SMTP != nil && c.SMTP.Username != nil
}

// ValidateNotificationConfig admits only the explicit administrator-selected
// receiver. It never discovers receivers or accepts credentials in a URL.
func ValidateNotificationConfig(kind string, c NotificationConfig) error {
	if kind == "webhook" && c.Webhook != nil && c.SMTP == nil {
		w := c.Webhook
		u, err := url.Parse(w.HTTPSURL)
		if err != nil || len(w.HTTPSURL) > 2048 || hasNotificationControl(w.HTTPSURL) || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return ErrNotificationConfig
		}
		if p := u.Port(); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 {
				return ErrNotificationConfig
			}
		}
		return nil
	}
	if kind != "smtp" || c.SMTP == nil || c.Webhook != nil {
		return ErrNotificationConfig
	}
	s := c.SMTP
	if s.Host == "" || len(s.Host) > 253 || strings.TrimSpace(s.Host) != s.Host || strings.ContainsAny(s.Host, "/@[] ") || hasNotificationControl(s.Host) || (strings.Contains(s.Host, ":") && net.ParseIP(s.Host) == nil) || s.Port < 1 || s.Port > 65535 || (s.TLSMode != "starttls_required" && s.TLSMode != "implicit_tls") {
		return ErrNotificationConfig
	}
	for _, address := range []string{s.From, s.To} {
		a, err := mail.ParseAddress(address)
		if err != nil || a.Address != address || len(address) > 254 || hasNotificationControl(address) {
			return ErrNotificationConfig
		}
	}
	if s.Username != nil && (*s.Username == "" || len(*s.Username) > 256 || hasNotificationControl(*s.Username)) {
		return ErrNotificationConfig
	}
	return nil
}

func hasNotificationControl(s string) bool {
	return strings.IndexFunc(s, unicode.IsControl) >= 0
}
