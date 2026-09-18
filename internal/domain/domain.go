package domain

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

const (
	SchemaVersion    = "1.0"
	RegistryRevision = "mac-ollama-1"
	ProtocolVersion  = "1.0"
)

type Clock interface {
	Now() time.Time
}

type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now() }

func NewUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate uuid: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s", hex.EncodeToString(b[0:4]), hex.EncodeToString(b[4:6]), hex.EncodeToString(b[6:8]), hex.EncodeToString(b[8:10]), hex.EncodeToString(b[10:16])), nil
}

type DeploymentState struct {
	SchemaVersion        string `json:"schema_version"`
	DeploymentID         string `json:"deployment_id"`
	DeploymentGeneration string `json:"deployment_generation"`
	RecoveryState        string `json:"recovery_state"`
	RecoveryPointMS      *int64 `json:"recovery_point_ms"`
	MutationsAllowed     bool   `json:"mutations_allowed"`
}

type User struct {
	ID                 string `json:"id"`
	Revision           int64  `json:"revision"`
	Name               string `json:"name"`
	Role               string `json:"role"`
	Disabled           bool   `json:"disabled"`
	TrustGeneration    string `json:"trust_generation"`
	HistoricalRestored bool   `json:"historical_restored"`
}

type Session struct {
	User      User   `json:"user"`
	ExpiresMS int64  `json:"expires_ms"`
	CSRFToken string `json:"csrf_token"`
}

type APIError struct {
	SchemaVersion  string `json:"schema_version"`
	Code           string `json:"code"`
	Message        string `json:"message"`
	RecoveryAction string `json:"recovery_action"`
	RequestID      string `json:"request_id"`
	Retryable      bool   `json:"retryable"`
	CLIExitCode    int    `json:"cli_exit_code"`
}
