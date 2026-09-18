package protocol

import (
	"encoding/json"
	"io"

	"rmt.local/monitor/internal/domain"
)

var (
	Version = "0.1.0-dev"
	Build   = "unreleased"
)

type Identity struct {
	SchemaVersion    string `json:"schema_version"`
	Version          string `json:"version"`
	Build            string `json:"build"`
	RegistryRevision string `json:"registry_revision"`
	ProtocolVersion  string `json:"protocol_version"`
}

func CurrentIdentity() Identity {
	return Identity{domain.SchemaVersion, Version, Build, domain.RegistryRevision, domain.ProtocolVersion}
}

func WriteJSON(w io.Writer, value any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	return enc.Encode(value)
}
