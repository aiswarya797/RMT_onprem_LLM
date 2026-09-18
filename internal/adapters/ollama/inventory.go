package ollama

import (
	"encoding/json"
	"fmt"
	"time"
)

type rawModelDetails struct {
	Format            string       `json:"format"`
	Family            string       `json:"family"`
	ParameterSize     string       `json:"parameter_size"`
	QuantizationLevel string       `json:"quantization_level"`
	ContextLength     *json.Number `json:"context_length"`
}

type rawModel struct {
	Name          string          `json:"name"`
	Model         string          `json:"model"`
	Size          *json.Number    `json:"size"`
	Digest        string          `json:"digest"`
	RemoteModel   string          `json:"remote_model"`
	RemoteHost    string          `json:"remote_host"`
	Details       rawModelDetails `json:"details"`
	SizeVRAM      *json.Number    `json:"size_vram"`
	ContextLength *json.Number    `json:"context_length"`
}

func decodeModels(data []byte, loaded bool, limit int) (ModelInventory, error) {
	var envelope struct {
		Models []json.RawMessage `json:"models"`
	}
	if err := strictDecode(data, &envelope); err != nil {
		return ModelInventory{}, err
	}
	if len(envelope.Models) > limit {
		return ModelInventory{}, &AdapterError{Kind: ErrorLimitExceeded, Op: "inventory", Err: fmt.Errorf("model count %d exceeds %d", len(envelope.Models), limit)}
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return ModelInventory{}, err
	}
	result := ModelInventory{Models: make([]Model, 0, len(envelope.Models)), UnknownFields: unknownKeys(top, "models")}
	for index, item := range envelope.Models {
		var raw rawModel
		if err := strictDecode(item, &raw); err != nil {
			return ModelInventory{}, withOp(fmt.Sprintf("model[%d]", index), err)
		}
		alias := raw.Model
		if alias == "" {
			alias = raw.Name
		}
		if err := validateAdmittedString(fmt.Sprintf("model[%d].alias", index), alias, true); err != nil {
			return ModelInventory{}, &AdapterError{Kind: ErrorLimitExceeded, Op: "inventory", Err: err}
		}
		for field, value := range map[string]string{"format": raw.Details.Format, "family": raw.Details.Family, "parameter_size": raw.Details.ParameterSize, "quantization_level": raw.Details.QuantizationLevel} {
			if err := validateAdmittedString("details."+field, value, false); err != nil {
				return ModelInventory{}, &AdapterError{Kind: ErrorLimitExceeded, Op: "inventory", Err: err}
			}
		}
		size, err := exactUint(raw.Size, "size", maxSignedInt64)
		if err != nil {
			return ModelInventory{}, &AdapterError{Kind: ErrorMalformed, Op: "inventory", Err: err}
		}
		sizeVRAM, err := exactUint(raw.SizeVRAM, "size_vram", maxSignedInt64)
		if err != nil {
			return ModelInventory{}, &AdapterError{Kind: ErrorMalformed, Op: "inventory", Err: err}
		}
		contextLength, err := exactUint(raw.ContextLength, "context_length", 131_072)
		if err != nil {
			return ModelInventory{}, &AdapterError{Kind: ErrorMalformed, Op: "inventory", Err: err}
		}
		detailContext, err := exactUint(raw.Details.ContextLength, "details.context_length", 131_072)
		if err != nil {
			return ModelInventory{}, &AdapterError{Kind: ErrorMalformed, Op: "inventory", Err: err}
		}
		if contextLength == nil {
			contextLength = detailContext
		}
		result.Models = append(result.Models, Model{
			Alias: alias, Digest: normalizedDigest(raw.Digest), Loaded: loaded, Local: raw.RemoteModel == "" && raw.RemoteHost == "",
			ReportedSizeBytes: size, SizeVRAMBytes: sizeVRAM, ContextLength: contextLength,
			Details: normalizeDetails(raw.Details, contextLength),
		})
		var object map[string]json.RawMessage
		_ = json.Unmarshal(item, &object)
		result.UnknownFields += unknownKeys(object, "name", "model", "size", "digest", "details", "size_vram", "context_length", "modified_at", "expires_at", "capabilities", "remote_model", "remote_host")
	}
	return result, nil
}

func decodeShow(data []byte, alias string, digest *string) (ModelInfo, error) {
	var response struct {
		Details      rawModelDetails `json:"details"`
		Capabilities []string        `json:"capabilities"`
		ModifiedAt   string          `json:"modified_at"`
	}
	if err := strictDecode(data, &response); err != nil {
		return ModelInfo{}, withOp("show", err)
	}
	if len(response.Capabilities) > MaxArrayItems {
		return ModelInfo{}, &AdapterError{Kind: ErrorLimitExceeded, Op: "show", Err: fmt.Errorf("capability count %d exceeds %d", len(response.Capabilities), MaxArrayItems)}
	}
	for field, value := range map[string]string{"format": response.Details.Format, "family": response.Details.Family, "parameter_size": response.Details.ParameterSize, "quantization_level": response.Details.QuantizationLevel} {
		if err := validateAdmittedString("details."+field, value, false); err != nil {
			return ModelInfo{}, &AdapterError{Kind: ErrorLimitExceeded, Op: "show", Err: err}
		}
	}
	for index, capability := range response.Capabilities {
		if err := validateAdmittedString(fmt.Sprintf("capabilities[%d]", index), capability, true); err != nil {
			return ModelInfo{}, &AdapterError{Kind: ErrorLimitExceeded, Op: "show", Err: err}
		}
	}
	contextLength, err := exactUint(response.Details.ContextLength, "details.context_length", 131_072)
	if err != nil {
		return ModelInfo{}, &AdapterError{Kind: ErrorMalformed, Op: "show", Err: err}
	}
	var modifiedAt *time.Time
	if response.ModifiedAt != "" {
		parsed, err := time.Parse(time.RFC3339Nano, response.ModifiedAt)
		if err != nil {
			return ModelInfo{}, &AdapterError{Kind: ErrorMalformed, Op: "show", Err: errorsForField("modified_at", err)}
		}
		modifiedAt = &parsed
	}
	var object map[string]json.RawMessage
	_ = json.Unmarshal(data, &object)
	return ModelInfo{
		Alias: alias, Digest: digest, Details: normalizeDetails(response.Details, contextLength),
		Capabilities: append([]string(nil), response.Capabilities...), ModifiedAt: modifiedAt,
		UnknownFields: unknownKeys(object, "details", "capabilities", "modified_at", "license", "modelfile", "parameters", "template", "system", "renderer", "parser", "messages", "remote_model", "remote_host", "model_info", "projector_info", "tensors", "requires"),
	}, nil
}

func normalizeDetails(raw rawModelDetails, contextLength *uint64) ModelDetails {
	return ModelDetails{
		Format: stringPointer(raw.Format), Family: stringPointer(raw.Family),
		ParameterSize: stringPointer(raw.ParameterSize), QuantizationLevel: stringPointer(raw.QuantizationLevel),
		ContextLength: contextLength,
	}
}

func unknownKeys(object map[string]json.RawMessage, known ...string) uint64 {
	allowed := make(map[string]struct{}, len(known))
	for _, key := range known {
		allowed[key] = struct{}{}
	}
	var count uint64
	for key := range object {
		if _, ok := allowed[key]; !ok {
			count++
		}
	}
	return count
}

func errorsForField(field string, err error) error { return fmt.Errorf("%s: %w", field, err) }
