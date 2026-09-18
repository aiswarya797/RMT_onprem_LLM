package ollama

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

func readBounded(body io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, &AdapterError{Kind: ErrorLimitExceeded, Err: fmt.Errorf("body exceeds %d bytes", limit)}
	}
	if !utf8.Valid(data) {
		return nil, &AdapterError{Kind: ErrorMalformed, Err: errors.New("body is not valid UTF-8")}
	}
	return data, nil
}

func strictDecode(data []byte, target any) error {
	if !utf8.Valid(data) {
		return &AdapterError{Kind: ErrorMalformed, Err: errors.New("JSON is not valid UTF-8")}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := validateJSONValue(decoder, 0); err != nil {
		return &AdapterError{Kind: ErrorMalformed, Err: err}
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return &AdapterError{Kind: ErrorMalformed, Err: fmt.Errorf("trailing JSON token %v", token)}
		}
		return &AdapterError{Kind: ErrorMalformed, Err: fmt.Errorf("trailing JSON: %w", err)}
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return &AdapterError{Kind: ErrorMalformed, Err: err}
	}
	return nil
}

func validateJSONValue(decoder *json.Decoder, depth int) error {
	if depth > MaxJSONDepth {
		return fmt.Errorf("JSON depth exceeds %d", MaxJSONDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			seen := make(map[string]struct{})
			keys := 0
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("object key is not a string")
				}
				if len(key) > MaxStringBytes {
					return fmt.Errorf("object key exceeds %d bytes", MaxStringBytes)
				}
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf("duplicate object key %q", key)
				}
				seen[key] = struct{}{}
				keys++
				if keys > MaxObjectKeys {
					return fmt.Errorf("object has more than %d keys", MaxObjectKeys)
				}
				if err := validateJSONValue(decoder, depth+1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("unterminated JSON object")
			}
		case '[':
			for decoder.More() {
				if err := validateJSONValue(decoder, depth+1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("unterminated JSON array")
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", value)
		}
	case string:
		// String values are bounded when they are admitted to a normalized
		// observation. Long response/template/system strings are intentionally
		// discarded and are bounded by the enclosing body budget instead.
	case json.Number:
		if _, err := strconv.ParseFloat(value.String(), 64); err != nil {
			return fmt.Errorf("invalid number: %w", err)
		}
	case nil, bool:
	default:
		return fmt.Errorf("unsupported JSON token %T", token)
	}
	return nil
}

func exactUint(value *json.Number, field string, maximum uint64) (*uint64, error) {
	if value == nil {
		return nil, nil
	}
	raw := value.String()
	if raw == "" || raw[0] == '-' || bytes.ContainsAny([]byte(raw), ".eE+") {
		return nil, fmt.Errorf("%s must be a non-negative integer", field)
	}
	parsed, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	if parsed > maximum {
		return nil, fmt.Errorf("%s exceeds %d", field, maximum)
	}
	return &parsed, nil
}

func normalizedDigest(raw string) *string {
	if len(raw) == 71 && raw[:7] == "sha256:" {
		raw = raw[7:]
	}
	if len(raw) != 64 {
		return nil
	}
	for _, char := range raw {
		if !(char >= '0' && char <= '9') && !(char >= 'a' && char <= 'f') {
			return nil
		}
	}
	return &raw
}

func stringPointer(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func validateAdmittedString(field, value string, required bool) error {
	if required && value == "" {
		return fmt.Errorf("%s is missing", field)
	}
	if len(value) > MaxStringBytes {
		return fmt.Errorf("%s exceeds %d bytes", field, MaxStringBytes)
	}
	return nil
}
