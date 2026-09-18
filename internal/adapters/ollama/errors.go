package ollama

import (
	"errors"
	"fmt"
)

type ErrorKind string

const (
	ErrorInvalidTarget ErrorKind = "invalid_target"
	ErrorUnreachable   ErrorKind = "unreachable"
	ErrorProtocol      ErrorKind = "credential_or_protocol_error"
	ErrorIncompatible  ErrorKind = "incompatible"
	ErrorLimitExceeded ErrorKind = "limit_exceeded"
	ErrorMalformed     ErrorKind = "malformed"
	ErrorBusy          ErrorKind = "operation_in_progress"
	ErrorTimeout       ErrorKind = "source_timeout"
	ErrorCancelled     ErrorKind = "cancelled"
)

type AdapterError struct {
	Kind ErrorKind
	Op   string
	Err  error
}

func (e *AdapterError) Error() string {
	if e.Op == "" {
		return fmt.Sprintf("ollama adapter %s: %v", e.Kind, e.Err)
	}
	return fmt.Sprintf("ollama adapter %s %s: %v", e.Op, e.Kind, e.Err)
}

func (e *AdapterError) Unwrap() error { return e.Err }

func errorKind(err error) ErrorKind {
	var adapterErr *AdapterError
	if errors.As(err, &adapterErr) {
		return adapterErr.Kind
	}
	return ErrorMalformed
}

func ErrorKindOf(err error) ErrorKind { return errorKind(err) }
