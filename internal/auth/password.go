package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemory      = 64 * 1024
	argonIterations  = 3
	argonParallelism = 1
	argonSaltBytes   = 16
	argonHashBytes   = 32
)

type PasswordHasher struct {
	slots     chan struct{}
	admission chan struct{}
}

var ErrHashBusy = errors.New("password hashing is busy")

func NewPasswordHasher(maxConcurrent int) *PasswordHasher {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	return &PasswordHasher{slots: make(chan struct{}, maxConcurrent), admission: make(chan struct{}, maxConcurrent+2)}
}

func (h *PasswordHasher) Hash(password string) (string, error) {
	if err := validatePassword(password); err != nil {
		return "", err
	}
	salt := make([]byte, argonSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	key, err := h.derive([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonHashBytes)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonIterations, argonParallelism, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func (h *PasswordHasher) Verify(encoded, password string) (bool, error) {
	params, salt, expected, err := parseHash(encoded)
	if err != nil {
		return false, err
	}
	actual, err := h.derive([]byte(password), salt, params.time, params.memory, params.parallelism, uint32(len(expected)))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

func (h *PasswordHasher) derive(password, salt []byte, timeCost, memory uint32, parallelism uint8, length uint32) ([]byte, error) {
	select {
	case h.admission <- struct{}{}:
		defer func() { <-h.admission }()
	default:
		return nil, ErrHashBusy
	}
	h.slots <- struct{}{}
	defer func() { <-h.slots }()
	return argon2.IDKey(password, salt, timeCost, memory, parallelism, length), nil
}

type argonParams struct {
	time        uint32
	memory      uint32
	parallelism uint8
}

func parseHash(encoded string) (argonParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return argonParams{}, nil, nil, errors.New("invalid argon2id hash")
	}
	var p argonParams
	var parallel uint64
	values := strings.Split(parts[3], ",")
	if len(values) != 3 {
		return p, nil, nil, errors.New("invalid argon2id parameters")
	}
	memory, err := strconv.ParseUint(strings.TrimPrefix(values[0], "m="), 10, 32)
	if err != nil {
		return p, nil, nil, err
	}
	timeCost, err := strconv.ParseUint(strings.TrimPrefix(values[1], "t="), 10, 32)
	if err != nil {
		return p, nil, nil, err
	}
	parallel, err = strconv.ParseUint(strings.TrimPrefix(values[2], "p="), 10, 8)
	if err != nil {
		return p, nil, nil, err
	}
	if memory != argonMemory || timeCost != argonIterations || parallel != argonParallelism {
		return p, nil, nil, errors.New("unsupported argon2id parameters")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) != argonSaltBytes {
		return p, nil, nil, errors.New("invalid argon2id salt")
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(hash) != argonHashBytes {
		return p, nil, nil, errors.New("invalid argon2id hash bytes")
	}
	p.memory, p.time, p.parallelism = uint32(memory), uint32(timeCost), uint8(parallel)
	return p, salt, hash, nil
}

func validatePassword(password string) error {
	if len(password) < 12 || len(password) > 1024 {
		return errors.New("password must be between 12 and 1024 bytes")
	}
	return nil
}
