package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"

	"rmt.local/monitor/internal/domain"
)

const SaltBytes = 32

type Scope struct {
	HostID string
	BootID string
	Salt   [SaltBytes]byte
}

func NewScope(hostID, bootID string) (Scope, error) {
	var scope Scope
	scope.HostID = hostID
	scope.BootID = bootID
	if _, err := rand.Read(scope.Salt[:]); err != nil {
		return Scope{}, fmt.Errorf("create per-boot process identity salt: %w", err)
	}
	return scope, nil
}

type ProcessIdentity struct {
	PID               int
	UID               uint32
	ParentPID         int
	StartAbsolute     uint64
	StartWallSec      uint64
	StartWallUsec     uint64
	UserTimeNS        uint64
	SystemTimeNS      uint64
	PhysicalFootprint uint64
}

func Consistent(before, after ProcessIdentity) bool {
	return before.PID > 0 && before.PID == after.PID &&
		before.UID == after.UID && before.ParentPID == after.ParentPID &&
		before.StartWallSec == after.StartWallSec && before.StartWallUsec == after.StartWallUsec &&
		before.StartAbsolute != 0 && before.StartAbsolute == after.StartAbsolute
}

func ProcessKey(scope Scope, value ProcessIdentity) (string, error) {
	if scope.HostID == "" || scope.BootID == "" || value.PID <= 0 || value.StartAbsolute == 0 {
		return "", errors.New("process key requires scoped host, boot, pid and start identity")
	}
	hash := sha256.New()
	writeField(hash, []byte("rmt-process-key-v1"))
	writeField(hash, []byte(scope.HostID))
	writeField(hash, []byte(scope.BootID))
	writeField(hash, scope.Salt[:])
	var numbers [16]byte
	binary.BigEndian.PutUint64(numbers[:8], uint64(value.PID))
	binary.BigEndian.PutUint64(numbers[8:], value.StartAbsolute)
	writeField(hash, numbers[:])
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type VerifiedRole string

const (
	RoleNone           VerifiedRole = ""
	RoleSelectedOllama VerifiedRole = "selected_ollama"
	RoleRMTHub         VerifiedRole = "rmt_hub"
	RoleRMTCollector   VerifiedRole = "rmt_collector"
)

// DisplayIdentity formats a role that was already verified by PID and start
// identity. A matching basename alone never confers Ollama or RMT ownership.
func DisplayIdentity(name string, role VerifiedRole) (*string, domain.ProcessCategory) {
	base := filepath.Base(name)
	if role == RoleSelectedOllama && base == "ollama" {
		return &base, domain.ProcessSelectedOllama
	}
	if (role == RoleRMTHub && base == "llm-monitor") || (role == RoleRMTCollector && base == "llm-monitor-collector") {
		return &base, domain.ProcessRMT
	}
	return nil, domain.ProcessOtherSameUser
}

type byteWriter interface {
	Write([]byte) (int, error)
}

func writeField(writer byteWriter, value []byte) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	_, _ = writer.Write(size[:])
	_, _ = writer.Write(value)
}
