package darwin

import (
	"context"
	"errors"

	"rmt.local/monitor/internal/collect/identity"
)

var (
	ErrPermissionDenied = errors.New("native read permission denied")
	ErrProcessExited    = errors.New("process exited during observation")
	ErrIdentityChanged  = errors.New("process identity changed during observation")
	ErrLimitExceeded    = errors.New("native read limit exceeded")
	ErrUnsupported      = errors.New("native method unsupported")
)

// NativeSDKRevision records the public and Darwin-private ABI surface used by
// this collector. U01 verified these declarations against the installed macOS
// 15.5 SDK; runtime observations still carry candidate method revisions until
// T16/T24 qualify each supported OS build.
const NativeSDKRevision = "macosx-15.5-sdk-mach-libproc-route-v1"

type CPUTicks struct {
	User   uint64
	System uint64
	Nice   uint64
	Idle   uint64
}

type InterfaceCounters struct {
	Index    uint32
	Name     string
	Loopback bool
	Received uint64
	Sent     uint64
}

type ProcessRead struct {
	Identity identity.ProcessIdentity
	Name     string
}

type NativeReader interface {
	MonotonicNS() uint64
	OSBuild(context.Context) (string, error)
	HostCPUTicks(context.Context) (CPUTicks, error)
	MemoryPressureFlag(context.Context) (uint32, error)
	CompressedBytes(context.Context) (uint64, error)
	SwapUsedBytes(context.Context) (uint64, error)
	DiskAvailableBytes(context.Context, string) (uint64, error)
	Interfaces(context.Context) ([]InterfaceCounters, bool, error)
	SameUserPIDs(context.Context, int) ([]int, bool, error)
	Process(context.Context, int) (ProcessRead, error)
	PIDListensOnEndpoint(context.Context, int, uint64, string, uint16) (bool, error)
	LogicalCPUCount() int
}

func NewNativeReader() NativeReader { return nativeReader{} }
