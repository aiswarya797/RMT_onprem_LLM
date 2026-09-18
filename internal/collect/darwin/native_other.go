//go:build !darwin || !cgo

package darwin

import (
	"context"
	"runtime"

	"rmt.local/monitor/internal/collect/identity"
)

type nativeReader struct{}

func (nativeReader) MonotonicNS() uint64                     { return 0 }
func (nativeReader) OSBuild(context.Context) (string, error) { return "", ErrUnsupported }
func (nativeReader) HostCPUTicks(context.Context) (CPUTicks, error) {
	return CPUTicks{}, ErrUnsupported
}
func (nativeReader) MemoryPressureFlag(context.Context) (uint32, error) { return 0, ErrUnsupported }
func (nativeReader) CompressedBytes(context.Context) (uint64, error)    { return 0, ErrUnsupported }
func (nativeReader) SwapUsedBytes(context.Context) (uint64, error)      { return 0, ErrUnsupported }
func (nativeReader) DiskAvailableBytes(context.Context, string) (uint64, error) {
	return 0, ErrUnsupported
}
func (nativeReader) Interfaces(context.Context) ([]InterfaceCounters, bool, error) {
	return nil, false, ErrUnsupported
}
func (nativeReader) SameUserPIDs(context.Context, int) ([]int, bool, error) {
	return nil, false, ErrUnsupported
}
func (nativeReader) Process(context.Context, int) (ProcessRead, error) {
	return ProcessRead{Identity: identity.ProcessIdentity{}}, ErrUnsupported
}
func (nativeReader) PIDListensOnEndpoint(context.Context, int, uint64, string, uint16) (bool, error) {
	return false, ErrUnsupported
}
func (nativeReader) LogicalCPUCount() int { return runtime.NumCPU() }

var _ NativeReader = nativeReader{}
