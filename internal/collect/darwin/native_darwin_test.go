//go:build darwin && cgo

package darwin

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This is a passive smoke test of the installed macOS APIs. It logs only
// availability and bounded counts: no process names, paths, arguments,
// environment, interface names, addresses, or raw identifiers.
func TestNativeReaderReadOnlyObservation(t *testing.T) {
	reader := NewNativeReader()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	first, err := reader.HostCPUTicks(ctx)
	if err != nil {
		t.Fatalf("host CPU read: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	second, err := reader.HostCPUTicks(ctx)
	if err != nil {
		t.Fatalf("second host CPU read: %v", err)
	}
	_, firstTotal, firstOK := cpuTotals(first)
	_, secondTotal, secondOK := cpuTotals(second)
	if !firstOK || !secondOK || secondTotal <= firstTotal {
		t.Fatalf("host CPU ticks were not monotonic")
	}

	if _, err := reader.CompressedBytes(ctx); err != nil {
		t.Fatalf("compressed-memory read: %v", err)
	}
	if _, err := reader.DiskAvailableBytes(ctx, t.TempDir()); err != nil {
		t.Fatalf("configured-volume statfs read: %v", err)
	}
	if _, err := reader.OSBuild(ctx); err != nil {
		t.Fatalf("OS build read: %v", err)
	}

	pressureAvailable := true
	if flag, err := reader.MemoryPressureFlag(ctx); err != nil {
		if !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("memory-pressure read: %v", err)
		}
		pressureAvailable = false
	} else if _, valid := pressureLevel(flag); !valid {
		t.Fatalf("native pressure returned unsupported flag %d", flag)
	}
	swapAvailable := true
	if _, err := reader.SwapUsedBytes(ctx); err != nil {
		if !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("swap read: %v", err)
		}
		swapAvailable = false
	}

	interfaces, truncated, err := reader.Interfaces(ctx)
	if err != nil {
		t.Fatalf("NET_RT_IFLIST2 read: %v", err)
	}
	if len(interfaces) > 64 || (truncated && len(interfaces) != 64) {
		t.Fatalf("native interface cap invalid: retained=%d truncated=%v", len(interfaces), truncated)
	}
	pids, processesTruncated, err := reader.SameUserPIDs(ctx, maxExaminedProcesses)
	if err != nil {
		t.Fatalf("same-user process list: %v", err)
	}
	if len(pids) > maxExaminedProcesses {
		t.Fatalf("native process cap exceeded: %d", len(pids))
	}
	self, err := reader.Process(ctx, os.Getpid())
	if err != nil {
		t.Fatalf("self process read: %v", err)
	}
	if self.Identity.PID != os.Getpid() || self.Identity.StartAbsolute == 0 || self.Identity.PhysicalFootprint == 0 {
		t.Fatal("self process identity or physical footprint unavailable")
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("create bounded local listener fixture: %v", err)
	}
	defer listener.Close()
	address := listener.Addr().(*net.TCPAddr)
	listens, err := reader.PIDListensOnEndpoint(ctx, os.Getpid(), self.Identity.StartAbsolute, "127.0.0.1", uint16(address.Port))
	if err != nil {
		t.Fatalf("self listener association: %v", err)
	}
	if !listens {
		t.Fatal("native listener association did not find exact loopback endpoint")
	}
	if _, err := reader.PIDListensOnEndpoint(ctx, os.Getpid(), self.Identity.StartAbsolute+1, "127.0.0.1", uint16(address.Port)); !errors.Is(err, ErrIdentityChanged) {
		t.Fatalf("listener query accepted a mismatched process incarnation: %v", err)
	}
	if listens, err := reader.PIDListensOnEndpoint(ctx, os.Getpid(), self.Identity.StartAbsolute, "127.0.0.2", uint16(address.Port)); err != nil || listens {
		t.Fatalf("listener was associated with a different loopback address: listens=%v err=%v", listens, err)
	}

	t.Logf("native_read_only cpu=true compressed=true disk=true pressure_available=%v swap_available=%v interfaces_retained=%d interfaces_truncated=%v processes_retained=%d processes_truncated=%v self_identity=true exact_listener=true sdk=%s",
		pressureAvailable, swapAvailable, len(interfaces), truncated, len(pids), processesTruncated, NativeSDKRevision)
}

// This witness brackets the native wrapper with the platform's read-only
// sysctl tool. It generates no pressure and records no process identity.
func TestNativePressureMethodWitness(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	readSysctl := func(name string) string {
		t.Helper()
		output, err := exec.CommandContext(ctx, "/usr/sbin/sysctl", "-n", name).Output()
		if err != nil {
			t.Fatalf("independent sysctl %s: %v", name, err)
		}
		return strings.TrimSpace(string(output))
	}
	buildBefore := readSysctl("kern.osversion")
	pressureBefore := readSysctl("kern.memorystatus_vm_pressure_level")
	reader := NewNativeReader()
	nativeBuild, err := reader.OSBuild(ctx)
	if err != nil {
		t.Fatalf("native OS build: %v", err)
	}
	nativeFlag, err := reader.MemoryPressureFlag(ctx)
	if err != nil {
		t.Fatalf("native pressure flag: %v", err)
	}
	pressureAfter := readSysctl("kern.memorystatus_vm_pressure_level")
	buildAfter := readSysctl("kern.osversion")
	if buildBefore != buildAfter || pressureBefore != pressureAfter {
		t.Skipf("independent pressure witness changed during bracket: build_stable=%v pressure_stable=%v", buildBefore == buildAfter, pressureBefore == pressureAfter)
	}
	independentFlag, err := strconv.ParseUint(pressureBefore, 10, 32)
	if err != nil {
		t.Fatalf("parse independent pressure flag: %v", err)
	}
	if nativeBuild != buildBefore || uint64(nativeFlag) != independentFlag {
		t.Fatalf("native witness mismatch: build_match=%v pressure_match=%v", nativeBuild == buildBefore, uint64(nativeFlag) == independentFlag)
	}
	level, valid := pressureLevel(nativeFlag)
	if !valid {
		t.Fatalf("stable native pressure flag %d has no 1/2/4 mapping", nativeFlag)
	}
	t.Logf("pressure_method_witness os_build=%s raw_flag=%d observed_level=%s source_pin=xnu-11417.121.6-source", nativeBuild, nativeFlag, level)
}
