//go:build darwin && cgo

package darwin

/*
#cgo LDFLAGS: -lproc
#include <errno.h>
#include <libproc.h>
#include <mach/host_info.h>
#include <mach/mach.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/machine.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/route.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/proc_info.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <unistd.h>

#define RMT_NATIVE_BUFFER_MAX (1024 * 1024)
#define RMT_PID_BUFFER_MAX 4096
#define RMT_FD_BUFFER_MAX 512
#define RMT_INTERFACE_MAX 64
#define RMT_IDENTITY_CHANGED 20001

struct rmt_cpu_ticks {
    uint64_t user;
    uint64_t system;
    uint64_t nice;
    uint64_t idle;
};

struct rmt_process_read {
    int pid;
    uint32_t uid;
    int ppid;
    uint64_t start_absolute;
    uint64_t start_wall_sec;
    uint64_t start_wall_usec;
    uint64_t user_time_ns;
    uint64_t system_time_ns;
    uint64_t physical_footprint;
    char name[64];
};

struct rmt_interface_counter {
    uint32_t index;
    uint32_t loopback;
    uint64_t received;
    uint64_t sent;
    char name[IFNAMSIZ];
};

static int rmt_errno_or_io(void) {
    return errno == 0 ? EIO : errno;
}

static uint64_t rmt_monotonic_ns(void) {
    mach_timebase_info_data_t timebase;
    if (mach_timebase_info(&timebase) != KERN_SUCCESS || timebase.denom == 0) {
        return 0;
    }
    __uint128_t ticks = mach_continuous_time();
    return (uint64_t)((ticks * timebase.numer) / timebase.denom);
}

static int rmt_host_cpu(struct rmt_cpu_ticks *out) {
    host_cpu_load_info_data_t info;
    mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;
    kern_return_t result = host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO, (host_info_t)&info, &count);
    if (result != KERN_SUCCESS || count < HOST_CPU_LOAD_INFO_COUNT) return EIO;
    out->user = info.cpu_ticks[CPU_STATE_USER];
    out->system = info.cpu_ticks[CPU_STATE_SYSTEM];
    out->nice = info.cpu_ticks[CPU_STATE_NICE];
    out->idle = info.cpu_ticks[CPU_STATE_IDLE];
    return 0;
}

static int rmt_pressure(uint32_t *out) {
    int value = 0;
    size_t size = sizeof(value);
    if (sysctlbyname("kern.memorystatus_vm_pressure_level", &value, &size, NULL, 0) != 0) return rmt_errno_or_io();
    if (size != sizeof(value) || value < 0) return EPROTO;
    *out = (uint32_t)value;
    return 0;
}

static int rmt_compressed(uint64_t *out) {
    vm_statistics64_data_t info;
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    kern_return_t result = host_statistics64(mach_host_self(), HOST_VM_INFO64, (host_info64_t)&info, &count);
    if (result != KERN_SUCCESS || count < HOST_VM_INFO64_COUNT) return EIO;
    vm_size_t page_size = 0;
    if (host_page_size(mach_host_self(), &page_size) != KERN_SUCCESS || page_size == 0) return EIO;
    if ((uint64_t)info.compressor_page_count > UINT64_MAX / (uint64_t)page_size) return EOVERFLOW;
    *out = (uint64_t)info.compressor_page_count * (uint64_t)page_size;
    return 0;
}

static int rmt_swap(uint64_t *out) {
    struct xsw_usage usage;
    size_t size = sizeof(usage);
    if (sysctlbyname("vm.swapusage", &usage, &size, NULL, 0) != 0) return rmt_errno_or_io();
    if (size != sizeof(usage)) return EPROTO;
    *out = usage.xsu_used;
    return 0;
}

static int rmt_os_build(char *out, size_t capacity) {
    size_t size = capacity;
    if (capacity < 2) return EINVAL;
    if (sysctlbyname("kern.osversion", out, &size, NULL, 0) != 0) return rmt_errno_or_io();
    if (size == 0 || size > capacity) return EOVERFLOW;
    out[capacity - 1] = '\0';
    return 0;
}

static int rmt_same_user_pids(int *out, int maximum, int *count_out, int *truncated_out) {
    if (maximum < 1 || maximum > RMT_PID_BUFFER_MAX) return EINVAL;
    int needed = proc_listpids(PROC_UID_ONLY, (uint32_t)geteuid(), NULL, 0);
    if (needed < 0) return rmt_errno_or_io();
    int requested = maximum + 1;
    int *buffer = calloc((size_t)requested, sizeof(int));
    if (buffer == NULL) return ENOMEM;
    int bytes = proc_listpids(PROC_UID_ONLY, (uint32_t)geteuid(), buffer, requested * (int)sizeof(int));
    if (bytes < 0) {
        int error = rmt_errno_or_io();
        free(buffer);
        return error;
    }
    int count = bytes / (int)sizeof(int);
    int retained = 0;
    for (int i = 0; i < count && retained < maximum; i++) {
        if (buffer[i] > 0) out[retained++] = buffer[i];
    }
    *count_out = retained;
    *truncated_out = needed > maximum * (int)sizeof(int) || count > maximum;
    free(buffer);
    return 0;
}

static int rmt_process(int pid, struct rmt_process_read *out) {
    struct proc_bsdinfo before;
    struct proc_bsdinfo after;
    struct rusage_info_v4 usage;
    memset(&before, 0, sizeof(before));
    memset(&after, 0, sizeof(after));
    memset(&usage, 0, sizeof(usage));
    int bytes = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &before, sizeof(before));
    if (bytes != sizeof(before)) return rmt_errno_or_io();
    if (before.pbi_uid != geteuid()) return EPERM;
    if (proc_pid_rusage(pid, RUSAGE_INFO_V4, (rusage_info_t *)&usage) != 0) return rmt_errno_or_io();
    bytes = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &after, sizeof(after));
    if (bytes != sizeof(after)) return rmt_errno_or_io();
    if (before.pbi_pid != after.pbi_pid || before.pbi_uid != after.pbi_uid || before.pbi_ppid != after.pbi_ppid ||
        before.pbi_start_tvsec != after.pbi_start_tvsec || before.pbi_start_tvusec != after.pbi_start_tvusec || usage.ri_proc_start_abstime == 0) {
        return RMT_IDENTITY_CHANGED;
    }
    out->pid = pid;
    out->uid = before.pbi_uid;
    out->ppid = (int)before.pbi_ppid;
    out->start_absolute = usage.ri_proc_start_abstime;
    out->start_wall_sec = before.pbi_start_tvsec;
    out->start_wall_usec = before.pbi_start_tvusec;
    out->user_time_ns = usage.ri_user_time;
    out->system_time_ns = usage.ri_system_time;
    out->physical_footprint = usage.ri_phys_footprint;
    const char *name = before.pbi_name[0] == '\0' ? before.pbi_comm : before.pbi_name;
    strlcpy(out->name, name, sizeof(out->name));
    return 0;
}

static int rmt_endpoint_matches(const struct in_sockinfo *info, int address_kind, const uint8_t *address) {
    if (address_kind == 1) {
        if ((info->insi_vflag & INI_IPV4) != 0) {
            uint32_t host = ntohl(info->insi_laddr.ina_46.i46a_addr4.s_addr);
            if ((host & 0xff000000U) == 0x7f000000U) return 1;
        }
        if ((info->insi_vflag & INI_IPV6) != 0 && IN6_IS_ADDR_LOOPBACK(&info->insi_laddr.ina_6)) return 1;
        return 0;
    }
    if (address_kind == 4 && (info->insi_vflag & INI_IPV4) != 0) {
        return memcmp(&info->insi_laddr.ina_46.i46a_addr4, address, 4) == 0;
    }
    if (address_kind == 6 && (info->insi_vflag & INI_IPV6) != 0) {
        return memcmp(&info->insi_laddr.ina_6, address, 16) == 0;
    }
    return 0;
}

static int rmt_pid_listens(int pid, uint64_t expected_start, int address_kind, const uint8_t *address, uint16_t port, int *listens_out) {
	*listens_out = 0;
	struct rusage_info_v4 before;
	struct rusage_info_v4 after;
	memset(&before, 0, sizeof(before));
	memset(&after, 0, sizeof(after));
	if (expected_start == 0 || proc_pid_rusage(pid, RUSAGE_INFO_V4, (rusage_info_t *)&before) != 0) return rmt_errno_or_io();
	if (before.ri_proc_start_abstime != expected_start) return RMT_IDENTITY_CHANGED;
	int needed = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
    if (needed < 0) return rmt_errno_or_io();
    if (needed > RMT_FD_BUFFER_MAX * (int)sizeof(struct proc_fdinfo)) return EOVERFLOW;
	if (needed == 0) {
		if (proc_pid_rusage(pid, RUSAGE_INFO_V4, (rusage_info_t *)&after) != 0) return rmt_errno_or_io();
		return after.ri_proc_start_abstime == expected_start ? 0 : RMT_IDENTITY_CHANGED;
	}
    struct proc_fdinfo *fds = calloc(1, (size_t)needed);
    if (fds == NULL) return ENOMEM;
    int bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, needed);
    if (bytes < 0) {
        int error = rmt_errno_or_io();
        free(fds);
        return error;
    }
    int count = bytes / (int)sizeof(struct proc_fdinfo);
    for (int i = 0; i < count; i++) {
        if (fds[i].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
        struct socket_fdinfo socket;
		int socket_bytes = proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDSOCKETINFO, &socket, sizeof(socket));
		if (socket_bytes != sizeof(socket)) {
			int error = rmt_errno_or_io();
			free(fds);
			return error;
        }
        if (socket.psi.soi_kind != SOCKINFO_TCP || socket.psi.soi_proto.pri_tcp.tcpsi_state != TSI_S_LISTEN) continue;
        uint16_t local_port = ntohs((uint16_t)socket.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport);
        if (local_port == port && rmt_endpoint_matches(&socket.psi.soi_proto.pri_tcp.tcpsi_ini, address_kind, address)) {
            *listens_out = 1;
            break;
        }
	}
	free(fds);
	if (proc_pid_rusage(pid, RUSAGE_INFO_V4, (rusage_info_t *)&after) != 0) return rmt_errno_or_io();
	if (after.ri_proc_start_abstime != expected_start) return RMT_IDENTITY_CHANGED;
	return 0;
}

static int rmt_interfaces(struct rmt_interface_counter *out, int maximum, int *count_out, int *truncated_out) {
    int mib[6] = {CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST2, 0};
    size_t needed = 0;
    if (sysctl(mib, 6, NULL, &needed, NULL, 0) != 0) return rmt_errno_or_io();
    if (needed == 0) {
        *count_out = 0;
        *truncated_out = 0;
        return 0;
    }
    if (needed > RMT_NATIVE_BUFFER_MAX) return EOVERFLOW;
    char *buffer = malloc(needed);
    if (buffer == NULL) return ENOMEM;
    if (sysctl(mib, 6, buffer, &needed, NULL, 0) != 0) {
        int error = rmt_errno_or_io();
        free(buffer);
        return error;
    }
    int count = 0;
    int truncated = 0;
    char *cursor = buffer;
    char *end = buffer + needed;
    while (cursor + sizeof(struct if_msghdr) <= end) {
        struct if_msghdr *header = (struct if_msghdr *)cursor;
        if (header->ifm_msglen == 0 || cursor + header->ifm_msglen > end) {
            free(buffer);
            return EPROTO;
        }
        if (header->ifm_type == RTM_IFINFO2 && header->ifm_msglen >= sizeof(struct if_msghdr2)) {
            struct if_msghdr2 *info = (struct if_msghdr2 *)cursor;
            if (count >= maximum) {
                truncated = 1;
            } else {
                out[count].index = info->ifm_index;
                out[count].loopback = (info->ifm_flags & IFF_LOOPBACK) != 0;
                out[count].received = info->ifm_data.ifi_ibytes;
                out[count].sent = info->ifm_data.ifi_obytes;
                if (if_indextoname(info->ifm_index, out[count].name) == NULL) {
                    free(buffer);
                    return rmt_errno_or_io();
                }
                count++;
            }
        }
        cursor += header->ifm_msglen;
    }
    *count_out = count;
    *truncated_out = truncated;
    free(buffer);
    return 0;
}
*/
import "C"

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"syscall"

	"rmt.local/monitor/internal/collect/identity"
)

type nativeReader struct{}

func (nativeReader) MonotonicNS() uint64 { return uint64(C.rmt_monotonic_ns()) }

func (nativeReader) OSBuild(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var buffer [256]C.char
	if err := nativeCallError(C.rmt_os_build(&buffer[0], C.size_t(len(buffer)))); err != nil {
		return "", err
	}
	return C.GoString(&buffer[0]), ctx.Err()
}

func (nativeReader) HostCPUTicks(ctx context.Context) (CPUTicks, error) {
	if err := ctx.Err(); err != nil {
		return CPUTicks{}, err
	}
	var value C.struct_rmt_cpu_ticks
	if err := nativeCallError(C.rmt_host_cpu(&value)); err != nil {
		return CPUTicks{}, err
	}
	return CPUTicks{User: uint64(value.user), System: uint64(value.system), Nice: uint64(value.nice), Idle: uint64(value.idle)}, ctx.Err()
}

func (nativeReader) MemoryPressureFlag(ctx context.Context) (uint32, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	var value C.uint32_t
	if err := nativeCallError(C.rmt_pressure(&value)); err != nil {
		return 0, err
	}
	return uint32(value), ctx.Err()
}

func (nativeReader) CompressedBytes(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	var value C.uint64_t
	if err := nativeCallError(C.rmt_compressed(&value)); err != nil {
		return 0, err
	}
	return uint64(value), ctx.Err()
}

func (nativeReader) SwapUsedBytes(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	var value C.uint64_t
	if err := nativeCallError(C.rmt_swap(&value)); err != nil {
		return 0, err
	}
	return uint64(value), ctx.Err()
}

func (nativeReader) DiskAvailableBytes(ctx context.Context, path string) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	var info syscall.Statfs_t
	if err := syscall.Statfs(path, &info); err != nil {
		return 0, err
	}
	available, blockSize := uint64(info.Bavail), uint64(info.Bsize)
	if blockSize != 0 && available > ^uint64(0)/blockSize {
		return 0, ErrLimitExceeded
	}
	return available * blockSize, ctx.Err()
}

func (nativeReader) Interfaces(ctx context.Context) ([]InterfaceCounters, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	values := make([]C.struct_rmt_interface_counter, C.RMT_INTERFACE_MAX)
	var count, truncated C.int
	if err := nativeCallError(C.rmt_interfaces(&values[0], C.RMT_INTERFACE_MAX, &count, &truncated)); err != nil {
		return nil, false, err
	}
	result := make([]InterfaceCounters, 0, int(count))
	for index := 0; index < int(count); index++ {
		item := values[index]
		result = append(result, InterfaceCounters{Index: uint32(item.index), Name: C.GoString(&item.name[0]), Loopback: item.loopback != 0, Received: uint64(item.received), Sent: uint64(item.sent)})
	}
	return result, truncated != 0, ctx.Err()
}

func (nativeReader) SameUserPIDs(ctx context.Context, maximum int) ([]int, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if maximum < 1 || maximum > int(C.RMT_PID_BUFFER_MAX) {
		return nil, false, ErrLimitExceeded
	}
	values := make([]C.int, maximum)
	var count, truncated C.int
	if err := nativeCallError(C.rmt_same_user_pids(&values[0], C.int(maximum), &count, &truncated)); err != nil {
		return nil, false, err
	}
	result := make([]int, 0, int(count))
	for index := 0; index < int(count); index++ {
		result = append(result, int(values[index]))
	}
	return result, truncated != 0, ctx.Err()
}

func (nativeReader) Process(ctx context.Context, pid int) (ProcessRead, error) {
	if err := ctx.Err(); err != nil {
		return ProcessRead{}, err
	}
	var value C.struct_rmt_process_read
	if err := nativeCallError(C.rmt_process(C.int(pid), &value)); err != nil {
		return ProcessRead{}, err
	}
	result := ProcessRead{Identity: identity.ProcessIdentity{
		PID: int(value.pid), UID: uint32(value.uid), ParentPID: int(value.ppid), StartAbsolute: uint64(value.start_absolute),
		StartWallSec: uint64(value.start_wall_sec), StartWallUsec: uint64(value.start_wall_usec), UserTimeNS: uint64(value.user_time_ns),
		SystemTimeNS: uint64(value.system_time_ns), PhysicalFootprint: uint64(value.physical_footprint),
	}, Name: C.GoString(&value.name[0])}
	return result, ctx.Err()
}

func (nativeReader) PIDListensOnEndpoint(ctx context.Context, pid int, expectedStart uint64, host string, port uint16) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	var address [16]C.uint8_t
	addressKind := C.int(1)
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return false, ErrUnsupported
		}
		if ip4 := ip.To4(); ip4 != nil {
			addressKind = 4
			for index := range ip4 {
				address[index] = C.uint8_t(ip4[index])
			}
		} else {
			addressKind = 6
			for index := range ip {
				address[index] = C.uint8_t(ip[index])
			}
		}
	}
	var listens C.int
	if err := nativeCallError(C.rmt_pid_listens(C.int(pid), C.uint64_t(expectedStart), addressKind, &address[0], C.uint16_t(port), &listens)); err != nil {
		return false, err
	}
	return listens != 0, ctx.Err()
}

func (nativeReader) LogicalCPUCount() int { return runtime.NumCPU() }

func nativeCallError(code C.int) error {
	if code == 0 {
		return nil
	}
	switch int(code) {
	case int(C.EPERM), int(C.EACCES):
		return ErrPermissionDenied
	case int(C.ESRCH):
		return ErrProcessExited
	case int(C.EOVERFLOW), int(C.ENOMEM):
		return ErrLimitExceeded
	case int(C.ENOTSUP), int(C.ENOSYS):
		return ErrUnsupported
	case int(C.RMT_IDENTITY_CHANGED):
		return ErrIdentityChanged
	default:
		return fmt.Errorf("native Darwin read failed with errno %d", int(code))
	}
}

var _ NativeReader = nativeReader{}
