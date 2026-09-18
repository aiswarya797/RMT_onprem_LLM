#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <errno.h>
#include <libproc.h>
#include <mach/host_info.h>
#include <mach/mach.h>
#include <mach/mach_host.h>
#include <mach/mach_time.h>
#include <mach/vm_statistics.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <unistd.h>

/*
 * One bounded, read-only snapshot for the U01 Mac experiment supervisor.
 * It deliberately emits no process names, paths, arguments, environment,
 * window metadata, prompts, responses, URLs, or credentials.
 */

typedef struct {
    pid_t pid;
    pid_t ppid;
    uid_t uid;
    uint64_t start_unix_us;
    uint64_t start_abstime;
    uint64_t phys_footprint;
    bool selected;
    bool rusage_ok;
} process_row;

#define MAX_PID_SNAPSHOT 4096U
#define HEADROOM_RESERVE_BYTES (512ULL * 1024ULL * 1024ULL)

static bool read_sysctl(const char *name, void *value, size_t expected_size, int *error_out) {
    size_t size = expected_size;
    if (sysctlbyname(name, value, &size, NULL, 0) != 0 || size != expected_size) {
        *error_out = errno ? errno : EIO;
        return false;
    }
    *error_out = 0;
    return true;
}

static double elapsed_ms(uint64_t start, uint64_t end) {
    mach_timebase_info_data_t info;
    if (mach_timebase_info(&info) != KERN_SUCCESS || info.denom == 0) {
        return -1.0;
    }
    long double ns = (long double)(end - start) * info.numer / info.denom;
    return (double)(ns / 1000000.0L);
}

static int find_row(process_row *rows, size_t count, pid_t pid) {
    for (size_t i = 0; i < count; i++) {
        if (rows[i].pid == pid) {
            return (int)i;
        }
    }
    return -1;
}

static process_row *read_owned_tree(pid_t root_pid, size_t *selected_count, int *error_out) {
    int bytes_needed = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (bytes_needed <= 0) {
        *error_out = errno ? errno : EIO;
        return NULL;
    }

    size_t needed_pids = (size_t)bytes_needed / sizeof(pid_t);
    if (needed_pids == 0 || needed_pids > MAX_PID_SNAPSHOT - 128U) {
        *error_out = E2BIG;
        return NULL;
    }
    size_t pid_capacity = needed_pids + 128U;
    pid_t *pids = calloc(pid_capacity, sizeof(pid_t));
    process_row *rows = calloc(pid_capacity, sizeof(process_row));
    if (pids == NULL || rows == NULL) {
        free(pids);
        free(rows);
        *error_out = ENOMEM;
        return NULL;
    }

    int bytes = proc_listpids(PROC_ALL_PIDS, 0, pids, (int)(pid_capacity * sizeof(pid_t)));
    if (bytes <= 0) {
        free(pids);
        free(rows);
        *error_out = errno ? errno : EIO;
        return NULL;
    }

    size_t row_count = 0;
    size_t pid_count = (size_t)bytes / sizeof(pid_t);
    for (size_t i = 0; i < pid_count; i++) {
        if (pids[i] <= 0) {
            continue;
        }
        struct proc_bsdinfo bsd = {0};
        int got = proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 0, &bsd, sizeof(bsd));
        if (got != (int)sizeof(bsd)) {
            continue;
        }
        rows[row_count].pid = (pid_t)bsd.pbi_pid;
        rows[row_count].ppid = (pid_t)bsd.pbi_ppid;
        rows[row_count].uid = bsd.pbi_uid;
        rows[row_count].start_unix_us = bsd.pbi_start_tvsec * 1000000ULL + bsd.pbi_start_tvusec;
        row_count++;
    }
    free(pids);

    int root_index = find_row(rows, row_count, root_pid);
    if (root_index < 0) {
        /* Absence from the bulk list is ambiguous. Only a direct lookup may
         * establish ESRCH; permission/race failures must remain unknown. */
        struct proc_bsdinfo direct = {0};
        errno = 0;
        int got = proc_pidinfo(root_pid, PROC_PIDTBSDINFO, 0, &direct, sizeof(direct));
        if (got != (int)sizeof(direct)) {
            int direct_error = errno;
            free(rows);
            *error_out = direct_error == ESRCH ? ESRCH : (direct_error ? direct_error : EIO);
            return NULL;
        }
        if (direct.pbi_uid != getuid() || row_count >= pid_capacity) {
            free(rows);
            *error_out = direct.pbi_uid != getuid() ? EPERM : E2BIG;
            return NULL;
        }
        rows[row_count].pid = (pid_t)direct.pbi_pid;
        rows[row_count].ppid = (pid_t)direct.pbi_ppid;
        rows[row_count].uid = direct.pbi_uid;
        rows[row_count].start_unix_us = direct.pbi_start_tvsec * 1000000ULL + direct.pbi_start_tvusec;
        root_index = (int)row_count++;
    }
    if (rows[root_index].uid != getuid()) {
        free(rows);
        *error_out = EPERM;
        return NULL;
    }
    rows[root_index].selected = true;

    bool changed;
    do {
        changed = false;
        for (size_t i = 0; i < row_count; i++) {
            if (rows[i].selected || rows[i].uid != getuid()) {
                continue;
            }
            int parent_index = find_row(rows, row_count, rows[i].ppid);
            if (parent_index >= 0 && rows[parent_index].selected) {
                rows[i].selected = true;
                changed = true;
            }
        }
    } while (changed);

    size_t out_count = 0;
    for (size_t i = 0; i < row_count; i++) {
        if (!rows[i].selected) {
            continue;
        }
        struct rusage_info_v4 usage = {0};
        if (proc_pid_rusage(rows[i].pid, RUSAGE_INFO_V4, (rusage_info_t *)&usage) == 0) {
            /* Re-read BSD identity after rusage to reject PID reuse/races. */
            struct proc_bsdinfo verify = {0};
            int got = proc_pidinfo(rows[i].pid, PROC_PIDTBSDINFO, 0, &verify, sizeof(verify));
            uint64_t verify_start_us = verify.pbi_start_tvsec * 1000000ULL + verify.pbi_start_tvusec;
            if (got == (int)sizeof(verify)
                && verify.pbi_uid == rows[i].uid
                && verify.pbi_ppid == (uint32_t)rows[i].ppid
                && verify_start_us == rows[i].start_unix_us
                && usage.ri_proc_start_abstime > 0) {
                rows[i].start_abstime = usage.ri_proc_start_abstime;
                rows[i].phys_footprint = usage.ri_phys_footprint;
                rows[i].rusage_ok = true;
            }
        }
        rows[out_count++] = rows[i];
    }

    *selected_count = out_count;
    *error_out = 0;
    return rows;
}

int main(int argc, char **argv) {
    pid_t owned_pid = -1;
    if (argc == 3 && strcmp(argv[1], "--owned-pid") == 0) {
        char *end = NULL;
        long value = strtol(argv[2], &end, 10);
        if (end == argv[2] || *end != '\0' || value <= 0 || value > INT32_MAX) {
            fprintf(stderr, "invalid --owned-pid\n");
            return 64;
        }
        owned_pid = (pid_t)value;
    } else if (argc != 1) {
        fprintf(stderr, "usage: macos_safety_probe [--owned-pid PID]\n");
        return 64;
    }

    uint32_t pressure_raw = 0;
    uint32_t memorystatus_percent = 0;
    uint64_t physical_bytes = 0;
    int pressure_error = 0, percent_error = 0, physical_error = 0;
    bool pressure_ok = read_sysctl("kern.memorystatus_vm_pressure_level", &pressure_raw,
        sizeof(pressure_raw), &pressure_error);
    bool percent_ok = read_sysctl("kern.memorystatus_level", &memorystatus_percent,
        sizeof(memorystatus_percent), &percent_error);
    bool physical_ok = read_sysctl("hw.memsize", &physical_bytes, sizeof(physical_bytes), &physical_error);

    vm_statistics64_data_t vm = {0};
    mach_msg_type_number_t vm_count = HOST_VM_INFO64_COUNT;
    vm_size_t page_size = 0;
    kern_return_t page_kr = host_page_size(mach_host_self(), &page_size);
    kern_return_t vm_kr = host_statistics64(mach_host_self(), HOST_VM_INFO64,
        (host_info64_t)&vm, &vm_count);
    bool vm_ok = page_kr == KERN_SUCCESS && vm_kr == KERN_SUCCESS && vm_count >= HOST_VM_INFO64_REV0_COUNT;

    uint64_t userspace_noncompressed_bytes = 0;
    uint64_t reclaimable_proxy_bytes = 0;
    uint64_t file_backed_bytes = 0;
    uint64_t kernel_percent_bytes = 0;
    uint64_t headroom_floor_bytes = 0;
    bool headroom_ok = false;
    bool headroom_consistent = false;
    if (vm_ok && physical_ok && percent_ok && memorystatus_percent <= 100) {
        /* vm_statistics64 free_count already includes speculative_count. */
        uint64_t pages = (uint64_t)vm.active_count + vm.inactive_count + vm.free_count;
        uint64_t reclaimable_pages = (uint64_t)vm.free_count + vm.purgeable_count;
        if (page_size > 0 && pages <= UINT64_MAX / page_size
            && reclaimable_pages <= UINT64_MAX / page_size
            && vm.external_page_count <= UINT64_MAX / page_size) {
            userspace_noncompressed_bytes = pages * page_size;
            reclaimable_proxy_bytes = reclaimable_pages * page_size;
            file_backed_bytes = (uint64_t)vm.external_page_count * page_size;
            kernel_percent_bytes = (physical_bytes / 100ULL) * memorystatus_percent;
            uint64_t guarded_reclaimable = reclaimable_proxy_bytes > HEADROOM_RESERVE_BYTES
                ? reclaimable_proxy_bytes - HEADROOM_RESERVE_BYTES : 0;
            headroom_floor_bytes = guarded_reclaimable < kernel_percent_bytes
                ? guarded_reclaimable : kernel_percent_bytes;
            uint64_t difference = userspace_noncompressed_bytes > kernel_percent_bytes
                ? userspace_noncompressed_bytes - kernel_percent_bytes
                : kernel_percent_bytes - userspace_noncompressed_bytes;
            uint64_t tolerance = physical_bytes / 20ULL; /* five percentage points */
            if (tolerance < 256ULL * 1024ULL * 1024ULL) {
                tolerance = 256ULL * 1024ULL * 1024ULL;
            }
            headroom_consistent = difference <= tolerance;
            headroom_ok = true;
        }
    }

    struct xsw_usage swap = {0};
    int swap_error = 0;
    bool swap_ok = read_sysctl("vm.swapusage", &swap, sizeof(swap), &swap_error);

    uint64_t desktop_start = mach_absolute_time();
    CFArrayRef windows = CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly, kCGNullWindowID);
    uint64_t desktop_end = mach_absolute_time();
    double desktop_ms = elapsed_ms(desktop_start, desktop_end);
    bool desktop_ok = windows != NULL && desktop_ms >= 0.0;
    if (windows != NULL) {
        CFRelease(windows);
    }

    size_t process_count = 0;
    int process_error = 0;
    process_row *processes = NULL;
    if (owned_pid > 0) {
        processes = read_owned_tree(owned_pid, &process_count, &process_error);
    }

    printf("{");
    printf("\"pressure\":{\"ok\":%s,\"raw\":%u,\"error\":%d},",
        pressure_ok ? "true" : "false", pressure_raw, pressure_error);
    printf("\"headroom\":{\"ok\":%s,\"consistent\":%s,\"independently_validated\":false,",
        headroom_ok ? "true" : "false", headroom_consistent ? "true" : "false");
    printf("\"method\":\"free_plus_purgeable_minus_512mib_uncertified_proxy\",\"floor_bytes\":%llu,",
        (unsigned long long)headroom_floor_bytes);
    printf("\"kernel_percent\":%u,\"kernel_percent_bytes\":%llu,",
        memorystatus_percent, (unsigned long long)kernel_percent_bytes);
    printf("\"userspace_noncompressed_bytes\":%llu,\"physical_bytes\":%llu,",
        (unsigned long long)userspace_noncompressed_bytes, (unsigned long long)physical_bytes);
    printf("\"reclaimable_proxy_bytes\":%llu,\"reserve_bytes\":%llu,",
        (unsigned long long)reclaimable_proxy_bytes,
        (unsigned long long)HEADROOM_RESERVE_BYTES);
    printf("\"file_backed_bytes_diagnostic_only\":%llu,",
        (unsigned long long)file_backed_bytes);
    printf("\"percent_error\":%d,\"physical_error\":%d,\"vm_error\":%d},",
        percent_error, physical_error, vm_ok ? 0 : (int)(vm_kr != KERN_SUCCESS ? vm_kr : page_kr));
    printf("\"swap\":{\"ok\":%s,\"used_bytes\":%llu,\"error\":%d},",
        swap_ok ? "true" : "false", (unsigned long long)swap.xsu_used, swap_error);
    printf("\"desktop\":{\"ok\":%s,\"round_trip_ms\":%.3f},",
        desktop_ok ? "true" : "false", desktop_ms);
    printf("\"owned_tree\":{\"requested\":%s,\"ok\":%s,\"error\":%d,\"processes\":[",
        owned_pid > 0 ? "true" : "false",
        owned_pid <= 0 || processes != NULL ? "true" : "false", process_error);
    for (size_t i = 0; i < process_count; i++) {
        if (i > 0) {
            printf(",");
        }
        printf("{\"pid\":%d,\"ppid\":%d,\"uid\":%u,\"start_unix_us\":%llu,",
            processes[i].pid, processes[i].ppid, processes[i].uid,
            (unsigned long long)processes[i].start_unix_us);
        printf("\"start_abstime\":%llu,\"phys_footprint_bytes\":%llu,\"rusage_ok\":%s}",
            (unsigned long long)processes[i].start_abstime,
            (unsigned long long)processes[i].phys_footprint,
            processes[i].rusage_ok ? "true" : "false");
    }
    printf("]}}\n");
    free(processes);
    return 0;
}
