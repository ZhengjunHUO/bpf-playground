#include <linux/types.h>
#include <stdbool.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "process_lc.h"

enum {
    BPF_ANY = 0,
    BPF_NOEXIST = 1,
    BPF_EXIST = 2,
    BPF_F_LOCK = 4,
};

enum bpf_map_type {
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_RINGBUF = 27,
};

typedef int __kernel_pid_t;
typedef __kernel_pid_t pid_t;

struct task_struct {
    int exit_code;
    pid_t tgid;
    struct task_struct *real_parent;
} __attribute__((preserve_access_index));

struct trace_event_raw_sched_process_exec {
    __u32 __data_loc_filename;
} __attribute__((preserve_access_index));

struct trace_event_raw_sched_process_template {
} __attribute__((preserve_access_index));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, pid_t);
    __type(value, __u64);
} start_timestamp SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024);
} rbuff SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    __u64 timestamp = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_timestamp, &pid, &timestamp, BPF_ANY);

    if (min_duration_ns)
        return 0;

    struct event *ev;
    ev = bpf_ringbuf_reserve(&rbuff, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->pid = pid;
    ev->exit_event = false;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    ev->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&ev->cmd_name, sizeof(ev->cmd_name));

    unsigned fn_offset = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&ev->filename, sizeof(ev->filename),
                       (void *)ctx + fn_offset);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    pid_t pid = id >> 32;
    pid_t tid = (__u32)id;

    if (pid != tid)
        return 0;

    __u64 *start_ts = bpf_map_lookup_elem(&start_timestamp, &pid);

    __u64 duration_ns = 0;
    if (start_ts)
        duration_ns = bpf_ktime_get_ns() - *start_ts;
    else if (min_duration_ns)
        return 0;

    bpf_map_delete_elem(&start_timestamp, &pid);

    if (min_duration_ns && duration_ns < min_duration_ns)
        return 0;

    struct event *ev;
    ev = bpf_ringbuf_reserve(&rbuff, sizeof(*ev), 0);
    if (!ev)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    ev->ppid = BPF_CORE_READ(task, real_parent, tgid);
    ev->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;

    ev->pid = pid;
    ev->duration_ns = duration_ns;
    ev->exit_event = true;
    bpf_get_current_comm(&ev->cmd_name, sizeof(ev->cmd_name));

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
