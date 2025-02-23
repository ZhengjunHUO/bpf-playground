#!/bin/sh

# List all probes (instrumentation point for capturing event data)
sudo bpftrace -l "tracepoint:syscalls:sys_exit*" | wc -l

# BEGIN: special probe that fires at the start of the program
#        used to set variables and print headers.
# sudo bpftrace -e 'BEGIN { printf("Rust rocks\n"); }'

# Get associated args
# sudo bpftrace -vl tracepoint:syscalls:sys_enter_bind

# sudo bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf("[pid: %d] %s openat: %s\n", pid, comm, str(args.filename)); }'
# @: denotes a special variable type "map"
# sudo bpftrace -e 'tracepoint:syscalls:sys_enter_openat { @dict[comm] = count() }'

# use predicate // to filter
# sudo bpftrace -e 'tracepoint:syscalls:sys_exit_read /pid == 3486/ { @rslt = hist(args.ret); }'
# sudo bpftrace -e 'kretprobe:vfs_read { @bytes = lhist(retval, 0, 2000, 200); }'

# sudo bpftrace -e 'kprobe:vfs_read { @start[tid] = nsecs; } kretprobe:vfs_read /@start[tid]/ { @ns[comm] = hist(nsecs - @start[tid]); delete(@start, tid); }'
# sudo bpftrace -e 'kprobe:vfs_read { @start[tid] = nsecs; } kretprobe:vfs_read /@start[tid]/ { @ns[comm] = hist(nsecs - @start[tid]); delete(@start[tid]); }'

# Count process-level events for five seconds, quit and print a summary.
sudo bpftrace -e 'tracepoint:sched:sched* { @[probe] = count(); } interval:s:5 { exit(); }'
#Attaching 29 probes...
#@[tracepoint:sched:sched_migrate_task]: 85
#@[tracepoint:sched:sched_wake_idle_without_ipi]: 3319
#@[tracepoint:sched:sched_wakeup]: 3913
#@[tracepoint:sched:sched_waking]: 3939
#@[tracepoint:sched:sched_stat_runtime]: 6927
#@[tracepoint:sched:sched_switch]: 7026

# Profile kernel stacks at 99 Hertz, printing a frequency count
# sudo bpftrace -e 'profile:hz:99 { @[kstack] = count(); }'
# counts stack traces that led to context switching (off-CPU) events
# sudo bpftrace -e 'tracepoint:sched:sched_switch { @[kstack] = count(); }'

# Block I/O requests by size in bytes
# sudo bpftrace -e 'tracepoint:block:block_rq_issue { @ = hist(args.bytes); }'
