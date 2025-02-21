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
