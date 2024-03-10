#include <linux/types.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

const volatile int BLOCKED_PID = 0;

typedef int __kernel_pid_t;
typedef __kernel_pid_t pid_t;

struct task_struct {
    pid_t pid;
} __attribute__((preserve_access_index));

SEC("lsm/task_setnice")
int BPF_PROG(task_setnice_handler, struct task_struct *p, int nice, int ret) {
    int pid = BPF_CORE_READ(p, pid);
    bpf_printk("Enter task_setnice hook against proc %d", pid);

    if (ret) {
        return ret;
    }

    bpf_printk("Try mutating nice value to %d on proc %d (blocked proc: %d)",
               nice, pid, BLOCKED_PID);

    if (pid == BLOCKED_PID && nice < 0) {
        bpf_printk("Mutating nice value to %d on proc %d blocked !", nice, pid);
        return -1;
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
