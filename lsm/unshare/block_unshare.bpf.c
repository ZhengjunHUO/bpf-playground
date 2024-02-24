#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TARGET_SYSCALL 272
#define CAP_SYS_ADMIN 21
#define CAP_TO_INDEX(x) ((x) >> 5)      /* 1 << 5 == bits in __u32 */
#define CAP_TO_MASK(x) (1U << ((x)&31)) /* mask for indexed __u32 */
#define CLONE_NEWUSER 0x10000000        /* New user namespace */

SEC("lsm/cred_prepare")
int BPF_PROG(cred_prepare_handler, struct cred *new, const struct cred *old,
             gfp_t gfp, int ret) {
    u64 pid = bpf_get_current_pid_tgid();
    bpf_printk("[PID: %d] Enter ebpf program", pid);

    if (ret) {
        return ret;
    }

    struct task_struct *task;
    task = bpf_get_current_task_btf();
    kernel_cap_t caps = BPF_CORE_READ(task, cred, cap_effective);

    struct pt_regs *regs;
    regs = (struct pt_regs *)bpf_task_pt_regs(task);
    int syscall =
        bpf_core_field_exists(regs->orig_ax) ? BPF_CORE_READ(regs, orig_ax) : 0;

    if (syscall != TARGET_SYSCALL) {
        return 0;
    }
    bpf_printk("[PID: %d] Spot an unshare syscall", pid);

    unsigned long flags = PT_REGS_PARM1_CORE(regs);
    if (!(flags & CLONE_NEWUSER)) {
        return 0;
    }

    if (caps.cap[CAP_TO_INDEX(CAP_SYS_ADMIN)] & CAP_TO_MASK(CAP_SYS_ADMIN)) {
        return 0;
    }

    bpf_printk("[PID: %d] unshare syscall blocked", pid);
    return -1;
}

char LICENSE[] SEC("license") = "GPL";
