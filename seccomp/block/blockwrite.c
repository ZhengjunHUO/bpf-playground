#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>

#include <linux/bpf.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/unistd.h>
#include <linux/audit.h>
#include <sys/prctl.h>

static int filter_on(int nr, int arch, int error) {
  // block the target syscall on specific arch
  struct sock_filter myfilter[] = {
    BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, arch))),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, arch, 0, 3),
    BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, nr, 0, 1),
    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (error & SECCOMP_RET_DATA)),
    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog filter_prog = {
    // Number of filter blocks
    .len = (unsigned short)(sizeof(myfilter) / sizeof(myfilter[0])),
    .filter = myfilter,
  };
  // load filter in secure computing mode and run in this mode
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter_prog)) {
    printf("prctl set seccomp filter failed!\n");
    return 1;
  }

  return 0;
}

int main(int argc, char const *argv[]) {
  // child process will not have more privilege
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    printf("Exec prctl failed!\n");
    return 1;
  }
  // Set the filter on syscall write, return Operation not permitted to any calls
  filter_on(__NR_write, AUDIT_ARCH_X86_64, EPERM);
  // Execute the command in shell
  return system(argv[1]);
}
