// +build ignore

#include "common.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("kprobe/sys_execve")
int pre_sys_execve(struct pt_regs *ctx) {
  char comm[16];
  const char fmt_str[] = "Executing program [%s]\n";
  bpf_get_current_comm(&comm, sizeof(comm));
  bpf_trace_printk(fmt_str, sizeof(fmt_str), comm);
  return 0;
}
