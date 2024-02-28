package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	bpf "github.com/iovisor/gobpf/bcc"
)

const source string = `
#include <uapi/linux/ptrace.h>
int pre_sys_execve(struct pt_regs *ctx) {
  char comm[16];
  bpf_get_current_comm(&comm, sizeof(comm));
  bpf_trace_printk("Executing program [%s]\n", comm);
  return 0;
}
`
func main() {
	m := bpf.NewModule(source, []string{})
	defer m.Close()

	// load program, return a fd
	sysExecve, err := m.LoadKprobe("pre_sys_execve")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load pre_sys_execve: %s\n", err)
		os.Exit(1)
	}

	// retrieve the name of the syscall execve
	syscallName := bpf.GetSyscallFnName("execve")

	// attach kprobe fd to a syscall's func name
	// maxActive use the default value
	err = m.AttachKprobe(syscallName, sysExecve, -1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach pre_sys_execve: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("Do # cat /sys/kernel/debug/tracing/trace_pipe to follow the trace.")
	fmt.Println("Press Ctrl + c to exit.")

	chIntrpt := make(chan os.Signal, 1)
        signal.Notify(chIntrpt, os.Interrupt, syscall.SIGTERM)
	// wait until interrupted
        <-chIntrpt
}
