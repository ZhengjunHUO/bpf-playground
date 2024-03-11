package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	bpf "github.com/iovisor/gobpf/bcc"
)

const source string = `
int trace_chdir(struct pt_regs *ctx) {
  char comm[16];
  bpf_get_current_comm(&comm, sizeof(comm));
  bpf_trace_printk("%s is changing dir...", comm);
  return 0;
}
`
func main() {
	m := bpf.NewModule(source, []string{})
	defer m.Close()

	// load program, return a fd
	tp, err := m.LoadTracepoint("trace_chdir")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load trace_chdir: %s\n", err)
		os.Exit(1)
	}

	// attach fd to tracepoint
	// cat /sys/kernel/debug/tracing/available_events to find available tracepoint
	// in format "category:name" ("subsystem:tracepointName")
	err = m.AttachTracepoint("syscalls:sys_enter_chdir", tp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach trace_chdir: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("Do # cat /sys/kernel/debug/tracing/trace_pipe to follow the trace.")
	fmt.Println("Press Ctrl + c to exit.")

	chIntrpt := make(chan os.Signal, 1)
        signal.Notify(chIntrpt, os.Interrupt, syscall.SIGTERM)
	// wait until interrupted
        <-chIntrpt
}
