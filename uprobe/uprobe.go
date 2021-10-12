package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	bpf "github.com/iovisor/gobpf/bcc"
)

const source string = `
int trace_gobin(struct pt_regs *ctx) {
  u64 pid = bpf_get_current_pid_tgid();
  bpf_trace_printk("[PID: %d] helloworld executed", pid);
  return 0;
}
`
func main() {
	m := bpf.NewModule(source, []string{})
	defer m.Close()

	// load program, return a fd
	userBin, err := m.LoadUprobe("trace_gobin")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load trace_gobin: %s\n", err)
		os.Exit(1)
	}

	// attach a uprobe fd to the symbol "main.main" in binary 'helloworld'
	// A pid can be given to attach to, or -1 to attach to all processes
	err = m.AttachUprobe("./helloworld", "main.main", userBin, -1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach trace_gobin: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("Do # cat /sys/kernel/debug/tracing/trace_pipe to follow the trace.")
	fmt.Println("Press Ctrl + c to exit.")

	chIntrpt := make(chan os.Signal, 1)
        signal.Notify(chIntrpt, os.Interrupt, syscall.SIGTERM)
	// wait until interrupted
        <-chIntrpt
}
