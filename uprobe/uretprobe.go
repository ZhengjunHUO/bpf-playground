package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	bpf "github.com/iovisor/gobpf/bcc"
)

const source string = `
BPF_HASH(cache, u64, u64);

int trace_starttime(struct pt_regs *ctx) {
  u64 pid = bpf_get_current_pid_tgid();
  u64 start_time = bpf_ktime_get_ns();
  cache.update(&pid, &start_time);
  bpf_trace_printk("[PID: %d] Execute helloworld at %d...", pid, start_time);
  return 0;
}

int trace_duration(struct pt_regs *ctx) {
  u64 pid = bpf_get_current_pid_tgid();
  u64 *start_time = cache.lookup(&pid);
  if (start_time == 0) {
    return 0;
  }
  u64 duration = bpf_ktime_get_ns() - *start_time;
  bpf_trace_printk("[PID: %d] helloworld returned, cost %d ns!", pid, duration);
  return 0;
}
`
func main() {
	m := bpf.NewModule(source, []string{})
	defer m.Close()

	// load programs in kernel, return fds
	start, err := m.LoadUprobe("trace_starttime")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load trace_starttime: %s\n", err)
		os.Exit(1)
	}

	duration, err := m.LoadUprobe("trace_duration")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load trace_duration: %s\n", err)
		os.Exit(1)
	}

	// attach uprobe/uretprobe fd to the symbol "main.main" in binary 'helloworld'
	err = m.AttachUprobe("./helloworld", "main.main", start, -1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach fd start: %s\n", err)
		os.Exit(1)
	}

	err = m.AttachUretprobe("./helloworld", "main.main", duration, -1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach fd duration: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("Do # cat /sys/kernel/debug/tracing/trace_pipe to follow the trace.")
	fmt.Println("Press Ctrl + c to exit.")

	chIntrpt := make(chan os.Signal, 1)
        signal.Notify(chIntrpt, os.Interrupt, syscall.SIGTERM)
	// wait until interrupted
        <-chIntrpt
}
