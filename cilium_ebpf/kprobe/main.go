//go:build linux
// +build linux

package main

import (
	"log"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-13 -cflags "-O2 -g -Wall -Werror -fdebug-prefix-map=/ebpf=." kprobe kprobe.c -- -I../headers

func main() {
	// allow to lock memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// 1) load compiled bpf program into the kernel
	obj := kprobeObjects{}
	if err := loadKprobeObjects(&obj, nil); err != nil {
		log.Fatalf("Error loading object: %v", err)
	}
	defer obj.Close()

	// name of the syscall execve
	fn := "sys_execve"
	// 2) attach callback func to syscall
	kpb, err := link.Kprobe(fn, obj.PreSysExecve)
	if err != nil {
		log.Fatal(err)
	}
	defer kpb.Close()


	fmt.Println("Do # cat /sys/kernel/debug/tracing/trace_pipe to follow the trace.")
	fmt.Println("Press Ctrl + c to exit.")

	chIntrpt := make(chan os.Signal, 1)
	signal.Notify(chIntrpt, os.Interrupt, syscall.SIGTERM)
        // wait until interrupted
	<-chIntrpt
}
