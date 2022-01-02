package main

import (
	"fmt"
	"log"
	"github.com/cilium/ebpf/link"
)

const (
	linkPinPath = "/sys/fs/bpf/cgroup_link"
)

func main() {
	// restore link from pinned file on bpffs
	l, err := link.LoadPinnedCgroup(linkPinPath, nil)
	if err != nil {
		log.Fatalln(err)
	}

	// remove the file on bpffs
	l.Unpin()
	l.Close()
	fmt.Println("Link unpinned")
}
