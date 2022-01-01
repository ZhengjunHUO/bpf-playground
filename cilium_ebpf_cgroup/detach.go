package main

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/cilium/ebpf/link"
)

const (
	ebpffsPath	= "/sys/fs/bpf"
	linkFileName	= "cgroup_link"
)

func main() {
	linkPinPath := filepath.Join(ebpffsPath	, linkFileName)

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
