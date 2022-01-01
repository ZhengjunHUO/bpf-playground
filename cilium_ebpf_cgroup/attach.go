package main

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	ebpffsPath	= "/sys/fs/bpf"
	cgroupPath	= "/sys/fs/cgroup/system.slice/docker-746823468eb932764abff0bc416aa39d96037d201976b293ccb66c10c4702567.scope"

	bpfProgName	= "bpf.o"
	egressFuncName  = "egress_filter"
	ingressFuncName = "ingress_filter"
	linkFileName	= "cgroup_link"
)

func main() {
	// remove ebpf lock memory limit
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalln(err)
	}

	// load precompiled bpf program
	collection, err := ebpf.LoadCollection(bpfProgName)
	if err != nil {
		log.Fatalln(err)
	}
//	ingressFunc := collection.Programs[ingressFuncName]
	egressFunc := collection.Programs[egressFuncName]

	// attach bpf program to specific cgroup
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: egressFunc,
	})
	if err != nil {
		log.Fatalln(err)
	}

	// pin link to the bpffs
	linkPinPath := filepath.Join(ebpffsPath, linkFileName)
	l.Pin(linkPinPath)
	l.Close()

	fmt.Println("eBPF program attached.")
}
