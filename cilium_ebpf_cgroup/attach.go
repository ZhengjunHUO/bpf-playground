package main

import (
	"fmt"
	"log"
	"net"
	"encoding/binary"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	cgroupPath	= "/sys/fs/cgroup/system.slice/docker-746823468eb932764abff0bc416aa39d96037d201976b293ccb66c10c4702567.scope"

	bpfProgName	= "bpf.o"
	egressFuncName  = "egress_filter"
	ingressFuncName = "ingress_filter"
	egressMapName   = "egress_blacklist"

	linkPinPath     = "/sys/fs/bpf/cgroup_link"
)

func main() {
	/* remove ebpf lock memory limit */
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalln(err)
	}

	/* load precompiled bpf program */
	collection, err := ebpf.LoadCollection(bpfProgName)
	if err != nil {
		log.Fatalln(err)
	}
	egressFunc := collection.Programs[egressFuncName]

	/* load map (temporary hardcode an entry to blacklist) */
	egressMap := collection.Maps[egressMapName]

	ip := binary.LittleEndian.Uint32(net.ParseIP("8.8.4.4").To4())
	bTrue := true
	if err = egressMap.Put(&ip, &bTrue); err != nil {
		log.Fatalln(err)
	}

	/* attach bpf program to specific cgroup */
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: egressFunc,
	})
	if err != nil {
		log.Fatalln(err)
	}

	/* pin link to the bpffs */
	l.Pin(linkPinPath)
	l.Close()

	fmt.Println("eBPF program attached.")
}
