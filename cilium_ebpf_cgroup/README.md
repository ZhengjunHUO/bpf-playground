# Attach a network filter to a cgroup
To apply to a container, change cgroupPath in attach.go \
- /sys/fs/cgroup/system.slice/docker-xxx.scope
```bash
# compile and attach ebpf program to cgroup
make
go run attach.go

# detach program
go run detach.go
make clean
```


