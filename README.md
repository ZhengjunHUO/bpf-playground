# Learn eBPF Programming

## Environment:
  - Fedora release 32 -- Linux 5.11.22-100.fc32.x86_64
  - Go version go1.17.2 linux/amd64

## Prerequisites:
```bash
dnf install kernel-devel-5.11.22-100.fc32
dnf install make glibc-devel.i686 elfutils-libelf-devel wget tar vim tmux jq systemtap-sdt-devel clang bcc bcc-devel strace git llvm
wget -c https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.6.6.tar.gz -O - | tar -xz
mv linux-5.6.6/ /kernel-src
cd /kernel-src/tools/lib/bpf/
make && make install prefix=/
```

if bpffs is not mounted: 
```bash
mount bpffs /sys/fs/bpf -t bpf
```

# Summary
## Networking
- [Socket Filter Programs](https://github.com/ZhengjunHUO/bpf-playground/tree/main/filter/raw_socket)\
attach to a raw socket, observability purposes only; SEC("socket") 

- [XDP Programs](https://github.com/ZhengjunHUO/bpf-playground/tree/main/xdp/droptcp)\
executed on network packet as early as possible; mitigate DDoS attack

- Cgroup Socket Programs\
attach BPF logic to cgroups\
useful in container environments where groups of processes are constrained by cgroups and where you can apply the same policies to all of them without having to identify each one independently\
usecase: [Cilium](https://github.com/cilium/cilium)

- [Traffic classifier programs](https://github.com/ZhengjunHUO/bpf-playground/tree/main/tc/bpf_cls)

## Tracing
- [Kprobe Programs](https://github.com/ZhengjunHUO/bpf-playground/tree/main/kprobe)\
attach dynamically to call points in the kernel\
bpf.GetSyscallFnName("execve")

- [Uprobe Programs](https://github.com/ZhengjunHUO/bpf-playground/tree/main/uprobe)\
dynamic access to programs running in user-space

- [Tracepoint Programs](https://github.com/ZhengjunHUO/bpf-playground/tree/main/tracepoint)\
attach to the tracepoint handler provided by the kernel; subsystem:tracepointName\
less flexible than kprobes (need to be defined by the kernel beforehand)

- [LSM](https://github.com/ZhengjunHUO/bpf-playground/tree/main/lsm)

- Perf Event Programs

# Debug
```sh
# check bpf map content
$ sudo bpftool map dump id <MAP_ID>

# check bpf program
$ sudo bpftool prog dump xlated id <PROG_ID>

# look inside compiled eBPF program
$ llvm-objdump -S <EBPF_OBJ>

# follow debug info (bpf_printk in bpf program)
$ sudo cat /sys/kernel/tracing/trace_pipe
```

# Memo
```sh
# Grub current kernel's BTF
$ sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# shows data structure layouts
$ sudo apt install dwarves
$ pahole __sk_buff

# Generate scaffolding code
$ sudo bpftool gen skeleton foo.bpf.o > foo.skel.h
```
