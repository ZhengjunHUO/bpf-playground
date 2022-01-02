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
- [Socket Filter Programs](https://github.com/ZhengjunHUO/bpflearn/tree/main/filter/raw_socket)\
attach to a raw socket, observability purposes only; SEC("socket") 

- [XDP Programs](https://github.com/ZhengjunHUO/bpflearn/tree/main/xdp/droptcp)\
executed on network packet as early as possible; mitigate DDoS attack

- Cgroup Socket Programs\
attach BPF logic to cgroups\
useful in container environments where groups of processes are constrained by cgroups and where you can apply the same policies to all of them without having to identify each one independently\
usecase: [Cilium](https://github.com/cilium/cilium)

- [Traffic classifier programs](https://github.com/ZhengjunHUO/bpflearn/tree/main/tc/bpf_cls)

## Tracing
- [Kprobe Programs](https://github.com/ZhengjunHUO/bpflearn/tree/main/kprobe)\
attach dynamically to call points in the kernel\
bpf.GetSyscallFnName("execve")

- [Uprobe Programs](https://github.com/ZhengjunHUO/bpflearn/tree/main/uprobe)\
dynamic access to programs running in user-space

- [Tracepoint Programs](https://github.com/ZhengjunHUO/bpflearn/tree/main/tracepoint)\
attach to the tracepoint handler provided by the kernel; subsystem:tracepointName\
less flexible than kprobes (need to be defined by the kernel beforehand)

- Perf Event Programs
