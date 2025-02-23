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
$ sudo apt install -y linux-tools-common

# Grub current kernel's BTF
$ sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# shows data structure layouts
$ sudo apt install dwarves
$ pahole __sk_buff

# Generate scaffolding code
$ sudo bpftool gen skeleton foo.bpf.o > foo.skel.h

# About perf probe
# Error 1: Failed to find the path for the kernel: No such file or directory
# Error 2: Failed to find source file path

# Require debugging symbols or kernel headers
$ sudo apt install ubuntu-dbgsym-keyring
$ echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse
deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse
deb http://ddebs.ubuntu.com $(lsb_release -cs)-proposed main restricted universe multiverse" | \
sudo tee -a /etc/apt/sources.list.d/ddebs.list
$ sudo apt-get update
$ sudo apt install linux-tools-$(uname -r) linux-headers-$(uname -r) linux-image-$(uname -r)-dbgsym

# Require kernel source code
$ wget http://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux-source-6.8.0_6.8.0-52.53_all.deb
$ sudo dpkg -i linux-source-6.8.0_6.8.0-52.53_all.deb
$ cd /usr/src/linux-source-6.8.0/
$ sudo bunzip2 linux-source-6.8.0.tar.bz2
$ sudo tar -xvf linux-source-6.8.0.tar
# Do some cleanup
$ sudo mv linux-source-6.8.0/ /usr/src/linux-source-6.8.0/

$ perf probe -s /usr/src/linux-source-6.8.0/ -L tcp_connect

```

# CO-RE
- [lsm/nice](https://github.com/ZhengjunHUO/bpf-playground/tree/main/lsm/nice)
- [lsm/unshare](https://github.com/ZhengjunHUO/bpf-playground/tree/main/lsm/unshare)
- [kprobe](https://github.com/ZhengjunHUO/bpf-playground/tree/main/kprobe/CO-RE/connect)
- [tracepoint](https://github.com/ZhengjunHUO/bpf-playground/tree/main/tracepoint/CO-RE)
