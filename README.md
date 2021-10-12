# Learn BPF Programming

## Environment:
  - Fedora release 34 -- Linux 5.11.12-300.fc34.x86_64
  - Go version go1.17.2 linux/amd64

## Prerequisites:
```bash
dnf install kernel-devel-5.14.9-200.fc34
dnf install make glibc-devel.i686 elfutils-libelf-devel wget tar vim tmux jq systemtap-sdt-devel clang bcc bcc-devel strace git
wget -c https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.14.9.tar.gz -O - | tar -xz
mv linux-5.14.9/ /kernel-src
cd /kernel-src/tools/lib/bpf/
make && make install prefix=/
```

if bpffs is not mounted: 
```bash
mount bpffs /sys/fs/bpf -t bpf
```
