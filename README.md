# Learn BPF Programming

## Environment:
  - Fedora release 32 -- Linux 5.6.6-300.fc32.x86_64

## Prerequisites:
```bash
dnf install kernel-devel-5.6.6-300.fc32
dnf install make glibc-devel.i686 elfutils-libelf-devel wget tar vim tmux jq systemtap-sdt-devel clang bcc strace git
wget -c https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.6.6.tar.gz -O - | tar -xz
mv linux-5.6.6/ /kernel-src
cd /kernel-src/tools/lib/bpf/
make && make install prefix=/
```

if bpffs is not mounted: 
```bash
mount bpffs /sys/fs/bpf -t bpf
```
