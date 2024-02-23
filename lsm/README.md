```sh
$ clang -Wall -O2 -target bpf -g -c -D__TARGET_ARCH_x86 block_unshare.bpf.c -o block_unshare.bpf.o
$ llvm-strip -g block_unshare.bpf.o
$ sudo bpftool gen skeleton block_unshare.bpf.o > block_unshare.skel.h
$ clang -Wall -g -c block_unshare.c -o block_unshare.o
$ clang -g block_unshare.o -lbpf -o block_unshare
```
