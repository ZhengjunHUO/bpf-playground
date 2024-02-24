COMPILER = clang

.DEFAULT_GOAL := build

block_unshare.bpf.o: block_unshare.bpf.c
	$(COMPILER) -Wall -O2 -target bpf -g -c -D__TARGET_ARCH_x86 -D__KERNEL__ $^ -o $@
	llvm-strip -g $@

block_unshare.skel.h: block_unshare.bpf.o
	sudo bpftool gen skeleton $^ > $@

block_unshare.o: block_unshare.c block_unshare.skel.h
	$(COMPILER) -Wall -g -c $< -o $@

block_unshare: block_unshare.o 
	$(COMPILER) -g $< -lbpf -o $@

.PHONY: build
build: block_unshare

.PHONY: exec
exec: build
	sudo ./block_unshare

.PHONY: clean
clean:
	rm -f *.o
	rm -f block_unshare.skel.h
	rm -f block_unshare
