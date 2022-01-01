COMPILER = clang
STRIP = llvm-strip

.PHONY: all
.DEFAULT_GOAL := build_prog

build_prog: bpf.c
	$(COMPILER) -O2 -target bpf -c $^ -o bpf.o -I../header_kernel_5.4
	$(STRIP) -g bpf.o

clean:
	$(RM) bpf.o
