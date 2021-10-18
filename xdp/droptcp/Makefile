COMPILER = clang

.PHONY: all
.DEFAULT_GOAL := build_prog

build_prog: droptcp.c
	$(COMPILER) -g -c -O2 -target bpf -c $^ -o droptcp.o

clean:
	rm -f droptcp.o
