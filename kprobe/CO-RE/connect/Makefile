COMPILER = clang

.DEFAULT_GOAL := build

connect_tcp.bpf.o: connect_tcp.bpf.c
	$(COMPILER) -Wall -O2 -target bpf -g -c -D__TARGET_ARCH_x86 -D__KERNEL__ $^ -o $@
	llvm-strip -g $@

connect_tcp.skel.h: connect_tcp.bpf.o
	sudo bpftool gen skeleton $^ > $@

connect_tcp.o: connect_tcp.c connect_tcp.skel.h
	$(COMPILER) -Wall -g -c $< -o $@

connect_tcp: connect_tcp.o 
	$(COMPILER) -g $< -lbpf -o $@

.PHONY: build
build: connect_tcp

.PHONY: exec
exec: build
	sudo ./connect_tcp

.PHONY: clean
clean:
	rm -f *.o
	rm -f connect_tcp.skel.h
	rm -f connect_tcp
