COMPILER = clang

.PHONY: all
.DEFAULT_GOAL := build

build_prog: packetCounter.c
	$(COMPILER) -O2 -target bpf -c $^ -o packetcounter.o

build_loader: bpfLoader.c
	$(COMPILER) -DHAVE_ATTR_TEST=0 -o loadbpf -I/kernel-src/tools/lib/bpf/ -I/kernel-src/tools/lib -I/kernel-src/tools/include -I/kernel-src/tools/perf -I/kernel-src/samples /kernel-src/samples/bpf/bpf_load.c $^ /kernel-src/tools/lib/bpf/libbpf.a -lelf -lz

build: build_prog build_loader

clean:
	rm -f packetcounter.o loadbpf 
