COMPILER = clang

.PHONY: all
.DEFAULT_GOAL := build_prog

build_prog: captureHttp.c
	$(COMPILER) -c -O2 -target bpf -c $^ -o captureHttp.o

clean:
	rm -f captureHttp.o 
