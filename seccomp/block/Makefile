COMPILER = clang

.PHONY: all
.DEFAULT_GOAL := build_prog

build_prog: blockwrite.c
	$(COMPILER) $^ -o blockwrite

clean:
	rm -f blockwrite
