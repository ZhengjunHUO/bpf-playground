COMPILER = clang
INCLUDE_PATH += -I/kernel-src/tools/lib/bpf

.PHONY: all
.DEFAULT_GOAL := build

save: pin_map_to_bpffs.c
	$(COMPILER) -o pinmap -lelf $(INCLUDE_PATH) -lbpf $^

load: get_map_from_bpffs.c
	$(COMPILER) -o getmap -lelf $(INCLUDE_PATH) -lbpf $^

build: save load

clean:
	rm -f pinmap getmap /sys/fs/bpf/my_first_stack
