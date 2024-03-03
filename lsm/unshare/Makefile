COMPILER ?= clang
STRIP := llvm-strip
BPFTOOL := bpftool
PROG_NAME ?= block_unshare
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
                         | sed 's/arm.*/arm/' \
                         | sed 's/aarch64/arm64/' \
                         | sed 's/ppc64le/powerpc/' \
                         | sed 's/mips.*/mips/' \
                         | sed 's/riscv64/riscv/' \
                         | sed 's/loongarch64/loongarch/')
MACROS := -D__TARGET_ARCH_$(ARCH) -D__KERNEL__
CFLAGS := -Wall -g
RMF := rm -f

ifeq ($(V),1)
	Q =
else
	Q = @
endif

ifeq ($(S),1)
	SFLAGS = -lelf -lz -static
else
	SFLAGS =
endif

.DEFAULT_GOAL := build

$(PROG_NAME).bpf.o: $(PROG_NAME).bpf.c
	$(Q)$(COMPILER) $(CFLAGS) -O2 -target bpf -c $(MACROS) $^ -o $@
	$(Q)$(STRIP) -g $@

$(PROG_NAME).skel.h: $(PROG_NAME).bpf.o
	$(Q)sudo $(BPFTOOL) gen skeleton $^ > $@

$(PROG_NAME).o: $(PROG_NAME).c $(PROG_NAME).skel.h
	$(Q)$(COMPILER) $(CFLAGS) -c $< -o $@

$(PROG_NAME): $(PROG_NAME).o
	$(Q)$(COMPILER) $< -lbpf $(SFLAGS) -o $@

.PHONY: build
build: $(PROG_NAME)

.PHONY: exec
exec: build
	$(Q)sudo ./$(PROG_NAME)

.PHONY: clean
clean:
	$(Q)$(RMF) *.o
	$(Q)$(RMF) $(PROG_NAME).skel.h
	$(Q)$(RMF) $(PROG_NAME)
