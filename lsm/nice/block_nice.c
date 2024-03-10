#include "block_nice.skel.h"
#include <bpf/libbpf.h>
#include <unistd.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
    return vfprintf(stderr, format, args);
}

int main(int argc, char *argv[]) {
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    int err = 0;
    int pid = getpid();
    printf("Running as pid %d!\n", pid);

    struct block_nice_bpf *prog;
    prog = block_nice_bpf__open();
    if (!prog) {
        fprintf(stderr, "Error opening BPF program !\n");
        goto destruction;
    }

    prog->rodata->BLOCKED_PID = pid;
    err = block_nice_bpf__load(prog);
    if (!prog) {
        fprintf(stderr, "Error loading BPF program !\n");
        goto destruction;
    }

    err = block_nice_bpf__attach(prog);
    if (err) {
        fprintf(stderr, "Error attaching BPF program !\n");
        goto destruction;
    }

    printf("Bpf program injected !\n");

    while (true) {
        sleep(1);
    }

destruction:
    block_nice_bpf__destroy(prog);
    return err;
}
