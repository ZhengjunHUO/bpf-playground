#include "block_unshare.skel.h"
#include <bpf/libbpf.h>
#include <unistd.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
    return vfprintf(stderr, format, args);
}

int main(int argc, char *argv[]) {
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    int err;

    struct block_unshare_bpf *prog;
    prog = block_unshare_bpf__open_and_load();
    if (!prog) {
        fprintf(stderr, "Error loading BPF program !\n");
        goto destruction;
    }

    err = block_unshare_bpf__attach(prog);
    if (err) {
        fprintf(stderr, "Error attaching BPF program !\n");
        goto destruction;
    }

    printf("Bpf program injected !\n");

    while (true) {
        sleep(1);
    }

destruction:
    block_unshare_bpf__destroy(prog);
    return err;
}
