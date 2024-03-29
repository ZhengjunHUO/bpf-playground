#include "block_unshare.skel.h"
#include <bpf/libbpf.h>
#include <signal.h>
#include <unistd.h>

static volatile bool running = true;
static void intr_handler(int signal) { running = false; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
    return vfprintf(stderr, format, args);
}

int main(int argc, char *argv[]) {
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    int err = 0;

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

    signal(SIGINT, intr_handler);
    signal(SIGTERM, intr_handler);

    while (running) {
        sleep(1);
    }
    printf("Ctrl-c captured, quit ...\n");

destruction:
    block_unshare_bpf__destroy(prog);
    return err;
}
