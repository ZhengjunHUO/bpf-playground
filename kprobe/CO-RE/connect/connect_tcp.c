#include <signal.h>
#include <unistd.h>

#include "connect_tcp.skel.h"

static volatile bool running = true;
static void intr_handler(int signal) { running = false; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
    return vfprintf(stderr, format, args);
}

int main(int argc, char *argv[]) {
    libbpf_set_print(libbpf_print_fn);

    int err = 0;

    struct connect_tcp_bpf *obj = connect_tcp_bpf__open_and_load();
    if (!obj) {
        fprintf(stderr, "Error loading BPF obj");
        goto destruction;
    }

    err = connect_tcp_bpf__attach(obj);
    if (err) {
        fprintf(stderr, "Error attaching BPF obj");
        goto destruction;
    }

    printf("BPF program injected !\n");

    signal(SIGINT, intr_handler);
    signal(SIGTERM, intr_handler);

    while (running) {
        sleep(1);
    }
    printf("Ctrl-c captured, quit ...\n");

destruction:
    connect_tcp_bpf__destroy(obj);
    return err;
}
