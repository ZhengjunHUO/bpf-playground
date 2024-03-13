#include "process_lc.h"
#include "process_lc.skel.h"

#include <bpf/libbpf.h>
#include <signal.h>
#include <time.h>

static volatile bool running = true;

static void intr_handler(int signal) { running = false; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
    return vfprintf(stderr, format, args);
}

static int parse_event(void *ctx, void *data, size_t data_sz) {
    const struct event *ev = data;

    time_t t;
    time(&t);
    struct tm *tm = localtime(&t);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", tm);

    if (ev->exit_event) {
        printf("%7d %7d %6s %16s %8s [%u]", ev->pid, ev->ppid, "EXIT",
               ev->cmd_name, timestamp, ev->exit_code);
        if (ev->duration_ns)
            printf(" (%llums)", ev->duration_ns / 1000000);
        printf("\n");
    } else {
        printf("%7d %7d %6s %16s %8s %s\n", ev->pid, ev->ppid, "EXEC",
               ev->cmd_name, timestamp, ev->filename);
    }

    return 0;
}

int main(int argc, char **argv) {
    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, intr_handler);
    signal(SIGTERM, intr_handler);

    struct ring_buffer *rbuff = NULL;
    int err = 0;

    struct process_lc_bpf *skel = process_lc_bpf__open();
    if (!skel) {
        fprintf(stderr, "Error opening BPF skeleton\n");
        err = -1;
        goto destruction;
    }

    // skel->rodata->min_duration_ns = 10000000ULL;
    err = process_lc_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Error loading BPF skeleton\n");
        goto destruction;
    }

    err = process_lc_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Error attaching BPF skeleton\n");
        goto destruction;
    }

    rbuff = ring_buffer__new(bpf_map__fd(skel->maps.rbuff), parse_event, NULL,
                             NULL);
    if (!rbuff) {
        err = -1;
        fprintf(stderr, "Error retieving the ring buffer\n");
        goto destruction;
    }

    printf("%7s %7s %6s %16s %8s %s\n", "PID", "PPID", "EVENT", "COMM", "TIME",
           "FILENAME/EXIT CODE");
    while (running) {
        err = ring_buffer__poll(rbuff, 100);
        if (err == -EINTR) {
            printf(" Ctrl-c captured, quit ...");
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling the ring buffer: %d\n", err);
            break;
        }
    }

destruction:
    ring_buffer__free(rbuff);
    process_lc_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
