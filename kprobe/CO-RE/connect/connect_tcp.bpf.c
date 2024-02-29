#include <linux/types.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_INET6 10
#define AF_INET 2

typedef __u64 __addrpair;
typedef __u32 __portpair;

struct pt_regs {
    long unsigned int di;
} __attribute__((preserve_access_index));

struct sock_common {
    union {
        __addrpair skc_addrpair;
        struct {
            __be32 skc_daddr;
            __be32 skc_rcv_saddr;
        };
    };
    union {
        __portpair skc_portpair;
        struct {
            __be16 skc_dport;
            __u16 skc_num;
        };
    };
    short unsigned int skc_family;
} __attribute__((preserve_access_index));

struct sock {
    struct sock_common __sk_common;
} __attribute__((preserve_access_index));

SEC("kprobe/tcp_connect")
int tcp_conn_prob(struct pt_regs *regs) {
    bpf_printk("tcp_conn called");
    struct sock *socket = (struct sock *)PT_REGS_PARM1_CORE(regs);
    // struct sock_common sock_comm = BPF_CORE_READ(socket, __sk_common);
    __u16 family = BPF_CORE_READ(socket, __sk_common.skc_family);

    // bpf_printk("family: %u", family);
    if (family == AF_INET) {
        bpf_printk("ipv4");
    }

    if (family == AF_INET6) {
        bpf_printk("ipv6");
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
