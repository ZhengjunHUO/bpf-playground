#include <linux/types.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_INET6 10
#define AF_INET 2

typedef __u64 __addrpair;
typedef __u32 __portpair;

struct pt_regs {
    long unsigned int di;
} __attribute__((preserve_access_index));

struct in6_addr {
    union {
        __u8 u6_addr8[16];
    } in6_u;
};

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
    struct in6_addr skc_v6_daddr;
    struct in6_addr skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

struct sock {
    struct sock_common __sk_common;
} __attribute__((preserve_access_index));

SEC("kprobe/tcp_connect")
int BPF_KPROBE(tcp_conn_prob, struct sock *socket) {
//int tcp_conn_prob(struct pt_regs *regs) {
    //struct sock *socket = (struct sock *)PT_REGS_PARM1_CORE(regs);
    __u16 family = BPF_CORE_READ(socket, __sk_common.skc_family);

    if (family == AF_INET) {
        __be32 saddr = BPF_CORE_READ(socket, __sk_common.skc_rcv_saddr);
        __be32 daddr = BPF_CORE_READ(socket, __sk_common.skc_daddr);
        __be16 dport = BPF_CORE_READ(socket, __sk_common.skc_dport);
        bpf_printk("[%pI4] => [%pI4:%u]", &saddr, &daddr, bpf_ntohs(dport));
    }

    if (family == AF_INET6) {
        __u8 *saddr =
            BPF_CORE_READ(socket, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        __u8 *daddr =
            BPF_CORE_READ(socket, __sk_common.skc_v6_daddr.in6_u.u6_addr8);

        bpf_printk("[%pI6] => [%pI6]", &saddr, &daddr);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
