#include <linux/bpf.h>
#include "bpf_helpers.h"

//#define SEC(name) __attribute__((section(name), used))

SEC("cgroup_skb/ingress")
int ingress_filter(struct __sk_buff *skb) {
    return 0;
}

SEC("cgroup_skb/egress")
int egress_filter(struct __sk_buff *skb) {
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
