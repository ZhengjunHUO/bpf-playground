#include <linux/bpf.h>
#include <netinet/ip.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") egress_blacklist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(_Bool),
    .max_entries = 1000,
};

/*
SEC("cgroup_skb/ingress")
int ingress_filter(struct __sk_buff *skb) {
    // Drop all
    return 0;
}
*/

SEC("cgroup_skb/egress")
int egress_filter(struct __sk_buff *skb) {
    struct iphdr iphd;
    bpf_skb_load_bytes(skb, 0, &iphd, sizeof(struct iphdr));
    //bpf_printk("Egress to %lu",iphd.daddr);

    return !bpf_map_lookup_elem(&egress_blacklist, &iphd.daddr);
}

char __license[] SEC("license") = "Dual MIT/GPL";
