#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

SEC("classifier")
int cls_main(struct __sk_buff *skb) { return TC_ACT_OK; }

char __license[] SEC("license") = "Dual MIT/GPL";
