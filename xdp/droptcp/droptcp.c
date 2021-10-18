#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#define SEC(NAME) __attribute__((section(NAME), used))

SEC("droptcpsection")
int drop_tcp(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct iphdr *ip = data + sizeof(struct ethhdr); 
  int hd_ln = sizeof(struct ethhdr) + sizeof(struct iphdr);

  if (data + hd_ln > data_end) {
    return XDP_DROP;
  }

  if (ip->protocol == IPPROTO_TCP) {
    return XDP_DROP;
  }

  return XDP_PASS;
}
