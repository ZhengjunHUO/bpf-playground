#pragma clang diagnostic ignored "-Wcompare-distinct-pointer-types"

#include <bits/types.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define SEC(NAME) __attribute__((section(NAME), used))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __bpf_htons(x) __builtin_bswap16(x)
#define __bpf_constant_htons(x) ___constant_swab16(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __bpf_htons(x) (x)
#define __bpf_constant_htons(x) (x)
#else
#error "Unknown __BYTE_ORDER__ in compiler!"
#endif

#define bpf_htons(x) (__builtin_constant_p(x) ? __bpf_constant_htons(x) : __bpf_htons(x))

unsigned long long load_byte(void *skb, unsigned long long off) asm("llvm.bpf.load.byte");

static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) = (void *)BPF_FUNC_trace_printk;

#define trace_printk(fmt, ...)                                                 \
  do {                                                                         \
    char _fmt[] = fmt;                                                         \
    bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__);                       \
  } while (0)


SEC("classifier")
static inline int mycls(struct __sk_buff *skb) {
  // Get packet's begin and end
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  // ********** Analyze Ether Header  ********** 
  // data pointer begin with the ethernet head
  struct ethhdr *eth_hd = data;

  // get ethernet header's len
  // real size: 6 + 6 + 2 = 14 bytes
  __u32 eth_hdlen = sizeof(*eth_hd);

  // avoid verifier's complain
  if (data + eth_hdlen > data_end) {
    return TC_ACT_OK;
  }

  // check the last 2 bytes eth in header
  // get the protocol type ("08 00" for IP)
  // if the packet's inner protocol is not IP, skip
  if (eth_hd->h_proto != bpf_htons(ETH_P_IP)) {
    return TC_ACT_OK;
  }

  // ********** Analyze IP Header  ********** 
  // jump over the ether header, locate the ip header
  struct iphdr *ip_hd = data + eth_hdlen;

  // get ip header's len stored in ihl(4 bits), value need to * 4 
  // real size: 20 bytes fix + options' len
  __u32 ip_hdlen = ip_hd->ihl << 2;

  // avoid verifier's complain
  if (ip_hd + 20 > data_end) {
    return TC_ACT_OK;
  }

  // get the protocol type ("06" for TCP)
  // if the packet's inner protocol is not TCP, skip
  if (ip_hd->protocol != IPPROTO_TCP) {
    return TC_ACT_OK;
  }

  // ********** Analyze TCP Header  ********** 
  // jump over the ether and ip header, locate the tcp header
  struct tcphdr *tcp_hd = data + eth_hdlen + ip_hdlen;

  // get tcp header's len stored in doff(4 bits), value need to * 4 
  // real size: 20 bytes fix + options' len
  __u32 tcp_hdlen = tcp_hd->doff << 2;

  // avoid verifier's complain
  if (tcp_hd + 20 > data_end) {
    return TC_ACT_OK;
  }

  // IP header + playload size
  __u32 ip_total_length = ip_hd->tot_len;

  // payload's offset (from skb's data)
  __u32 pl_offset = ETH_HLEN + ip_hdlen + tcp_hdlen;
  // payload's size
  __u32 pl_length = ip_total_length - ip_hdlen - tcp_hdlen;

  // ********** Analyze Payload ********** 
  if (pl_length >= 4) {
    unsigned long pl[4];
    int i = 0;
    for (i = 0; i < 4; i++) {
      pl[i] = load_byte(skb, pl_offset + i);
    }

    if ((pl[0] == 'H') && (pl[1] == 'T') && (pl[2] == 'T') && (pl[3] == 'P')) {
      trace_printk("Spot a HTTP request !\n");
    }
  }

  return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
