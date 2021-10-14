#include <linux/bpf.h>
#include <linux/string.h>
#include <linux/ip.h>
#include <linux/if_ether.h>

#define SEC(NAME) __attribute__((section(NAME), used)) 

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)
#endif

struct bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
  unsigned int map_flags;
};

static int (*bpf_map_update_elem)(struct bpf_map_def *map, void *key, void *value, __u64 flags) = (void *) BPF_FUNC_map_update_elem;
static void *(*bpf_map_lookup_elem)(struct bpf_map_def *map, void *key) = (void *)BPF_FUNC_map_lookup_elem;
unsigned long long load_byte(void *skb, unsigned long long off) asm("llvm.bpf.load.byte");

struct bpf_map_def SEC("maps") packetcount = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 64,
};

SEC("socket")
int count_packet(struct __sk_buff *skb) {
  int proto = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
  int *cnt = bpf_map_lookup_elem(&packetcount, &proto);
  int one = 1;
  if (cnt) {
    (*cnt)++;
  } else {
    cnt = &one;
  }
  bpf_map_update_elem(&packetcount, &proto, cnt, BPF_ANY);
  return 0;
}

char _license[] SEC("license") = "GPL";
