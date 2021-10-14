#include <bpf/bpf_load.h>
#include <bpf/sock_example.h>
#include <assert.h>

char bpf_log_buf[BPF_LOG_BUF_SIZE];

int main(int argc, char **argv) {
  // Get bpf program's name
  char buffer[64];
  sprintf(buffer, "%s", argv[1]);
  // Load bpf prog to kernel, store its fd to prog_fd[0] 
  if (load_bpf_file(buffer)) {
    printf("%s", bpf_log_buf);
    return -1;
  }

  // create RAW socket and bind to the loopback interface 
  int sock = open_raw_sock("lo");
  // attach the bpf prog to the raw socket
  if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, prog_fd, sizeof(prog_fd[0]))) {
    printf("Failed to setsockopt: %s\n", strerror(errno));
    return -1;
  }

  // Observe the number of packet of specific protocol counted by bpf program
  int i, packet_type, tcps, udps, icmps;
  for (i = 0; i < 20; i++) {
    packet_type = IPPROTO_TCP;
    assert(bpf_map_lookup_elem(map_fd[0], &packet_type, &tcps) == 0);

    packet_type = IPPROTO_UDP;
    assert(bpf_map_lookup_elem(map_fd[0], &packet_type, &udps) == 0);

    packet_type = IPPROTO_ICMP;
    assert(bpf_map_lookup_elem(map_fd[0], &packet_type, &icmps) == 0);

    printf("Ingress packet number: TCP[%d] UDP[%d] ICMP[%d]\n", tcps, udps, icmps);
    sleep(1);
  }
}
