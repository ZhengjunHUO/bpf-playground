# How to
- learn from the book Linux Observability with BPF Chapter 6
### Compile the BPF Program
```bash
make
```
### Load bpf program to netif 
```bash
./attach.sh eth0
```
### Read the output
```bash
cat /sys/kernel/debug/tracing/trace_pipe
          <idle>-0       [000] d.s. 19289.903041: bpf_trace_printk: Spot a HTTP request !
```
OR
```bash
tc exec bpf dbg
Running! Hang up with ^C!

          <idle>-0       [000] d.s. 19819.014678: bpf_trace_printk: Spot a HTTP request !
```
### Open a second terminal, do a curl, see the output in the first terminal
```bash
curl ifconfig.co
```
### Detach bpf program from netif
```bash
./detach.sh eth0
```
### Clean up
```bash
make clean
```
