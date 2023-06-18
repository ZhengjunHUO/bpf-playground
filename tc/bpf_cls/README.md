# How to
- learn from the book Linux Observability with BPF Chapter 6
### Compile the BPF Program
```bash
make

# check object
objdump -h captureHttp.o
```
### Load bpf program to netif 
```bash
./attach.sh eth0
```
### Check change in qdisc list
```bash
tc qdisc ls
qdisc noqueue 0: dev lo root refcnt 2 
qdisc fq_codel 0: dev eth0 root refcnt 2 limit 10240p flows 1024 quantum 1514 target 5ms interval 100ms memory_limit 32Mb ecn drop_batch 64 
++ qdisc ingress ffff: dev eth0 parent ffff:fff1 ---------------- 
qdisc fq_codel 0: dev eth1 root refcnt 2 limit 10240p flows 1024 quantum 1514 target 5ms interval 100ms memory_limit 32Mb ecn drop_batch 64 
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
## If bpf program is attached to loopback interface, bring up a http server locally
```bash
python3 -m http.server &
curl 127.0.0.1:8000
```

# Explore
```
# Add delay to packet
$ sudo tc qdisc add dev enp0s3 root netem delay 100ms
$ sudo tc qdisc del dev enp0s3 root

# BPF direct action
$ sudo tc qdisc add dev enp0s3 clsact
$ sudo tc filter add dev enp0s3 ingress|egress bpf da obj foo.o [sec bar]
$ tc filter show dev enp0s3 ingress|egress
$ sudo tc filter del dev enp0s3 ingress|egress
$ sudo tc qdisc delete dev enp0s3 clsact
```
