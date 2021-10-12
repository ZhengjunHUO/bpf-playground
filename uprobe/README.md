- Compile the target program to be attached to
```bash
go build -o helloworld helloworld.go
```
- Run uprobe/uretprobe program
```bash
go run uprobe.go
go run uretprobe.go
```
- Find out available "symbols" in binary  
```bash
nm helloworld | grep <PATTERN>
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;uretprobe.go's example output
```
      helloworld-4722    [000] d...  8517.366436: bpf_trace_printk: [PID: 4722] Execute helloworld at 315537958...
      helloworld-4722    [000] d...  8517.370604: bpf_trace_printk: [PID: 4722] helloworld returned, cost 4175829 ns!
```
- To see what happened when the program is running
```bash
cat /sys/kernel/debug/tracing/trace_pipe
```
