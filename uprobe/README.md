- Compile the target program and run uprobe program
```bash
go build -o helloworld helloworld.go
go run uprobe.go
```
- Find out available "symbols" in binary  
```bash
nm helloworld | grep <PATTERN>
```
- To see what happened when the program is running
```bash
cat /sys/kernel/debug/tracing/trace_pipe
```
