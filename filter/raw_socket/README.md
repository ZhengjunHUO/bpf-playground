# How to
- learn from the book Linux Observability with BPF Chapter 6
### Compile the BPF Program and load program
```bash
make
```
### Run (load bpf program, attach to socket) 
```bash
./loadbpf packetcounter.o
```
### Open a second terminal, ping localhost, see the output in the first terminal
```bash
ping 127.0.0.1
```
### Clean up
```bash
make clean
```
