# How To
### Bring up a http server at 0.0.0.0:8000 
```bash
python3 -m http.server &
```
### From remote check the port 8000 of the first machine 
```
nmap -Pn -p 8000 <FIRST_SERVER_PUB_IP>
...
PORT     STATE SERVICE
8000/tcp open  http-alt
```
### On first machine, compile the xdp program
```bash
make
```
### Attach the compiled xdp program to public interface
```bash
./attach.sh eth1
```
### Check the difference in the output of ip a command 
```
ip a
...
-3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
+3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdpgeneric/id:36 qdisc fq_codel state UP group default qlen 1000
```
### On remote, redo nmap
```
nmap -Pn -p 8000 192.168.33.10
...
PORT     STATE    SERVICE
8000/tcp filtered http-alt
```
### Detach the xdp program
```bash
./detach.sh eth1
```
### Clean up
```bash
make clean
```
### Compatibility
- possible to attach the compiled(under v5.11) xdp program to a host's interface running under lower kernel version with 
```
CONFIG_XDP_SOCKETS=y
```
- Tested on a Debian 4.19



