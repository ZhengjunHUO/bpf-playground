#!/bin/bash
tc qdisc add dev $1 handle 0: ingress
tc filter add dev $1 ingress bpf obj captureHttp.o flowid 0:
