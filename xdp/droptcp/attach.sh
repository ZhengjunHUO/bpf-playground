#!/bin/bash

ip link set dev $1 xdp obj droptcp.o sec droptcpsection
