## Compile phase
```bash
make
```

## Execute phase, observe the output in Terminal
```bash
./pinmap
ls /sys/fs/bpf/
./getmap
```

## Cleanup phase
```
make clean
```

## About EPERM
eBPF program uses locked memory (default 64k). If memory is not sufficient, bpf_create_map return Operation not permitted error. Do:
```bash
ulimit -l <BIG_NUM>
```
to increase the limit.
