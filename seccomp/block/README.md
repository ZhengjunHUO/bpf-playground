# How To
### Compile program
```bash
make
```
### Do "ls" with filter, no output
```bash
./blockwrite ls blockwrite.c
```
### Trace the syscall when executing
```bash
strace -f ./blockwrite ls blockwrite.c
...
[pid  3376] write(2, "ls: ", 4)         = -1 EPERM (Operation not permitted)
[pid  3376] write(2, "write error", 11) = -1 EPERM (Operation not permitted)
[pid  3376] write(2, "\n", 1)           = -1 EPERM (Operation not permitted)
```
