- Find available subsystem:tracepoint to attach to:
```bash
cat /sys/kernel/debug/tracing/available_events
```
- To see what happened when the program is running
```bash
cat /sys/kernel/debug/tracing/trace_pipe
```
