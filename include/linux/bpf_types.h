/* internal file - do not include directly */

#ifdef CONFIG_BPF_EVENTS
BPF_PROG_TYPE(BPF_PROG_TYPE_KPROBE, kprobe_prog_ops)
BPF_PROG_TYPE(BPF_PROG_TYPE_TRACEPOINT, tracepoint_prog_ops)
BPF_PROG_TYPE(BPF_PROG_TYPE_PERF_EVENT, perf_event_prog_ops)
#endif
