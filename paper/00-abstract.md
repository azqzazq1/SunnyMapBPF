# BPF Map Poisoning: A Cross-Tool Evasion Technique Against eBPF-Based Security Monitoring

**Azizcan Dastan**
Milenium Security

## Abstract

Extended Berkeley Packet Filter (eBPF) has become the dominant instrumentation framework for runtime security monitoring in cloud-native environments. Tools such as Falco, Tracee, and Tetragon attach BPF programs to kernel tracepoints, kprobes, and LSM hooks, relying on BPF maps as the primary mechanism for configuration storage, process tracking, and inter-program control flow. The implicit security assumption underlying this architecture is that kernel-resident state is protected from tampering by non-kernel actors. This paper demonstrates that assumption to be false.

We introduce BPF map poisoning, a class of evasion attacks in which an adversary with `CAP_BPF` modifies the runtime BPF map state of a security tool to suppress event generation entirely at the kernel level. Using only the legitimate `bpf(2)` syscall interface -- `BPF_MAP_GET_NEXT_ID` for enumeration, `BPF_MAP_GET_FD_BY_ID` for access, and `BPF_MAP_UPDATE_ELEM`/`BPF_MAP_DELETE_ELEM` for modification -- we achieve complete event suppression against three widely deployed tools: Tracee v0.24.1 (16 to 0 events via `config_map` policy zeroing), Tetragon v1.4.0 (14 to 0 events via `execve_calls` prog\_array deletion and `execve_map` clearing), and Falco (1+ to 0 alerts via `interesting_syscalls` array zeroing). Each attack executes via a single command, takes effect within one BPF program invocation, and produces no logs or alerts from the targeted tool. We find that none of the tested tools employ `bpf_map_freeze()`, `BPF_F_RDONLY_PROG`, or any runtime map integrity verification. We analyze root causes, survey available kernel mitigations, and argue that the eBPF security ecosystem requires fundamental reassessment of its intra-kernel trust model.

**Keywords:** eBPF, BPF maps, security evasion, runtime monitoring, Falco, Tracee, Tetragon, cloud-native security, kernel security, map poisoning
