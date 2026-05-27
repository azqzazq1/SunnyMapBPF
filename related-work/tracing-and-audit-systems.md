# Tracing and Audit Systems

## Overview

Linux provides multiple tracing and auditing frameworks that operate at different layers of the kernel. The Linux audit subsystem, ftrace, perf, kprobes, tracepoints, and uprobes form the foundation on which eBPF-based monitoring tools are built. This survey covers these traditional tracing mechanisms, how eBPF extends them, and whether the audit subsystem and other non-BPF tracing frameworks are vulnerable to attacks similar to BPF map poisoning.

---

## 1. The Linux Audit Subsystem

### Architecture

The Linux audit subsystem (auditd) provides a kernel-to-userspace event logging framework designed for compliance and security auditing. It operates through:

- **Kernel audit framework**: In-kernel code that generates audit records at audit hook points
- **auditd daemon**: Userspace daemon that receives records via netlink socket and writes to log files
- **auditctl**: Command-line tool for configuring audit rules at runtime
- **audit rules**: Configuration specifying which events to log (syscalls, file access, etc.)

### Audit Event Generation

Audit rules are evaluated at specific kernel hook points:

```
# Example audit rules
-a always,exit -F arch=b64 -S execve -k process_execution
-a always,exit -F arch=b64 -S openat -F dir=/etc -k config_access
-w /etc/passwd -p wa -k passwd_changes
```

The kernel evaluates audit rules synchronously in the syscall path. When a rule matches, the kernel generates an audit record containing syscall number, arguments, return value, process context (UID, PID, comm), and SELinux context.

### Security Model

The audit subsystem's security model differs fundamentally from eBPF tools:

- **Kernel-native**: Audit hooks are compiled into the kernel, not loaded dynamically
- **Protected configuration**: Modifying audit rules requires `CAP_AUDIT_CONTROL`; rules are stored in kernel memory, not BPF maps
- **Tamper evidence**: The audit subsystem can be configured in "immutable mode" (`-e 2`), after which rules cannot be changed until reboot
- **Netlink-based**: Audit records are delivered via netlink, not BPF ring buffers

### Comparison with BPF-Based Monitoring

| Property | Linux Audit | eBPF Tools (Falco, Tracee) |
|---|---|---|
| Configuration storage | Kernel data structures | BPF maps |
| Config modification | `CAP_AUDIT_CONTROL` | `CAP_BPF` (any map writable) |
| Immutable mode | Yes (`-e 2`) | No (no equivalent) |
| Config protection | Kernel-internal, not BPF-accessible | BPF maps, globally accessible |
| Event transport | Netlink socket | Perf/ring buffers |
| Performance | Higher overhead (synchronous) | Lower overhead (in-kernel filtering) |
| Flexibility | Rule-based (limited grammar) | Programmable (BPF programs) |
| io_uring visibility | Limited (being improved) | Limited (syscall-based tools) |

### Is Audit Vulnerable to Similar Attacks?

The audit subsystem is **not** vulnerable to BPF map poisoning because its configuration is not stored in BPF maps. However, it has its own attack surfaces:

1. **auditd process kill**: An attacker with root can kill the auditd daemon, stopping log collection (but the kernel continues generating records; they queue in the kernel buffer)
2. **Rule deletion**: `auditctl -D` deletes all audit rules (requires `CAP_AUDIT_CONTROL`). Mitigated by immutable mode.
3. **Log tampering**: If the attacker can write to `/var/log/audit/`, they can modify or delete logs. Remote log shipping mitigates this.
4. **Netlink backpressure**: Flooding the audit netlink socket can cause record drops (the kernel has limited buffer space). However, the kernel logs "audit: backlog limit exceeded" when this occurs.

The audit subsystem's resistance to configuration tampering (via immutable mode and kernel-internal rule storage) serves as a model for how BPF-based tools *could* protect their configuration.

---

## 2. ftrace

### Architecture

ftrace (Function Tracer) is the kernel's built-in tracing framework. It provides:

- **Function tracing**: Trace entry/exit of kernel functions
- **Function graph tracing**: Trace call graphs with timing
- **Event tracing**: Trace predefined kernel events (tracepoints)
- **Dynamic tracing**: kprobes and kretprobes
- **Tracefs**: Filesystem interface at `/sys/kernel/tracing/` (or `/sys/kernel/debug/tracing/`)

### ftrace and eBPF

eBPF programs can attach to ftrace hooks:

- `BPF_PROG_TYPE_TRACING` (fentry/fexit): Attach to function entry/exit via ftrace
- `BPF_PROG_TYPE_KPROBE`: Attach to kprobes (which use ftrace on supported architectures)

ftrace's infrastructure provides the hook mechanism; eBPF provides the programmable processing logic.

### Security Considerations

ftrace configuration is controlled via tracefs:

- Requires `CAP_SYS_ADMIN` or appropriate tracefs permissions
- Configuration is not stored in BPF maps (it is in kernel data structures exposed via tracefs)
- An attacker with root access can disable ftrace by writing to tracefs, but this is detectable (the files are world-readable, monitoring tools can check)

---

## 3. perf_event

### Architecture

perf is the kernel's performance analysis framework. It provides:

- **Hardware performance counters**: CPU cycles, cache misses, branch mispredictions
- **Software events**: Context switches, page faults, CPU migrations
- **Tracepoint events**: Kernel tracepoints
- **USDT (User Statically Defined Tracepoints)**: User-space tracepoints

### perf and eBPF

eBPF programs can attach to perf events:

- `BPF_PROG_TYPE_PERF_EVENT`: Process perf samples in-kernel
- BPF-based profilers (Parca, py-spy BPF mode) use perf events for CPU sampling
- `perf_event_open()` returns a file descriptor that can be used as an eBPF attachment point

### Security Considerations

perf_event access is governed by:

- `CAP_PERFMON` (or `CAP_SYS_ADMIN`)
- `kernel.perf_event_paranoid` sysctl (0-3, restricting unprivileged access)
- Event-specific permissions for hardware counters

perf events are not stored in BPF maps; they are kernel data structures managed by the perf subsystem. An attacker cannot poison perf events via BPF map modification.

---

## 4. kprobes and kretprobes

### Architecture

kprobes (Kernel Probes) allow dynamic instrumentation of arbitrary kernel functions:

- **kprobe**: Trigger at function entry (or any instruction address)
- **kretprobe**: Trigger at function return
- **Mechanism**: kprobes work by replacing the instruction at the probe point with a breakpoint (`int3` on x86) or a trampoline

### kprobes and eBPF

eBPF programs commonly attach to kprobes:

```c
SEC("kprobe/do_sys_openat2")
int trace_openat(struct pt_regs *ctx) { ... }

SEC("kretprobe/do_sys_openat2")
int trace_openat_ret(struct pt_regs *ctx) { ... }
```

- Tracee uses kprobes for file operation, network, and process tracing
- Tetragon uses kprobes for TracingPolicy enforcement
- Falco uses kprobes for supplementary event collection

### Security Considerations

kprobe attachment requires `CAP_BPF` + `CAP_PERFMON` (or `CAP_SYS_ADMIN`). The kprobe infrastructure itself (list of active probes, probe handlers) is stored in kernel data structures, not BPF maps. An attacker cannot disable kprobes via BPF map modification.

However, the *eBPF programs* attached to kprobes use BPF maps for configuration and output. Poisoning these maps does not remove the kprobe attachment but changes what the BPF program does when the kprobe fires (e.g., the program executes but discards all events due to a poisoned config map).

---

## 5. Tracepoints

### Architecture

Tracepoints are statically defined instrumentation points in the kernel source code. Unlike kprobes (which are dynamic and can be placed anywhere), tracepoints are:

- Predefined by kernel developers at specific, stable locations
- Have a defined argument structure (stable ABI)
- Lower overhead than kprobes (optimized for production use)
- Available via `/sys/kernel/tracing/events/` or the `perf_event_open()` interface

### Key Tracepoint Categories for Security

| Category | Examples | Used By |
|---|---|---|
| `syscalls` | `sys_enter_openat`, `sys_exit_execve` | Falco, Tracee |
| `sched` | `sched_process_exec`, `sched_process_exit` | Process monitoring |
| `raw_syscalls` | `sys_enter`, `sys_exit` | Falco (raw tracepoints) |
| `net` | `net_dev_queue`, `netif_receive_skb` | Network monitoring |
| `signal` | `signal_generate`, `signal_deliver` | Signal tracing |
| `io_uring` | `io_uring_submit_sqe`, `io_uring_complete` | io_uring monitoring |

### BPF and Tracepoints

eBPF programs attach to tracepoints via:

- `BPF_PROG_TYPE_TRACEPOINT`: Standard tracepoint attachment
- `BPF_PROG_TYPE_RAW_TRACEPOINT`: Lower-overhead raw tracepoint attachment (no argument copying)

Falco's eBPF driver primarily uses raw tracepoints (`raw_syscalls:sys_enter`, `raw_syscalls:sys_exit`) for maximum performance.

### Security Considerations

Tracepoint definitions are kernel-compiled and cannot be modified at runtime. The tracepoint infrastructure is not stored in BPF maps. However, the eBPF programs attached to tracepoints are subject to the same map poisoning: the tracepoint fires, the BPF program executes, but the program's behavior is determined by (potentially poisoned) map contents.

---

## 6. uprobes

### Architecture

uprobes (User-space Probes) allow dynamic instrumentation of user-space functions:

- Probe placement by virtual address or symbol name in ELF binaries
- Mechanism: kernel replaces instruction at probe point with breakpoint
- Trigger: when user-space process executes the probed instruction, control transfers to kernel, which runs the uprobe handler (including any attached eBPF programs)

### Security Use Cases

- SSL/TLS key logging (probing `SSL_write`/`SSL_read` in OpenSSL/BoringSSL)
- Application-level tracing (function call monitoring)
- Pixie uses uprobes extensively for protocol-aware tracing

### Security Considerations

uprobe attachment is stored in kernel data structures. BPF map poisoning does not affect uprobe attachment but can corrupt the data collected by uprobe-attached BPF programs.

---

## 7. BPF Trampoline (fentry/fexit)

### Architecture (Kernel 5.5+)

BPF trampolines provide a more efficient alternative to kprobes for function entry/exit tracing:

- Direct code patching (no breakpoint overhead)
- Access to function arguments with BTF type information
- Lower overhead than kprobes (~3ns vs. ~60ns per invocation)
- Used by `BPF_PROG_TYPE_TRACING` programs with `fentry`/`fexit`/`fmod_ret` attachment

### Security Implications

- `fmod_ret` allows BPF programs to modify function return values, enabling enforcement (similar to `bpf_override_return()`)
- BPF trampolines are managed by the kernel's BPF subsystem, not stored in BPF maps
- However, the BPF programs using trampolines may consult BPF maps for policy decisions -- these maps are poisonable

---

## 8. Traditional Audit vs. eBPF-Based Monitoring

### Comparison Matrix

| Aspect | Linux Audit (auditd) | eBPF Tools |
|---|---|---|
| **Architecture** | Kernel hooks + netlink + userspace daemon | BPF programs + maps + userspace agent |
| **Configuration** | Kernel data structures | BPF maps |
| **Performance** | Higher overhead (synchronous, context switch per event) | Lower overhead (in-kernel processing, batched output) |
| **Flexibility** | Rule grammar (limited, declarative) | BPF programs (Turing-complete, imperative) |
| **Tamper resistance** | Immutable mode (`-e 2`), kernel-internal rules | None (maps writable by any `CAP_BPF`) |
| **Completeness** | Syscall-focused, limited io_uring | Hook-dependent (syscall, LSM, VFS) |
| **Deployment** | Standard on all Linux systems | Requires recent kernel, tool deployment |
| **Compliance** | STIG, PCI-DSS, SOC2 certified | Not standardized for compliance |
| **Self-protection** | Yes (immutable mode, protected config) | No (unprotected BPF maps) |

### The Performance-Security Tradeoff

The eBPF ecosystem gained traction largely because of performance advantages over the audit subsystem. In-kernel BPF programs can filter, aggregate, and enrich events without the context-switch overhead of sending every event to userspace. BPF maps are the key enabler of this performance: they allow kernel-side state management and filtering.

However, this performance architecture introduces the security vulnerability: the same maps that enable efficient kernel-side processing are also the attack surface for BPF map poisoning. The audit subsystem's less efficient architecture (kernel generates events, userspace processes them) avoids this vulnerability because there is no kernel-side mutable state that controls event generation.

---

## 9. Is the Audit Subsystem Vulnerable to Similar Attacks?

### Direct Comparison

| Attack Vector | Audit Subsystem | eBPF Tools |
|---|---|---|
| Config modification | Requires `CAP_AUDIT_CONTROL`; immutable mode blocks all changes | Requires `CAP_BPF`; no immutable mode |
| Config stored in | Kernel data structures (not BPF maps) | BPF maps (globally accessible) |
| Process kill | `kill auditd` stops logging (kernel buffers temporarily) | `kill agent` stops processing (kernel programs may continue) |
| Log tampering | Modify `/var/log/audit/` (requires root + file access) | Modify BPF maps (requires `CAP_BPF` only) |
| Kernel-level suppression | Not possible without kernel exploit | Possible via BPF map poisoning |

### The Critical Difference

The audit subsystem's configuration is **not stored in a globally accessible data structure**. Audit rules are kernel-internal; they cannot be modified via BPF map operations. Even `auditctl` (the legitimate configuration tool) operates via a dedicated netlink socket with capability checks, not via a general-purpose data modification interface.

eBPF tools chose BPF maps as their configuration mechanism because maps are the natural BPF data structure. This was an engineering decision (BPF programs can only access BPF maps, not arbitrary kernel data structures), but it has security consequences: the configuration is stored in the most permissive kernel data structure available.

### Hybrid Approaches

A future design could combine the performance of eBPF with the tamper resistance of the audit subsystem:

1. **Immutable BPF configuration**: Use `bpf_map_freeze()` for configuration maps, requiring program reload to change configuration (analogous to audit immutable mode)
2. **Signed configuration**: Cryptographically sign map contents, verify in BPF program before use
3. **Kernel-side integrity**: Store critical configuration in kernel data structures (e.g., BPF program `.rodata`) rather than mutable maps
4. **Heartbeat verification**: Userspace agent periodically reads and verifies map contents, alerting on unexpected changes

---

## 10. Relevance to BPF Map Poisoning

The tracing and audit landscape provides two key insights for BPF map poisoning research:

1. **The audit subsystem demonstrates that tamper-resistant monitoring is achievable in Linux**. Immutable audit rules, kernel-internal configuration storage, and dedicated modification interfaces provide a security model that BPF-based tools could aspire to. The audit subsystem proves that the BPF tools' lack of self-protection is a design choice, not a technical necessity.

2. **eBPF extends traditional tracing but inherits a new vulnerability**. kprobes, tracepoints, and ftrace are kernel-native mechanisms whose configuration is stored in protected kernel data structures. When eBPF programs attach to these hooks, they gain the flexibility of programmable processing but lose the tamper resistance of kernel-native configuration. The BPF map -- the bridge between the kernel hook and the BPF program's logic -- is the weak link.

The comparison between the audit subsystem and eBPF tools makes the case that BPF map poisoning is not an inevitable consequence of kernel monitoring but rather a consequence of choosing a permissive data structure (BPF maps) for security-critical configuration. Alternative designs exist and are proven in production (the audit subsystem has been protecting Linux systems for over two decades).
