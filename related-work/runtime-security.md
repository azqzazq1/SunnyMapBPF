# Runtime Security Tools

## Overview

eBPF-based runtime security tools represent the current state of the art in cloud-native threat detection and enforcement. These tools attach BPF programs to kernel hooks (tracepoints, kprobes, LSM hooks, fentry/fexit) to monitor system activity in real time, generating security events and optionally enforcing policies. This survey covers the major tools, their architectures, security models, and documented limitations, with emphasis on how their design exposes them to BPF map poisoning.

---

## 1. Falco (CNCF Graduated)

### Background

- **Developer**: Originally Sysdig, now a CNCF Graduated project (graduated 2024)
- **Repository**: `falcosecurity/falco`, `falcosecurity/libs`
- **Architecture**: Kernel driver (kmod or eBPF) captures system call events, userspace engine (libsinsp/libscap) applies rules
- **Deployment**: DaemonSet in Kubernetes, standalone on bare metal
- **Scale**: Widely deployed across CNCF ecosystem; used by major cloud providers' managed Kubernetes offerings

### Technical Architecture

Falco's eBPF driver attaches BPF programs to raw tracepoints for syscall entry and exit (`sys_enter` / `sys_exit`). The core filtering mechanism is the `interesting_syscalls` array:

- **Type**: `BPF_MAP_TYPE_ARRAY`, 512 entries (indexed by syscall number)
- **Function**: Each byte indicates whether the corresponding syscall should be captured (nonzero) or skipped (zero)
- **Population**: `libscap` populates the array at startup based on the loaded Falco rule set. Only syscalls referenced by active rules are marked interesting.
- **Kernel-side check**: The BPF program reads `interesting_syscalls[syscall_nr]` at the top of the tracepoint handler. If zero, the event is discarded immediately -- it never reaches the perf/ring buffer or userspace.

Additional critical maps include `syscall_table` (maps syscall numbers to handler functions), `settings_map` (global configuration such as `boot_time`, `snaplen`, `dropping_mode`), and the perf/ring buffer maps for event transport.

### Security Model

Falco's documentation describes its threat model in terms of detecting container escapes, privilege escalation, and anomalous system behavior. The implicit assumption is that Falco's kernel-side filtering state is authoritative. The documentation does not address:

- External modification of `interesting_syscalls` by a co-located `CAP_BPF` process
- Runtime integrity verification of map contents
- Use of `bpf_map_freeze()` to protect configuration maps after initialization

### Documented Limitations

- **Syscall-only visibility**: Falco's eBPF driver monitors syscalls. Activity that does not transit the syscall interface (e.g., io_uring completions, some kernel-internal operations) may not be captured.
- **Performance filtering**: The `interesting_syscalls` design is explicitly a performance optimization -- avoiding the cost of capturing and processing unneeded syscalls. Its security implications (providing a single point of suppression) are not discussed.
- **Drop counting**: Falco tracks dropped events (when the ring buffer is full) but does not detect events that were *never generated* due to map state changes.

---

## 2. Tracee (Aqua Security)

### Background

- **Developer**: Aqua Security
- **Repository**: `aquasecurity/tracee`
- **Architecture**: BPF programs on tracepoints, kprobes, LSM hooks; Go userspace with libbpfgo
- **Key feature**: Policy-based filtering entirely in kernel via BPF maps

### Technical Architecture

Tracee uses a sophisticated in-kernel policy engine. The central data structure is `config_map`:

- **Type**: `BPF_MAP_TYPE_ARRAY`, single entry (index 0)
- **Contents**: A struct containing `enabled_policies` (bitmask of active policies), `policies_version` (monotonically increasing version counter), and additional filtering metadata
- **Kernel-side logic**: The `match_scope_filters()` function checks `enabled_policies` against event filters. When `enabled_policies == 0`, no policy matches any event, and all events are discarded.

Additional critical maps:

- **`policies_config_map`**: Per-policy configuration including event sets, UID filters, PID filters, and scope definitions
- **`events_map`**: Maps event IDs to the set of policies subscribed to each event
- **`proc_info_map`**: Hash map of process metadata (PIDs, namespaces, container IDs) used for scope filtering
- **`containers_map`**: Maps container IDs to runtime metadata

### Security Model

Tracee's policy engine is designed to filter events at the kernel level for performance. The filtering metadata -- which policies are active, which events each policy subscribes to, which processes are in scope -- is entirely stored in BPF maps that are writable by any `CAP_BPF` process.

### Relevant Research

- **Guo and Zeng, "Phantom Attack: Evading System Call Monitoring" (NDSS 2023)**. Demonstrated TOCTOU (time-of-check-time-of-use) attacks against syscall argument tracing. An attacker modifies syscall arguments in shared memory between the point where the tracing tool reads them and the point where the kernel uses them. This work targeted the *data integrity* of event arguments, not the *configuration integrity* of the tracing tool itself. BPF map poisoning is a different class: rather than corrupting individual event data, it suppresses event generation entirely.

---

## 3. Tetragon (Cilium/Isovalent)

### Background

- **Developer**: Isovalent (now part of Cisco), maintained as part of the Cilium project
- **Repository**: `cilium/tetragon`
- **Architecture**: BPF programs on kprobes, tracepoints, LSM hooks, uprobes; Go userspace agent
- **Key feature**: Runtime enforcement (not just detection) via BPF LSM hooks and `bpf_override_return()`
- **Production deployment**: Integrated with Cilium in major Kubernetes platforms (GKE Dataplane V2, EKS, AKS)

### Technical Architecture

Tetragon's architecture centers on **tail calls** and **pinned maps**:

- **`execve_calls`** (`BPF_MAP_TYPE_PROG_ARRAY`): A tail call dispatch table mapping indices to BPF programs. The main entry-point program for `execve` tracing performs a `bpf_tail_call()` into this map. If the target index is empty or the tail call fails, execution falls through (silently -- tail call failure is not an error in BPF semantics).

- **`execve_map`** (`BPF_MAP_TYPE_HASH`): Maps PIDs to process metadata (binary path, namespace info, capability sets, parent PID). This is Tetragon's process tree. Every security event is enriched with process context from this map.

- **Pinned map namespace**: All maps are pinned to `/sys/fs/bpf/tetragon/` for cross-program state sharing and persistence. Pinning makes maps discoverable via the filesystem, simplifying programmatic access (both legitimate and malicious).

- **Enforcement pipeline**: For TracingPolicy resources that specify `matchActions` with `action: Override` or `action: Signal`, Tetragon attaches BPF LSM programs that call `bpf_override_return()` or `bpf_send_signal()`. The enforcement decision depends on data from BPF maps (which processes to enforce on, which syscalls to block).

### Security Model

Tetragon's documentation (Fournier et al., 2023) describes a security model focused on detecting and enforcing policy at the kernel level. The use of BPF LSM hooks is presented as providing stronger guarantees than tracepoint-based monitoring alone, since LSM hooks are in the kernel's security decision path.

However, the enforcement pipeline's correctness depends on the integrity of multiple BPF maps:

- If `execve_calls` entries are deleted, the tail call chain breaks and execution falls through without processing
- If `execve_map` is cleared, all process context is lost; events cannot be attributed to processes
- If enforcement policy maps are modified, enforcement rules change silently

None of these maps use `bpf_map_freeze()` or `BPF_F_RDONLY_PROG`.

---

## 4. Sysdig (Commercial)

### Background

- **Developer**: Sysdig, Inc.
- **Architecture**: Kernel module or eBPF driver (shared codebase with Falco via `falcosecurity/libs`), commercial userspace platform
- **Key feature**: Comprehensive runtime security, compliance, and forensics platform

### Technical Architecture

Sysdig shares its kernel instrumentation layer with Falco (the `libs` repository). The `interesting_syscalls` filtering mechanism is identical. The commercial platform adds:

- Cloud-native threat detection rules (Sysdig Secure)
- Kubernetes audit log integration
- Image scanning and drift detection
- Forensic capture and replay

### Relevance

Because Sysdig shares the `falcosecurity/libs` kernel driver, the same BPF map poisoning attacks that affect Falco apply to Sysdig's eBPF driver. The `interesting_syscalls` array is the same data structure, populated the same way, and unprotected by the same absence of `bpf_map_freeze()`.

---

## 5. LKRG (Linux Kernel Runtime Guard)

### Background

- **Developer**: Openwall Project (Solar Designer)
- **Architecture**: Kernel module (not eBPF-based), integrity verification via periodic checks
- **Key feature**: Detects kernel code and critical data structure modifications at runtime

### Technical Architecture

LKRG takes a fundamentally different approach from eBPF tools: it periodically verifies the integrity of kernel text, module code, and critical data structures (IDT, GDT, syscall table, security-related function pointers) by comparing against stored reference hashes. It does not use BPF and is not affected by BPF map poisoning.

### Relevance

LKRG represents an alternative integrity verification model. Its approach -- computing and periodically checking cryptographic hashes of critical state -- could inform mitigation strategies for BPF map poisoning. A "BPF map integrity guard" that periodically hashes critical map contents and alerts on unexpected changes would be the BPF analog of LKRG's kernel integrity checking.

---

## 6. Kubearmor

### Background

- **Developer**: AccuKnox
- **Architecture**: BPF LSM hooks and AppArmor integration
- **Key feature**: Combines eBPF runtime visibility with AppArmor policy enforcement

### Technical Architecture

KubeArmor uses BPF LSM programs for visibility and AppArmor profiles for enforcement. Its BPF maps store monitoring configuration and process context. Like other eBPF tools, its maps are not protected with `bpf_map_freeze()`.

---

## 7. Cross-Tool Analysis: Shared Architectural Patterns

### Common Vulnerabilities

All eBPF runtime security tools share several architectural characteristics that expose them to BPF map poisoning:

| Pattern | Tools Affected | Risk |
|---|---|---|
| Configuration in BPF ARRAY maps | All | Single-point policy suppression |
| Process tracking in BPF HASH maps | Tracee, Tetragon | Process context erasure |
| Tail call dispatch via PROG_ARRAY | Tetragon | Execution pipeline disruption |
| Maps not frozen after initialization | All | Runtime modification by any `CAP_BPF` process |
| No runtime integrity checks | All | Modifications undetected |
| No userspace heartbeat for map state | All | No reconciliation of kernel-side state |

### Why Tools Don't Use `bpf_map_freeze()`

Several factors explain the absence of map freezing:

1. **Dynamic configuration**: Some maps must be updated at runtime (e.g., adding new policies, updating process tracking). `bpf_map_freeze()` is a one-way operation; frozen maps cannot be updated by the tool itself.

2. **Architecture decisions**: Maps that *could* be frozen (e.g., `interesting_syscalls`, `config_map` after initial setup) are simply not frozen, likely because the threat was not considered during design.

3. **Startup sequencing**: The tool must populate maps before freezing, requiring careful ordering of initialization steps. For tools that reload or reconfigure at runtime, freezing is incompatible with the current architecture.

4. **No kernel notification**: If a map is modified, there is no kernel mechanism to notify the owning process. Even if a tool wanted to detect map tampering, it would need to poll map contents.

---

## 8. Detection Capabilities of Existing Tools

### What They Detect

- **Process execution** (execve, execveat)
- **File access** (open, openat, read, write, unlink)
- **Network connections** (connect, accept, bind, sendto, recvfrom)
- **Privilege escalation** (setuid, setgid, capset, ptrace)
- **Module loading** (init_module, finit_module)
- **Container escapes** (namespace manipulation, mount namespace pivoting)
- **Kernel exploitation indicators** (kernel module loading, kexec)

### What They Cannot Detect (When Poisoned)

When BPF map poisoning suppresses event generation at the kernel level, the tools cannot detect any activity -- including the `bpf()` syscall used to perform the poisoning itself. This is because:

1. The `bpf()` syscall is typically in the `interesting_syscalls` set, but if the *entire* array is zeroed, even `bpf()` events are suppressed.
2. Even if `bpf()` events were captured before poisoning, the poisoning itself (a single `BPF_MAP_UPDATE_ELEM` call) would appear as a legitimate BPF operation, indistinguishable from normal map management by authorized tools.
3. The tools have no self-monitoring capability: they do not check whether their own map contents have been modified.

---

## 9. Relevance to BPF Map Poisoning

The runtime security tool landscape demonstrates a systemic architectural vulnerability: every major tool stores its security-critical kernel-side state in BPF maps that lack access control beyond initial `CAP_BPF` checks. The tools' detection capabilities -- however sophisticated their rule sets and policy engines -- are predicated on the integrity of this map state. BPF map poisoning attacks the foundation on which all detection logic rests.

The diversity of attack surfaces (configuration arrays, process tracking hash maps, tail call dispatch tables) means that poisoning attacks can be tailored to each tool's architecture, achieving different effects (policy suppression, context erasure, pipeline disruption) but the same outcome: complete evasion.
