# eBPF Observability and Telemetry

## Overview

eBPF has become the dominant technology for Linux observability and telemetry, enabling deep kernel-level instrumentation without kernel module development or recompilation. Observability tools use BPF programs and maps to collect performance metrics, trace system calls, profile applications, and monitor network flows. While observability tools differ from security tools in their primary purpose, they share the same BPF map architecture and are thus exposed to the same poisoning attack surface. This survey covers the major observability tools, their relationship to security tools, and the shared vulnerability surface.

---

## 1. BCC (BPF Compiler Collection)

### Background

- **Developer**: IOVisor Project (Linux Foundation)
- **Repository**: `iovisor/bcc`
- **First release**: 2015 (one of the earliest eBPF user-facing toolkits)
- **Language**: Python/Lua front-end, C BPF programs compiled via LLVM at runtime

### Architecture

BCC provides a framework for writing BPF programs in C, compiled at runtime using an embedded LLVM/Clang toolchain. It includes 100+ pre-built tools for system analysis:

- **Process**: `execsnoop`, `opensnoop`, `exitsnoop`, `runqlat`
- **Filesystem**: `ext4slower`, `fileslower`, `filetop`
- **Network**: `tcpconnect`, `tcpaccept`, `tcplife`, `tcpretrans`
- **Memory**: `memleak`, `oomkill`, `slabratetop`
- **CPU**: `cpudist`, `profile`, `offcputime`, `llcstat`

Each tool creates BPF maps to aggregate data (histograms, counts, per-PID statistics) and uses perf buffers or BPF ring buffers to stream events to userspace.

### BPF Map Usage

BCC tools typically create:
- `BPF_HASH` maps for per-key aggregation (e.g., per-PID syscall counts)
- `BPF_HISTOGRAM` (implemented as `BPF_MAP_TYPE_PERCPU_ARRAY`) for latency distributions
- `BPF_PERF_OUTPUT` or `BPF_RINGBUF_OUTPUT` for event streaming

These maps are transient (exist only while the tool runs) and unauthenticated -- any `CAP_BPF` process can read or modify them.

### Relevance

BCC tools are the foundation for many ad-hoc investigations and are sometimes deployed persistently in production. An attacker who poisons BCC map data can corrupt diagnostic information, potentially masking performance anomalies that would indicate malicious activity. More importantly, BCC demonstrates the BPF map pattern that all subsequent tools inherited.

---

## 2. bpftrace

### Background

- **Developer**: Brendan Gregg (Netflix), Alastair Robertson, community
- **Repository**: `bpftrace/bpftrace`
- **Architecture**: High-level tracing language (awk-like syntax) compiled to BPF programs
- **Deployment**: Primarily interactive debugging, increasingly used for production monitoring

### Architecture

bpftrace compiles a domain-specific language into BPF programs and maps. Example:

```
bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf("%s %s\n", comm, str(args->filename)); }'
```

This generates a BPF program attached to the `sys_enter_openat` tracepoint, with maps for string storage and output buffering.

### Map Usage

bpftrace creates maps for:
- **`@` variables**: Global associative arrays stored in `BPF_MAP_TYPE_HASH`
- **`@` histograms**: Stored in `BPF_MAP_TYPE_PERCPU_ARRAY` or equivalent
- **String buffers**: Temporary storage for `str()` and `printf()` formatting
- **Stack traces**: `BPF_MAP_TYPE_STACK_TRACE` for `kstack` / `ustack`

All maps are accessible to any `CAP_BPF` process during the bpftrace session.

### Relevance

bpftrace is increasingly used as a forensic investigation tool. If an investigator runs bpftrace to trace suspicious activity on a compromised host, an attacker with `CAP_BPF` could poison the tracing maps to suppress or corrupt evidence, a scenario where observability tool poisoning directly impacts security.

---

## 3. Pixie (CNCF Sandbox)

### Background

- **Developer**: Pixie Labs (acquired by New Relic, 2020)
- **Repository**: `pixie-io/pixie`
- **Architecture**: Auto-instrumentation via BPF uprobes and kprobes; in-cluster data processing
- **Key feature**: Protocol-aware tracing (HTTP, gRPC, MySQL, Kafka, DNS) without code changes

### Architecture

Pixie deploys eBPF programs (PEMs -- Pixie Edge Modules) as DaemonSets that automatically instrument application protocols by attaching uprobes to TLS libraries (OpenSSL, BoringSSL, Go crypto/tls) and kprobes to socket operations. Data is stored in-cluster in a columnar format and queried via PxL (Pixie Query Language).

### BPF Map Usage

Pixie uses BPF maps for:
- **Connection tracking**: Hash maps mapping socket file descriptors to connection metadata
- **Protocol parsing state**: Per-connection state machines for protocol decoding
- **TLS key extraction**: Maps storing intercepted TLS session keys for decryption
- **Data buffers**: Per-CPU arrays for assembling protocol messages before userspace transfer

### Security Implications

Pixie's TLS key extraction maps are particularly security-sensitive: they contain cryptographic session keys that enable decryption of otherwise encrypted traffic. Poisoning these maps could either inject false keys (causing decryption failure that masks exfiltration) or read legitimate keys (providing an attacker with the ability to decrypt captured traffic).

---

## 4. Hubble (Cilium)

### Background

- **Developer**: Isovalent (now Cisco), part of the Cilium project
- **Repository**: `cilium/hubble`
- **Architecture**: Built on top of Cilium's eBPF datapath; observes network flows via BPF events
- **Key feature**: Kubernetes-aware network observability (pod-to-pod, pod-to-service, pod-to-external)

### Architecture

Hubble is not a standalone BPF tool; it reads events from Cilium's existing BPF datapath. Cilium's BPF programs (attached to TC and XDP hooks) generate network flow events that Hubble aggregates and exposes via API and CLI.

### Shared Map Surface with Cilium

Because Hubble relies on Cilium's BPF maps, poisoning Cilium's network policy maps or connection tracking maps would simultaneously affect both network policy enforcement (Cilium) and network observability (Hubble). This creates a dual-impact attack surface where a single map poisoning operation compromises both security enforcement and observability.

---

## 5. Cilium Observability Stack

### Architecture

Cilium's observability capabilities extend beyond Hubble:

- **Metrics**: BPF maps aggregate per-endpoint, per-service, and per-policy-verdict metrics, exported to Prometheus
- **Flow logs**: BPF programs generate flow events (L3/L4/L7) stored in per-CPU ring buffers
- **Policy verdict logging**: Each network policy decision is logged with context from BPF maps

### BPF Map Dependency

Cilium's observability is deeply intertwined with its enforcement datapath. The same BPF maps that store network policies, endpoint identities, and connection tracking state are used to generate observability data. This coupling means that observability data integrity depends on enforcement map integrity, and vice versa.

---

## 6. Parca (Continuous Profiling)

### Background

- **Developer**: Polar Signals
- **Repository**: `parca-dev/parca-agent`
- **Architecture**: BPF-based continuous CPU profiling with stack unwinding
- **Key feature**: Always-on, low-overhead profiling with DWARF-based stack unwinding in BPF

### BPF Map Usage

Parca Agent uses BPF maps for:
- **Stack trace storage**: `BPF_MAP_TYPE_STACK_TRACE` for kernel and user stack traces
- **Profile aggregation**: Per-CPU hash maps for aggregating sample counts per stack trace
- **Unwind tables**: Large array maps storing DWARF unwind information for user-space stack walking

---

## 7. Observability vs. Security: Architectural Comparison

### Shared Patterns

| Aspect | Observability Tools | Security Tools |
|---|---|---|
| BPF program hooks | kprobes, tracepoints, uprobes | kprobes, tracepoints, LSM hooks |
| Data storage | BPF maps (hash, array, per-CPU) | BPF maps (hash, array, prog_array) |
| Event transport | perf buffers, ring buffers | perf buffers, ring buffers |
| Map protection | None (no freeze, no RDONLY) | None (no freeze, no RDONLY) |
| Userspace processing | Aggregation, display | Rule matching, alerting |
| Map access control | CAP_BPF only | CAP_BPF only |

### Key Differences

1. **Enforcement capability**: Security tools (especially Tetragon) can enforce policies by blocking operations. Observability tools are passive.

2. **Tail call usage**: Security tools like Tetragon use `PROG_ARRAY` tail calls extensively for event processing pipelines. Observability tools rarely use tail calls.

3. **Map longevity**: Security tool maps persist for the lifetime of the security daemon (continuously running). Observability tool maps may be transient (bpftrace sessions, BCC tool invocations).

4. **State criticality**: Poisoning a security tool's maps suppresses threat detection. Poisoning an observability tool's maps corrupts performance data. Both are damaging, but security tool poisoning has more immediate security impact.

---

## 8. Shared Vulnerability Surface

### The Common BPF Map Problem

All observability and security tools share the same fundamental vulnerability: BPF maps are globally accessible to any process with `CAP_BPF`. There is no namespace isolation for BPF maps (BPF maps exist in a global ID space), no ownership model (any process can open any map by ID), and no access control beyond the initial capability check.

### Cross-Tool Attack Scenarios

1. **Observability-to-security pivot**: An attacker who initially targets observability tools (lower perceived impact) can use the same techniques to pivot to security tool maps. The `bpf(BPF_MAP_GET_NEXT_ID)` syscall enumerates all maps on the system regardless of their owner.

2. **Observability corruption as cover**: An attacker poisons both security and observability maps simultaneously. Security map poisoning prevents detection; observability map poisoning prevents forensic analysis of performance anomalies that might indicate compromise.

3. **Shared map discovery**: The `bpf(BPF_MAP_GET_INFO_BY_FD)` syscall reveals map name, type, key/value size, and max entries -- sufficient to identify which maps belong to which tools and determine the correct poisoning payload.

### Map Discovery and Enumeration

An attacker with `CAP_BPF` can enumerate all BPF maps on the system:

```
bpftool map list    # Lists all maps with ID, type, name, and size
bpftool map dump id <N>  # Reads all entries from a map
bpftool map update id <N> key <K> value <V>  # Modifies entries
```

Map names often reveal their purpose (`interesting_syscalls`, `config_map`, `execve_map`, `policy_filter`), making target identification straightforward. Neither map listing nor map modification generates any kernel audit event by default.

---

## 9. OpenTelemetry and eBPF

### eBPF in the OpenTelemetry Ecosystem

The OpenTelemetry project has embraced eBPF as a zero-instrumentation collection mechanism:

- **OpenTelemetry eBPF Collector** (`open-telemetry/opentelemetry-ebpf-profiler`): Continuous profiling agent using BPF for stack sampling.
- **Beyla** (Grafana): eBPF-based auto-instrumentation for HTTP/gRPC services, generating OpenTelemetry-compatible traces and metrics without code changes.

These tools introduce additional BPF maps into the system, each unprotected and accessible to co-located attackers.

---

## 10. Relevance to BPF Map Poisoning

The observability tool landscape amplifies the BPF map poisoning threat in several ways:

1. **Increased map population**: Production Kubernetes nodes running Cilium + Tetragon + Falco + Pixie may have hundreds of BPF maps active simultaneously, all unprotected, creating a large attack surface.

2. **Forensic blindness**: If an attacker poisons observability tool maps alongside security tool maps, post-incident forensic analysis based on eBPF-collected data is unreliable.

3. **Shared design patterns**: The observability community's conventions (map naming, aggregation patterns, event buffering) are well-documented and predictable, reducing the reconnaissance effort required for targeted poisoning.

4. **Legitimacy of BPF access**: In environments where observability tools require `CAP_BPF` for legitimate purposes, restricting `CAP_BPF` to prevent poisoning also restricts observability, creating a capability management dilemma.
