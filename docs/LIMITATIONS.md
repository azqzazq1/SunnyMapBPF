# Limitations

This section presents an honest assessment of the scope, assumptions, and constraints of this research. We believe transparency about limitations strengthens rather than weakens the findings.

## 1. Privilege Requirement

**BPF Map Poisoning requires `CAP_BPF` (or the superset `CAP_SYS_ADMIN`).** This is a post-exploitation assumption: we do not demonstrate how an attacker obtains this capability, only what can be done once it is obtained. `CAP_BPF` is a powerful capability that already grants significant kernel introspection and, in some configurations, code execution via BPF program loading.

**Counterpoint:** The threat model is realistic. `CAP_BPF` is commonly available in privileged containers (the default in Docker), granted to debugging and profiling tools, and obtainable through numerous documented privilege escalation paths. Furthermore, the value of this research is not in the initial access but in demonstrating that security monitoring can be silently disabled *after* access is obtained -- a gap in the assumed defense-in-depth chain.

## 2. Version Specificity

All experiments were conducted against specific tool versions:

| Tool | Version Tested | Release Date |
|------|---------------|-------------|
| Tracee | v0.24.1 | 2024 |
| Tetragon | v1.4.0 | 2024 |
| Falco | latest (at time of testing) | 2024/2025 |

Map layouts, field offsets, and internal data structures may change between versions. The specific `config_map` layout in Tracee, the `execve_calls` key space in Tetragon, and the `interesting_syscalls` array size in Falco are all implementation details that could be refactored.

**Counterpoint:** While specific offsets may change, the architectural vulnerability persists as long as the tools use mutable, unprotected BPF maps for event-generation control. Version changes may require attack adaptation (different map names, field offsets, or key formats) but do not eliminate the attack class.

## 3. Docker-Based Testing Environment

All tools were deployed in Docker containers following their official quick-start documentation. This introduces several potential differences from bare-metal or Kubernetes production deployments:

- **Container isolation:** Docker's default seccomp profile and capability restrictions may differ from Kubernetes pod security policies or bare-metal deployments.
- **BPF filesystem mounting:** The availability and configuration of `/sys/fs/bpf/` varies across container runtimes.
- **Kernel sharing:** All containers share the host kernel's BPF subsystem, which is the expected behavior but may differ in VM-based isolation environments (Kata Containers, Firecracker).

**Counterpoint:** Docker-based deployment is the most common initial deployment model for all three tools and is explicitly documented in their official getting-started guides. The BPF subsystem is a host-kernel resource regardless of the container runtime, so the attack surface is identical in containerized and bare-metal deployments.

## 4. Map Layout Dependencies

The attacks require knowledge of target map structure:

- **Tracee:** The `config_map` value layout (offset of `enabled_policies` and `policies_version` fields) is determined by the C struct definition in the BPF source code.
- **Tetragon:** The `execve_calls` prog_array key space and `execve_map` entry format depend on internal constants.
- **Falco:** The `interesting_syscalls` array is straightforward (4-byte values indexed by syscall number), but the map name or ID may vary.

An attacker must either (a) reverse-engineer the map layout from the tool's source code or BPF bytecode, or (b) use a version-specific attack payload.

**Counterpoint:** All three tools are open source. Map layouts are documented in source code and stable across patch releases. The PoC scripts in this repository include automated map discovery that does not depend on hardcoded IDs.

## 5. Scope of Map-Based Attacks

This research demonstrates three specific attack instances (one per tool). We do not claim to have exhaustively explored all possible map-based attacks against each tool. Additional attack surfaces may exist:

- **Tracee:** Maps controlling network event filtering, file access policies, or container-specific scoping.
- **Tetragon:** TracingPolicy maps, kprobe argument filter maps, or namespace tracking maps.
- **Falco:** Maps controlling specific rule categories, container metadata, or rate limiting.

The attacks presented target the most critical maps (those controlling global event generation), but more surgical attacks targeting specific detection capabilities are likely possible.

## 6. Single-Node Scope

All testing was performed on a single host. We did not evaluate:

- **Distributed detection architectures** where events are correlated across multiple nodes, potentially enabling detection of per-node blindness through event rate anomaly detection.
- **Centralized policy management** systems (e.g., Tetragon's Helm-based policy distribution) that might detect inconsistencies between configured and effective policies.
- **Multi-cluster deployments** where a poisoned node might be detectable through cross-cluster event correlation.

**Counterpoint:** BPF Map Poisoning is inherently a per-host attack. Detection through distributed correlation would require sophisticated anomaly detection that, to our knowledge, none of the tested tools currently implement.

## 7. Recovery Assessment

We verified recovery through tool restart (Tetragon, Falco) and manual map restoration (Tracee). We did not systematically evaluate:

- **Automatic recovery mechanisms** (if any exist in newer versions)
- **Time-to-detection** in environments with external health monitoring
- **Interaction with orchestration systems** (e.g., Kubernetes liveness probes) that might restart a poisoned tool

## 8. Kernel Version Coverage

Testing was performed on Linux 5.15+ kernels. Older kernels (pre-5.8, before `CAP_BPF` separation from `CAP_SYS_ADMIN`) have a different capability model, and newer kernels (6.9+, with BPF tokens) may offer additional defense options. Our analysis of BPF tokens (see DISCUSSION.md) suggests they do not provide per-map access control, but this has not been empirically verified.

## 9. Attacker Detectability

We claim the attack produces no logs or alerts in the targeted tools. We did not comprehensively evaluate detectability through:

- **Kernel audit subsystem** (`audit` framework): `bpf()` syscalls may be logged if the audit subsystem is configured with appropriate rules.
- **eBPF-based monitors of BPF operations:** A dedicated BPF program attached to `bpf()` syscall entry could potentially detect map modification attempts.
- **Hardware performance counters:** Anomalous BPF map access patterns might be detectable through PMU monitoring, though this is speculative.

These external detection mechanisms are not implemented by default in any standard deployment we are aware of.

## 10. Dual-Use Nature

The PoC scripts and attack techniques described in this research could be used maliciously. While the underlying capabilities (`bpftool map update`) are well-documented and readily available to anyone with `CAP_BPF`, the specific application to security tool evasion and the identification of critical map targets lower the barrier for adversarial use. We address this ethical consideration in ETHICS.md and mitigate it through responsible disclosure.
