# 1. Introduction

## 1.1 The Rise of eBPF for Security Monitoring

The Linux kernel's extended Berkeley Packet Filter (eBPF) subsystem has transformed runtime security monitoring. By allowing verified, sandboxed programs to execute at kernel attach points -- tracepoints, kprobes, fentry/fexit, LSM hooks -- eBPF provides security tools with unprecedented visibility into system behavior without requiring custom kernel modules. The performance advantages over ptrace-based and audit-based approaches, combined with the safety guarantees of the BPF verifier, have driven rapid adoption across the cloud-native ecosystem.

Three tools dominate eBPF-based runtime security: Falco (CNCF graduated project, Sysdig), Tracee (Aqua Security), and Tetragon (Cilium/Isovalent, now part of the CNCF). Together, these tools are deployed on millions of production nodes across major cloud providers and enterprise Kubernetes clusters. Each implements a fundamentally similar architecture: BPF programs attached to kernel hooks generate security-relevant events, BPF maps store configuration and runtime state, and a userspace daemon consumes events via perf buffers or ring buffers for policy evaluation and alerting.

## 1.2 The Trust Assumption

The security model of these tools rests on an implicit but critical assumption: *kernel-resident state is protected from external tampering*. Because BPF programs execute in kernel context and BPF maps reside in kernel memory, tool developers treat map contents as trusted. Configuration values written to maps at initialization time are assumed to persist unmodified. Process tracking tables are assumed to reflect actual kernel state. Tail call routing arrays are assumed to maintain their programmed dispatch tables.

This assumption conflates two distinct properties: the integrity of BPF *program* execution (which the verifier and JIT compiler do protect) and the integrity of BPF *map* contents (which the kernel does not protect beyond an initial capability check). The `bpf(2)` syscall provides a fully documented, stable API for any process with `CAP_BPF` to enumerate all BPF maps on the system, obtain file descriptors to maps belonging to other programs, and read or write arbitrary entries. No ownership model, access control list, or namespace isolation restricts cross-program map access at runtime.

## 1.3 Our Contribution

This paper makes the following contributions:

1. **Attack class identification.** We define BPF map poisoning as a distinct attack class: the modification of BPF map entries belonging to a defensive tool by an adversary process, using the legitimate `bpf(2)` syscall interface, to suppress or corrupt security event generation at the kernel level.

2. **Systematic vulnerability analysis.** We analyze the BPF map usage of Falco, Tracee, and Tetragon, identifying specific maps whose modification achieves total event suppression. For each tool, we document the map name, type, value structure, and the semantic effect of specific field modifications.

3. **Empirical demonstration.** We implement and dynamically verify three concrete attack instances against production releases of each tool. Each attack achieves complete suppression of security events -- zero events where baseline operation produced 14-16 events -- using a single `bpftool` command requiring only `CAP_BPF`.

4. **Defense analysis.** We evaluate the available kernel-level mitigation mechanisms -- `bpf_map_freeze()`, `BPF_F_RDONLY_PROG`, `BPF_F_WRONLY_PROG`, BPF token scoping (kernel 6.9+) -- and assess their applicability to each tool's architecture. We identify that none of the tested tools employ any of these mechanisms and discuss the architectural constraints that make adoption non-trivial.

5. **Attack taxonomy.** We establish a taxonomy of BPF map poisoning primitives: policy disablement, process invisibility, pipeline breakage, syscall filter suppression, and container exemption, providing a framework for analyzing the map-based attack surface of future eBPF security tools.

## 1.4 Key Finding

Across all three tools tested, BPF maps containing security-critical configuration and state are writable by any process with `CAP_BPF`. No tool employs `bpf_map_freeze()`, marks maps with `BPF_F_RDONLY_PROG`, implements runtime integrity checks on map contents, or monitors for external map modifications. The attacks require no BPF program loading, no verifier bypass, and no kernel exploit. They operate entirely within the designed and documented BPF API, exploiting not a kernel vulnerability but an architectural gap in the tools' threat models.

## 1.5 Paper Structure

The remainder of this paper is organized as follows. Section 2 provides technical background on the eBPF architecture, BPF map types, and the architectures of the three target security tools. Section 3 formalizes the threat model, specifying attacker capabilities and assumptions. Section 4 presents the attack design, including our map inventory methodology, attack primitive taxonomy, and per-tool attack vectors. Section 5 describes the implementation, covering map discovery, struct layout analysis, and version-aware manipulation techniques. Section 6 presents the evaluation methodology and results, with per-tool event suppression measurements. Section 7 surveys related work in BPF security research and runtime monitoring evasion. Section 8 discusses the implications of our findings and analyzes potential defenses. Section 9 addresses limitations and future work. Section 10 concludes.
