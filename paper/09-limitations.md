# 9. Limitations and Future Work

## 9.1 Limitations

**Single-host scope.** Our evaluation targets individual host-level tool deployments. In production Kubernetes environments, security tools are typically deployed as DaemonSets with centralized alert aggregation (e.g., Falco + Falcosidekick, Tetragon + Hubble). An alert rate drop to zero on a single node may trigger centralized anomaly detection if the aggregation layer monitors per-node event rates. Our evaluation does not assess the effectiveness of such out-of-band detection mechanisms.

**Version specificity.** The Tracee attack depends on the `config_entry_t` struct layout, which is version-specific. The offsets documented (offset 14 for `policies_version`, offset 216 for `enabled_policies`) are verified for v0.24.1 but may change in future releases. The Tetragon and Falco attacks are less version-sensitive (they operate on map structure rather than struct internals) but are still subject to architectural changes in future releases.

**Static workload.** Our evaluation uses a fixed set of system operations to generate events. Production workloads are more diverse and continuous. The attack's effectiveness in production is expected to be identical (the poisoning disables event generation at the BPF program level, regardless of workload characteristics), but this has not been verified in a production environment.

**CAP_BPF acquisition not demonstrated.** We assume the attacker has already obtained `CAP_BPF`. The paper does not demonstrate specific techniques for acquiring this capability. In practice, `CAP_BPF` can be obtained through container escape from a privileged container, exploitation of a kernel vulnerability, or misconfigured capability grants, but the feasibility of each path is environment-dependent.

**Limited tool coverage.** We evaluated three open-source tools. The eBPF security ecosystem includes additional tools (Cilium network policies, Pixie, Inspektor Gadget, commercial products from vendors such as Sysdig, Aqua, Isovalent, and CrowdStrike) that may have different map protection postures. Our methodology generalizes to these tools, but we have not verified attacks against them.

**No kernel version matrix.** All experiments were conducted on a single kernel version family. While the `bpf(2)` map manipulation API is stable across kernel versions (5.8+), we have not verified that the attacks work identically on all supported kernels. Variations in BPF verifier behavior, map implementation details, or capability checks across kernel versions could theoretically affect the results, though we consider this unlikely given the API stability guarantees.

## 9.2 Future Work

**Automated map vulnerability scanning.** We envision a tool that automatically analyzes BPF maps on a running system, classifies them by security criticality (based on owning program type, map flags, and update patterns), and identifies maps that are security-critical but unprotected. Such a tool could be integrated into security auditing pipelines and CI/CD systems.

**Cross-namespace map isolation.** The BPF subsystem currently provides no namespace-scoped map isolation. Investigating kernel-level mechanisms for restricting map access to the creating namespace (or a designated set of namespaces) would address the root cause of the vulnerability. The BPF token mechanism (kernel 6.9+) provides a foundation for this, but its application to map access control in the security tool context has not been explored.

**Stealthy map poisoning detection.** Developing kernel-level or hypervisor-level mechanisms to detect unauthorized map modifications without relying on the security tool's own integrity checks. Potential approaches include eBPF-based map modification auditing (attaching a BPF program to the `bpf(2)` syscall entry that logs `BPF_MAP_UPDATE_ELEM` operations targeting protected maps) or hardware-assisted integrity monitoring.

**Tool-specific mitigations.** Working with the maintainers of Falco, Tracee, and Tetragon to implement the defenses analyzed in Section 8.3. The specific implementation strategy (map freezing, integrity monitoring, heartbeat, or a combination) will depend on each tool's architectural constraints and performance requirements.

**Map poisoning in enforcement mode.** Tetragon supports enforcement mode, where BPF programs can kill processes that violate policies (via `bpf_send_signal()`). We have not evaluated whether map poisoning can disable enforcement actions. If the enforcement decision depends on maps that are similarly unprotected, an attacker could disable both monitoring and enforcement simultaneously, which would represent a more severe security impact than monitoring evasion alone.

**Temporal analysis.** Characterizing the detection window: how quickly must an integrity check run to detect poisoning before the attacker completes their objective? This depends on the attacker's post-evasion activity timeline and the integrity check's polling interval. Modeling this as a race condition would inform the required polling frequency for effective detection.

**Batch operation optimization.** Investigating the use of `BPF_MAP_UPDATE_BATCH` and `BPF_MAP_DELETE_BATCH` (kernel 5.6+) to reduce the Falco attack from 512 syscalls to 1, and the Tetragon `execve_map` clearing from N syscalls to 1. This would reduce the attack's syscall footprint and make syscall-level detection harder.
