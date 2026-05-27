# 6. Evaluation

## 6.1 Experimental Setup

All experiments were conducted on a single host with the following configuration:

| Component | Specification |
|-----------|--------------|
| Kernel | Linux 5.15+ / 6.x with BPF JIT enabled |
| Architecture | x86\_64 |
| BPF tooling | bpftool (matching kernel version) |
| Container runtime | Docker CE |
| Tracee | aquasec/tracee:latest (v0.24.1) |
| Tetragon | quay.io/cilium/tetragon:v1.4.0 |
| Falco | falcosecurity/falco:latest |

Each tool was deployed in its documented Docker configuration with `--privileged`, `--pid=host`, and the recommended volume mounts for kernel headers, debug filesystem, and BPF filesystem access. These configurations match the deployment patterns described in each tool's official documentation and Kubernetes deployment manifests.

## 6.2 Experimental Protocol

Each experiment follows a five-phase protocol designed to establish causality between map poisoning and event suppression:

**Phase 1: Setup.** Deploy the target tool in a fresh container. Wait 15 seconds for BPF program loading, map initialization, and initial process scanning to complete.

**Phase 2: Baseline measurement.** Generate a standardized workload of system activity (process execution, file access, user identification commands) and measure the number of security events or alerts produced by the tool. This establishes that the tool is functioning correctly and actively monitoring the system.

**Phase 3: Poisoning.** Execute the map poisoning attack against the identified target map(s). Record the exact commands issued and verify the map modification via a subsequent map read.

**Phase 4: Blindness verification.** Generate the identical workload as Phase 2 and measure the number of events or alerts produced. The hypothesis under test is that the count drops to zero.

**Phase 5: Restoration.** Demonstrate that the effect is reversible by either restoring the original map values (Tracee) or restarting the tool (Tetragon, Falco), then repeating the workload to confirm event generation resumes.

The standardized workload consists of the following operations, chosen to trigger multiple event types across all tools:

| Operation | Expected Event Type |
|-----------|-------------------|
| `/bin/ls /etc/shadow` | file access, process exec |
| `/bin/cat /etc/passwd` | file read, process exec |
| `/usr/bin/whoami` | process exec |
| `/usr/bin/id` | process exec |
| `/bin/uname -a` | process exec |
| `/bin/ps aux` | process exec, file reads |
| `/usr/bin/find /tmp -maxdepth 1` | process exec, directory scan |
| `/bin/bash -c "echo test"` | process exec (shell) |

## 6.3 Metrics

**Primary metric: Event suppression ratio.** Defined as 1 - (post-poison events / baseline events). A ratio of 1.0 indicates complete suppression. We report absolute event counts alongside the ratio.

**Secondary metric: Attack latency.** The wall-clock time between issuing the poisoning command and observing the first suppressed event (i.e., the time for the poisoned state to take effect). For all three tools, this is bounded by the next BPF program invocation cycle -- effectively instantaneous for tracepoint-attached programs.

**Tertiary metric: Restoration success.** Whether the tool resumes normal event generation after map restoration or tool restart.

## 6.4 Results

### 6.4.1 Tracee v0.24.1

| Metric | Value |
|--------|-------|
| Baseline events | 16 |
| Post-poison events | 0 |
| Suppression ratio | 1.0 (100%) |
| Attack command count | 1 (`bpftool map update`) |
| Fields modified | 2 (`enabled_policies`, `policies_version`) |
| Bytes modified | 10 (8 bytes for u64 + 2 bytes for u16) |
| Attack latency | < 1 BPF invocation cycle |
| Restoration method | Map value restore (no restart required) |
| Post-restore events | > 0 (confirmed recovery) |

The Tracee attack achieved complete suppression with a single map update operation modifying 10 bytes within the 256-byte `config_entry_t` value. The version bump ensured immediate cache invalidation across all CPUs. After restoring the original `enabled_policies` value and `policies_version`, Tracee resumed event generation without requiring a process restart, confirming that the BPF programs and userspace daemon remained functional throughout the attack.

### 6.4.2 Tetragon v1.4.0

| Metric | Value |
|--------|-------|
| Baseline process\_exec events | 14+ |
| Baseline total events | 14+ |
| Post-poison process\_exec events | 0 |
| Post-poison total events | 0 |
| Suppression ratio | 1.0 (100%) |
| Attack commands | 2 (`bpftool map delete` x2) + N (`bpftool map delete` per PID entry) |
| Maps modified | 2 (`execve_calls`, `execve_map`) |
| Attack latency | < 1 BPF invocation cycle |
| Restoration method | Container restart required |
| Post-restore events | > 0 (confirmed recovery) |

The Tetragon attack required two phases: prog\_array deletion (2 commands, instantaneous) and hash map clearing (N commands where N = number of tracked processes, typically 50-200 entries on a production system, completing in under 2 seconds). The combined effect was total blindness across all event types, not just process execution events. This is because the `execve_map` clearing affects all sensors that depend on process context, which in Tetragon's architecture is all sensors.

Unlike Tracee, Tetragon could not be restored by simply rewriting the map values: the prog\_array entries reference BPF program file descriptors that are not recoverable from userspace without re-loading the programs. A full container restart was required to restore monitoring.

### 6.4.3 Falco (Latest)

| Metric | Value |
|--------|-------|
| Baseline alerts | 1+ |
| Post-poison alerts | 0 |
| Suppression ratio | 1.0 (100%) |
| Attack commands | 512 (`bpftool map update` x512) |
| Entries modified | 512 (all syscall slots) |
| Bytes modified | 512 (1 byte per entry) |
| Attack latency | < 1 BPF invocation cycle (per modified syscall) |
| Restoration method | Container restart required |
| Post-restore alerts | > 0 (confirmed recovery) |

The Falco attack required the most individual operations (512 map updates) but each is a trivial single-byte write. The attack is parallelizable and could be optimized using `BPF_MAP_UPDATE_BATCH` (kernel 5.6+) to a single syscall. Falco does not repopulate `interesting_syscalls` at runtime, so the attack persists until Falco is restarted.

Note on Falco baseline: Falco's baseline alert count is workload-dependent and rule-dependent. In our testing, the standardized workload triggered at least one Falco rule (e.g., "Read sensitive file untrusted" for `/etc/shadow` access). The exact count varies by Falco version and default ruleset. The critical metric is the transition from non-zero to zero alerts.

## 6.5 Cross-Tool Comparison

| Property | Tracee | Tetragon | Falco |
|----------|--------|----------|-------|
| Map type attacked | ARRAY | PROG\_ARRAY + HASH | ARRAY |
| Discovery method | ID enumeration | Pinned filesystem | ID enumeration |
| Attack commands | 1 | 2 + N | 512 |
| Map knowledge required | Struct layout | Entry keys only | None (all entries zeroed) |
| Version sensitivity | High (struct offsets) | Low (stable pin paths) | Low (stable map structure) |
| Restoration complexity | Low (map rewrite) | High (restart required) | Medium (restart required) |
| Selective suppression | Yes (per-policy bits) | Partial (per-PID deletion) | Yes (per-syscall) |

The comparison reveals a trade-off between attack complexity and restoration difficulty. Tracee requires the most structural knowledge (exact struct offsets) but offers the easiest restoration. Tetragon requires the least structural knowledge (just delete entries) but causes the most persistent damage. Falco requires no structural knowledge (zero all entries) but needs the most individual operations.

## 6.6 Reversibility Demonstration

All three attacks are fully reversible, confirming that the effect is not caused by tool crashes, memory corruption, or permanent state damage:

**Tracee:** Writing the original `enabled_policies` value and `policies_version` back to `config_map` immediately restores event generation. No restart required. Events generated during the blind period are permanently lost (they were dropped in-kernel, not queued).

**Tetragon:** A container restart causes Tetragon to re-load all BPF programs, re-populate `execve_calls` with correct prog\_array entries, and re-scan `/proc` to rebuild `execve_map`. Normal monitoring resumes within 12-15 seconds of restart.

**Falco:** A container restart causes the `libscap` initialization code to re-populate `interesting_syscalls` based on the loaded ruleset. Normal alerting resumes within 10-15 seconds of restart.

The reversibility property has dual implications: it confirms the attack's mechanism (data-plane manipulation, not code corruption) but also means an attacker's evasion window is bounded by the tool's monitoring for unexpected restarts or external health checks.
