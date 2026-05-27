# Future Work and Roadmap

## 1. Expanded Tool Coverage

### 1.1 Cilium Network Policies

Cilium uses eBPF for network policy enforcement in Kubernetes. Its datapath programs consult BPF maps (e.g., `cilium_policy`, `cilium_ipcache`, `cilium_lxc`) to make allow/deny decisions on network packets. Poisoning these maps could potentially:

- Bypass network policies, allowing traffic that should be blocked
- Redirect traffic between endpoints
- Disable network-level security enforcement cluster-wide

Cilium's maps are pinned under `/sys/fs/bpf/tc/globals/`, making them enumerable. This represents the highest-priority extension of this research because Cilium network policies are a critical security boundary in many Kubernetes deployments.

**Priority:** High
**Estimated effort:** 2-3 weeks
**Prerequisites:** Cilium test cluster, understanding of Cilium datapath map layouts

### 1.2 bpftrace and BCC Tools

bpftrace and BCC (BPF Compiler Collection) are widely used for ad-hoc tracing and observability. While not security tools per se, they are sometimes used for security-relevant monitoring (e.g., tracing sensitive file access, monitoring privilege escalation attempts). Poisoning their maps could:

- Suppress tracing output during an attack
- Inject false data into tracing results
- Disable performance monitoring that might detect anomalous behavior

**Priority:** Medium
**Estimated effort:** 1-2 weeks

### 1.3 KubeArmor

KubeArmor uses eBPF (via BPF LSM hooks) for container-level security policy enforcement. Its maps control which operations are allowed or denied. Poisoning these maps could bypass security policies without triggering any policy violation alert.

**Priority:** Medium-High
**Estimated effort:** 2 weeks

### 1.4 Inspektor Gadget

Inspektor Gadget (CNCF sandbox project) provides eBPF-based debugging and monitoring tools for Kubernetes. Its gadgets use BPF maps for filtering and state management. The map poisoning attack surface follows the same pattern as the tools already tested.

**Priority:** Medium
**Estimated effort:** 1 week

### 1.5 Pixie (New Relic)

Pixie uses eBPF for full-stack observability in Kubernetes. While primarily an observability tool, its data collection mechanisms could be suppressed through map poisoning, creating blind spots in application performance monitoring.

**Priority:** Low-Medium
**Estimated effort:** 1-2 weeks

## 2. Kernel-Level Defense Prototypes

### 2.1 Per-Map ACL Kernel Patch

Develop a proof-of-concept kernel patch that adds per-map access control lists to the BPF subsystem. The prototype would:

- Extend `struct bpf_map` with an ACL structure (owner UID, allowed program IDs)
- Add a `BPF_MAP_SET_ACL` command to the `bpf()` syscall
- Enforce ACL checks on `BPF_MAP_UPDATE_ELEM` and `BPF_MAP_DELETE_ELEM`
- Provide backward compatibility (maps without ACLs retain current behavior)

This would be submitted as an RFC to the BPF mailing list (bpf@vger.kernel.org) for community review.

**Priority:** High
**Estimated effort:** 4-6 weeks (development + testing + documentation)
**Dependencies:** Kernel development environment, BPF selftests

### 2.2 Map Owner Process Binding

A simpler kernel patch that associates each map with an "owner" process (the creator) and restricts modification to the owner:

- Implemented via a new `BPF_F_OWNER_ONLY` flag on `bpf(BPF_MAP_CREATE)`
- Owner tracked by `struct pid` reference (survives PID reuse)
- Maps with this flag reject `BPF_MAP_UPDATE_ELEM` from non-owner processes

**Priority:** High
**Estimated effort:** 2-3 weeks
**Dependencies:** Kernel development environment

### 2.3 BPF LSM Hook Extension

Extend the existing BPF LSM framework to include hooks for map data operations:

- `bpf_map_update_elem` hook: called before every map update, allowing LSM policies to approve/deny
- `bpf_map_delete_elem` hook: called before every map deletion
- Policy integration with SELinux and AppArmor for label-based map access control

**Priority:** Medium-High
**Estimated effort:** 3-4 weeks

## 3. Automated Map Integrity Verification Tool

### 3.1 Design

Develop an open-source tool ("BPF Map Watchdog" or similar) that provides runtime integrity verification for BPF maps belonging to security tools. Features:

- **Map registration:** Security tools register critical maps and their expected state (schema, canary values, acceptable value ranges)
- **Periodic verification:** The watchdog reads registered maps at configurable intervals and compares against expected state
- **Tamper alerting:** Discrepancies generate alerts via syslog, webhook, or dedicated event channel
- **Auto-recovery:** Optionally re-populate poisoned maps from cached expected state
- **Independent channel:** Alerting does not depend on the monitored tool's event pipeline

### 3.2 Architecture

```
+------------------+     +-------------------+     +--------------+
| Security Tool    |     | BPF Map Watchdog  |     | Alert Sink   |
| (Falco/Tracee/   |     | (independent      |     | (syslog,     |
|  Tetragon)       |     |  process)         |     |  webhook,    |
+--------+---------+     +--------+----------+     |  SIEM)       |
         |                        |                 +--------------+
    Creates maps            Reads & verifies              ^
         |                        |                       |
         v                        v                       |
+--------+---------+     +--------+----------+            |
| BPF Maps         |<----| Integrity Check   |--alert--->-+
| (kernel)         |     | (periodic read +  |
+------------------+     |  compare)         |
                         +-------------------+
```

**Priority:** High
**Estimated effort:** 4-8 weeks (MVP)
**Language:** Go or Rust (for BPF interaction libraries)
**Dependencies:** libbpf, cilium/ebpf (Go), or aya (Rust)

### 3.3 Integration with Existing Tools

Provide integration plugins for:
- Falco: Register `interesting_syscalls` map with expected non-zero values
- Tracee: Register `config_map` with expected `enabled_policies` and `policies_version`
- Tetragon: Register `execve_calls` prog_array with expected entry count

## 4. Broader BPF Attack Surface Exploration

### 4.1 Ring Buffer Poisoning

Investigate whether BPF ring buffers (`BPF_MAP_TYPE_RINGBUF`) can be corrupted to:
- Inject false security events into the tool's userspace consumer
- Cause the consumer to crash or enter an error state
- Overflow the ring buffer to cause event loss

**Priority:** Medium
**Estimated effort:** 2-3 weeks

### 4.2 Prog_Array Hijacking

Investigate whether an attacker can replace tail-call targets in prog_arrays with attacker-controlled BPF programs:
- Requires `CAP_BPF` + ability to load BPF programs
- Could redirect execution flow within a security tool's BPF pipeline
- More powerful than deletion (substitution vs. suppression)

**Priority:** Medium-High
**Estimated effort:** 3-4 weeks

### 4.3 BPF Link Manipulation

Investigate attacks against BPF links (the mechanism that attaches BPF programs to events):
- Can links be detached by a non-owner process?
- Can link parameters be modified to change the attachment point?
- What are the access control checks on `bpf(BPF_LINK_DETACH)`?

**Priority:** Medium
**Estimated effort:** 2 weeks

### 4.4 Map-of-Maps Redirection

For tools using `BPF_MAP_TYPE_ARRAY_OF_MAPS` or `BPF_MAP_TYPE_HASH_OF_MAPS`, investigate whether inner map pointers can be replaced to redirect data flow to attacker-controlled maps.

**Priority:** Low-Medium
**Estimated effort:** 2 weeks

## 5. Academic Publication

### 5.1 Paper Submission

Prepare a peer-reviewed academic paper based on this research, targeting one of the following venues:

| Venue | Type | Deadline (typical) | Relevance |
|-------|------|-------------------|-----------|
| USENIX Security Symposium | Conference | February/October | Top-tier systems security |
| ACM CCS | Conference | May | Top-tier security |
| NDSS | Conference | May/September | Network and distributed systems security |
| IEEE S&P (Oakland) | Conference | December | Top-tier security |
| EuroSys | Conference | October | Systems |
| USENIX ATC | Conference | January | General systems |

**Priority:** High
**Estimated effort:** 6-8 weeks (writing, revision, submission)

### 5.2 Paper Structure

1. Introduction and motivation
2. Background (eBPF, BPF maps, security tools)
3. Threat model
4. Attack design and implementation
5. Experimental evaluation
6. Mitigations and defense analysis
7. Discussion
8. Related work
9. Conclusion

## 6. Community Engagement

### 6.1 Conference Presentations

Submit to practitioner-oriented conferences for broader impact:

- **DEF CON / Black Hat** -- Offensive security audience, tool demos
- **KubeCon + CloudNativeCon** -- Cloud-native security track, direct engagement with tool maintainers
- **Linux Plumbers Conference** -- BPF/networking track, direct engagement with kernel developers
- **eBPF Summit** -- Focused eBPF community, technical depth

### 6.2 Upstream Contributions

Contribute defensive patches to affected tools:

- Falco: `bpf_map_freeze()` on `interesting_syscalls` after rule loading
- Tracee: Periodic `config_map` integrity verification in userspace daemon
- Tetragon: Event rate anomaly detection in the agent

### 6.3 BPF Mailing List RFC

Submit a Request for Comments to the BPF mailing list proposing per-map access control, including:

- Problem statement with empirical evidence from this research
- Proposed kernel API changes
- Prototype implementation
- Backward compatibility analysis

## 7. Timeline

| Quarter | Milestone |
|---------|-----------|
| Q2 2026 | Responsible disclosure to all tool maintainers |
| Q3 2026 | Public release of repository; upstream defense contributions |
| Q3 2026 | Expanded tool coverage (Cilium, KubeArmor) |
| Q3 2026 | BPF Map Watchdog tool MVP |
| Q4 2026 | Kernel patch RFC submission to BPF mailing list |
| Q4 2026 | Academic paper submission |
| Q1 2027 | Conference presentations |
| Q1-Q2 2027 | Broader attack surface exploration (ring buffer, link manipulation) |
