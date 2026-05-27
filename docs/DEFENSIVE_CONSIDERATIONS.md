# Defensive Considerations

This section presents defense recommendations stratified by audience: tool maintainers, operators/defenders, and kernel developers. For each recommendation, we assess feasibility, limitations, and expected effectiveness against BPF Map Poisoning.

---

## 1. For Tool Maintainers

### 1.1 Apply bpf_map_freeze() on Static Configuration Maps

**Description:** Call `bpf_map_freeze()` on maps whose contents are determined at load time and do not require runtime updates. After freezing, any `bpf(BPF_MAP_UPDATE_ELEM)` call targeting the map returns `-EPERM`.

**Applicable maps:**
- Falco: `interesting_syscalls` could be frozen after initial rule compilation, then re-created (not updated) when rules change
- Tracee: Static lookup tables, syscall number mappings, architecture constants
- Tetragon: Static policy tables that do not change after loading

**Feasibility:** High for static maps. Requires identifying which maps are truly immutable after initialization and restructuring the update path for maps that are "mostly static" (changed only during reconfiguration).

**Limitations:** Does not protect the most critical attack targets. Tracee's `config_map`, Tetragon's `execve_map`, and any map requiring runtime updates cannot be frozen. Freezing is permanent -- if a tool needs to update a frozen map, it must destroy and recreate it, which is disruptive.

**Effectiveness:** Partial. Protects a subset of maps but not the ones targeted in our primary attacks.

### 1.2 Periodic Map Integrity Verification

**Description:** Implement a userspace watchdog thread that periodically reads critical map values and compares them against expected state. If a discrepancy is detected, the tool can alert, re-populate the map, or restart.

**Implementation example:**
```
// Pseudocode: integrity check loop
while (running) {
    sleep(INTEGRITY_CHECK_INTERVAL_MS);
    actual = bpf_map_lookup_elem(config_map_fd, &key);
    if (actual.enabled_policies != expected.enabled_policies) {
        LOG_ALERT("config_map tampered: enabled_policies=%d, expected=%d",
                  actual.enabled_policies, expected.enabled_policies);
        bpf_map_update_elem(config_map_fd, &key, &expected, BPF_EXIST);
    }
}
```

**Feasibility:** High. Requires minimal code changes and no kernel modifications. The check interval determines the window of vulnerability: a 100ms interval limits blindness to at most 100ms per tampering event.

**Limitations:**
- **TOCTOU race:** An attacker can re-poison the map immediately after the integrity check restores it, creating a cat-and-mouse loop. The attacker has the advantage because map updates are instantaneous.
- **Performance cost:** Frequent map reads add system call overhead. For maps with many entries (e.g., Falco's 512-entry `interesting_syscalls`), full verification is more expensive.
- **Not tamper-proof:** The integrity check itself runs in userspace and could be attacked (process kill, ptrace, capability removal).

**Effectiveness:** Moderate. Raises the attack complexity from "single command, permanent effect" to "must continuously re-apply," but does not eliminate the vulnerability.

### 1.3 Canary Values and Map Checksums

**Description:** Insert sentinel values at known positions in critical maps. The BPF program checks canary values before processing events. If a canary is missing or incorrect, the program generates a tamper alert via a dedicated event channel.

**Implementation approach:**
```c
// BPF-side canary check
u32 canary_key = CANARY_KEY;
u32 *canary = bpf_map_lookup_elem(&config_map, &canary_key);
if (!canary || *canary != EXPECTED_CANARY_VALUE) {
    // Generate tamper-detection event via ringbuf or perf_event
    struct tamper_event *evt = bpf_ringbuf_reserve(&tamper_ringbuf, sizeof(*evt), 0);
    if (evt) {
        evt->type = TAMPER_DETECTED;
        evt->map_id = CONFIG_MAP_ID;
        bpf_ringbuf_submit(evt, 0);
    }
    return 0; // Fail open or fail closed, depending on policy
}
```

**Feasibility:** Medium. Requires BPF program modifications and a dedicated tamper-alert channel (separate ringbuf or perf event). The canary check adds a small overhead to every BPF program invocation.

**Limitations:**
- **Canary values are observable.** An attacker who can read the map (which requires the same `CAP_BPF`) can identify and preserve canary values while poisoning other entries.
- **Checksums are recomputable.** If the attacker knows the checksum algorithm, they can update the checksum to match the poisoned data.
- **Obscurity, not security.** Canary-based approaches rely on the attacker not knowing the canary scheme, which is a weak assumption for open-source tools.

**Effectiveness:** Low to moderate. Increases attack complexity but is defeated by a knowledgeable attacker.

### 1.4 Map Modification Alerting via BPF

**Description:** Attach a BPF program to the `bpf()` syscall (via kprobe, tracepoint, or LSM hook) that monitors `BPF_MAP_UPDATE_ELEM` and `BPF_MAP_DELETE_ELEM` operations targeting the tool's own maps. Generate an alert when an unexpected process modifies a protected map.

**Implementation approach:**
```c
// Attached to tracepoint:syscalls:sys_enter_bpf or kprobe:__sys_bpf
SEC("kprobe/__sys_bpf")
int monitor_bpf_map_ops(struct pt_regs *ctx) {
    int cmd = PT_REGS_PARM1(ctx);
    if (cmd != BPF_MAP_UPDATE_ELEM && cmd != BPF_MAP_DELETE_ELEM)
        return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == TOOL_PID)  // Allow self-modifications
        return 0;

    // Alert: unauthorized map modification attempt
    // ... emit event via ringbuf
    return 0;
}
```

**Feasibility:** Medium-high. Requires a dedicated monitoring BPF program and knowledge of the tool's own PID. Must be robust against PID spoofing and race conditions during tool restart.

**Limitations:**
- **Circular dependency.** The monitoring BPF program's own maps could be poisoned to disable it. The meta-monitoring problem applies recursively.
- **Performance impact.** Monitoring every `bpf()` syscall adds overhead to all BPF operations on the host, not just map updates.
- **False positives.** Legitimate BPF tools (bpftool, debugging utilities) may trigger alerts.

**Effectiveness:** Moderate to high if combined with integrity verification. The attacker must now simultaneously poison the target maps and disable the monitoring BPF program, increasing attack complexity.

### 1.5 Event Rate Anomaly Detection

**Description:** Track the rate of events generated by BPF programs in userspace. A sudden drop to zero events (or a statistically significant rate decrease) triggers an alert and initiates map integrity verification.

**Feasibility:** High. Most tools already track event rates for performance monitoring. Adding anomaly detection requires minimal additional logic.

**Limitations:**
- **Legitimate quiet periods.** Idle systems produce few events. The anomaly detector must distinguish between natural quiet periods and poisoning-induced silence.
- **Slow poisoning.** An attacker could gradually reduce detection sensitivity (if the map structure allows partial poisoning) to avoid triggering rate-based anomaly detection.
- **Detection delay.** Rate-based anomaly detection inherently introduces a detection delay (typically seconds to minutes) during which the system is blind.

**Effectiveness:** Moderate. Effective against sudden, total blindness attacks (all three attacks demonstrated in this research). Less effective against gradual or partial poisoning.

---

## 2. For Operators and Defenders

### 2.1 Restrict CAP_BPF Distribution

**Description:** Minimize the number of processes and containers that hold `CAP_BPF`. In Kubernetes, use PodSecurityPolicies (deprecated), Pod Security Standards, or OPA/Gatekeeper policies to prevent containers from obtaining `CAP_BPF` or `CAP_SYS_ADMIN`.

**Implementation:**
```yaml
# Kubernetes Pod Security Standard (restricted profile)
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
  containers:
  - name: app
    securityContext:
      capabilities:
        drop: ["ALL"]
      allowPrivilegeEscalation: false
```

**Feasibility:** High in well-managed environments. Requires audit of existing workloads that use `CAP_BPF`.

**Limitations:** Does not protect against container escapes that grant host-level capabilities. Does not protect against compromised privileged workloads (monitoring agents, CNI plugins, node-level daemons) that legitimately hold `CAP_BPF`.

**Effectiveness:** High as a preventive control. If `CAP_BPF` is never granted to untrusted workloads, BPF Map Poisoning requires a prior privilege escalation.

### 2.2 Monitor bpf() Syscalls Externally

**Description:** Use the kernel audit framework (auditd) to log all `bpf()` syscalls, independent of eBPF-based monitoring. Audit rules can capture the command, map ID, and calling process.

**Implementation:**
```bash
# Add audit rule for bpf() syscall (syscall number 321 on x86_64)
auditctl -a always,exit -F arch=b64 -S bpf -k bpf_monitor
```

**Feasibility:** High. The audit framework is available on all mainstream Linux distributions and is independent of the eBPF subsystem.

**Limitations:**
- **Volume:** `bpf()` syscalls are frequent in environments with active BPF tools. The audit log volume may be high, requiring filtering and analysis infrastructure.
- **Evasion:** An attacker with `CAP_SYS_ADMIN` can modify audit rules. An attacker with `CAP_BPF` alone cannot.
- **Analysis gap:** Raw audit logs record that a `bpf()` syscall occurred but do not inherently indicate that the operation was malicious. Correlation with map IDs and process context is required.

**Effectiveness:** Moderate to high. Provides an independent audit trail that BPF Map Poisoning cannot suppress (assuming the audit framework itself is not compromised).

### 2.3 Defense-in-Depth with Independent Monitoring

**Description:** Deploy monitoring systems that do not rely on eBPF maps for their operation. Candidates include:

- **Kernel audit framework** (auditd): syscall-level logging via kernel-internal audit hooks
- **Falco kernel module driver:** Falco's kernel module driver uses a different instrumentation path than its eBPF driver and may have a different attack surface (though similar tampering via IOCTL is plausible)
- **Network-level monitoring:** Packet capture and analysis (Suricata, Zeek) operating at the network interface level
- **File integrity monitoring:** AIDE, OSSEC, or inotify-based tools for file-level change detection
- **Process accounting:** `acct(2)` or `taskstats` for process creation/exit tracking independent of eBPF

**Feasibility:** Medium. Requires deploying and maintaining additional monitoring infrastructure, increasing operational complexity and cost.

**Effectiveness:** High when combined with eBPF monitoring. The independent systems detect events that a poisoned eBPF tool misses, providing true defense-in-depth.

### 2.4 Implement Health Checks with Event Injection

**Description:** Periodically inject synthetic events (e.g., execute a known process, read a known sensitive file) and verify that the monitoring tool generates corresponding alerts. Absence of expected alerts indicates monitoring failure.

**Implementation:**
```bash
# Health check: verify Falco detects /etc/shadow reads
cat /etc/shadow > /dev/null
sleep 2
# Check Falco logs for "Sensitive file opened" alert
if ! grep -q "Sensitive file opened" /var/log/falco_events.log; then
    echo "ALERT: Falco detection failure detected"
fi
```

**Feasibility:** High. Can be implemented as a Kubernetes CronJob or systemd timer.

**Limitations:**
- **Timing window.** There is a gap between injection and verification during which the system is blind.
- **Attacker adaptation.** A sophisticated attacker could selectively re-enable detection for known health-check patterns.
- **False positives.** Event processing delays may cause transient false alarms.

**Effectiveness:** Moderate to high. Detects total blindness attacks within the health check interval. Less effective against selective poisoning that preserves health-check event paths.

---

## 3. For Kernel Developers

### 3.1 Per-Map Access Control Lists

**Description:** Extend the BPF map metadata to include an access control list specifying which processes (by PID, UID, or BPF program ID) can read, write, or delete entries. The kernel enforces these ACLs on every `bpf(BPF_MAP_UPDATE_ELEM)` and `bpf(BPF_MAP_DELETE_ELEM)` call.

**Feasibility:** Low to medium. Requires significant kernel changes to the BPF subsystem, including new `bpf()` commands to set and query ACLs, modifications to the map access path, and a policy for ACL inheritance when maps are shared between programs.

**Limitations:**
- **Complexity:** ACL management adds complexity to both the kernel and userspace tools.
- **PID instability:** PIDs are recycled and cannot be used as stable identifiers for long-lived access control. UID-based or namespace-based ACLs are more robust.
- **Compatibility:** Existing BPF tools assume unrestricted map access. ACLs would require updates to every tool that shares maps between programs.

**Effectiveness:** High. If correctly implemented, per-map ACLs would directly prevent unauthorized map modifications.

### 3.2 Map Owner Process Binding

**Description:** Associate each BPF map with an "owner" process at creation time. Only the owner process (and its descendants, optionally) can modify the map. The owner is determined by the process that calls `bpf(BPF_MAP_CREATE)`.

**Feasibility:** Medium. Simpler than full ACLs. Requires tracking the owner PID in the map metadata and checking it on update/delete operations.

**Limitations:**
- **Process lifecycle.** If the owner process exits and restarts (e.g., after a crash or upgrade), it receives a new PID and loses access to its own maps unless a re-binding mechanism is provided.
- **Shared maps.** Many BPF architectures use maps shared between multiple processes (e.g., map pinning for inter-program communication). Owner binding would break these use cases.

**Effectiveness:** High for single-process tools. Limited for multi-process architectures.

### 3.3 Selective Map Freeze (Partial Freeze)

**Description:** Extend `bpf_map_freeze()` to support partial freezing: freezing specific keys or key ranges while leaving others mutable. Alternatively, introduce a "freeze except from owner" mode that allows the creator process to continue updating while blocking all other writers.

**Feasibility:** Medium. The "freeze except from owner" variant is simpler than full partial freeze. Requires modifications to the map freeze implementation and the update path.

**Limitations:**
- **Partial freeze complexity.** Per-key freeze state requires additional metadata per map entry, increasing memory overhead.
- **"Freeze except from owner"** inherits the process lifecycle limitations described in 3.2.

**Effectiveness:** High. Would directly address the core problem: security tool maps need runtime updates from their own daemon but protection from other processes.

### 3.4 Map Signing and Integrity Verification

**Description:** Introduce a kernel mechanism for map integrity verification based on cryptographic signatures or HMACs. The map creator provides a signing key at creation time, and all subsequent updates must include a valid signature. The kernel verifies the signature before applying the update.

**Feasibility:** Low. Requires key management infrastructure, cryptographic operations in the BPF update path (performance-sensitive), and a trust model for key distribution.

**Limitations:**
- **Performance:** Cryptographic verification on every map update adds latency, particularly for high-frequency updates.
- **Key management:** Securely storing and distributing signing keys is a significant operational challenge, especially in containerized environments.
- **Key compromise:** If the signing key is extracted from the monitoring tool's process memory, the defense is defeated.

**Effectiveness:** High in theory. The practical feasibility challenges make this a long-term research direction rather than a near-term mitigation.

### 3.5 BPF LSM Hooks for Map Operations

**Description:** Add Linux Security Module (LSM) hooks to the `bpf()` syscall path for map operations (`BPF_MAP_UPDATE_ELEM`, `BPF_MAP_DELETE_ELEM`, `BPF_MAP_LOOKUP_ELEM`). This would allow LSM policies (SELinux, AppArmor, BPF LSM) to enforce access control on specific map operations.

**Feasibility:** Medium. The BPF subsystem already has some LSM hooks (for program loading and map creation). Extending these to map data operations is architecturally consistent.

**Limitations:**
- **Policy complexity.** LSM policies would need to reference BPF map IDs or names, which are not currently part of the LSM security context.
- **Circular dependency with BPF LSM.** If the LSM hook is itself implemented as a BPF program (via BPF LSM), its maps could potentially be poisoned, recreating the recursive problem.

**Effectiveness:** Medium to high. Particularly effective when combined with established LSM frameworks (SELinux, AppArmor) that are not susceptible to BPF map poisoning.

---

## 4. Defense Effectiveness Summary

| Defense | Implementer | Feasibility | Effectiveness | Addresses Root Cause? |
|---------|------------|-------------|---------------|----------------------|
| `bpf_map_freeze()` on static maps | Tool maintainer | High | Partial | Partially |
| Periodic integrity verification | Tool maintainer | High | Moderate | No (detection only) |
| Canary values | Tool maintainer | Medium | Low-Moderate | No (obscurity) |
| Map modification alerting | Tool maintainer | Medium-High | Moderate-High | No (detection only) |
| Event rate anomaly detection | Tool maintainer | High | Moderate | No (detection only) |
| Restrict `CAP_BPF` | Operator | High | High (preventive) | No (reduces exposure) |
| Audit `bpf()` syscalls | Operator | High | Moderate-High | No (detection only) |
| Independent monitoring | Operator | Medium | High | No (compensating) |
| Health check injection | Operator | High | Moderate-High | No (detection only) |
| Per-map ACLs | Kernel developer | Low-Medium | High | **Yes** |
| Map owner binding | Kernel developer | Medium | High | **Yes** |
| Selective freeze | Kernel developer | Medium | High | **Yes** |
| Map signing | Kernel developer | Low | High | **Yes** |
| BPF LSM hooks | Kernel developer | Medium | Medium-High | Partially |

**Conclusion:** No single defense is sufficient. The most effective near-term strategy combines tool-level mitigations (integrity verification, map freeze on static maps, event rate monitoring) with operator-level controls (restricting `CAP_BPF`, independent monitoring). A complete solution requires kernel-level changes to the BPF map access model.
