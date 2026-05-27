# Security Implications

## 1. Impact on Cloud-Native Security Posture

### 1.1 The eBPF Security Promise

The cloud-native security industry has converged on eBPF as the preferred instrumentation layer for runtime security monitoring. Marketing materials, analyst reports, and technical documentation consistently emphasize eBPF's advantages: kernel-level visibility, low overhead, no kernel module required, and safety guarantees through the BPF verifier. Organizations have invested significant resources in deploying eBPF-based tools as core components of their security architecture.

BPF Map Poisoning challenges a foundational assumption underlying this investment: that eBPF-based monitors are resilient to tampering by processes running on the same host. The reality is that any process with `CAP_BPF` can silently and completely disable these monitors using documented kernel interfaces.

### 1.2 Affected Deployment Scenarios

The following deployment scenarios are directly impacted:

**Kubernetes runtime security.** Falco, Tetragon, and Tracee are commonly deployed as DaemonSets in Kubernetes clusters, running one instance per node to monitor all containers on that node. A container escape that grants `CAP_BPF` on the host allows the attacker to disable monitoring for the entire node -- all pods, all namespaces -- with a single map modification.

**Container-native security platforms.** Commercial platforms built on these open-source tools (Aqua Platform on Tracee, Isovalent Enterprise on Tetragon, Sysdig Secure on Falco) inherit the same vulnerability. The commercial wrapper adds policy management, alerting, and UI but does not alter the fundamental BPF map architecture.

**CI/CD pipeline security.** eBPF-based tools are increasingly used to monitor build environments for supply chain attacks. A compromised build step with host access could disable monitoring before executing malicious actions.

**Edge and IoT deployments.** Single-node deployments without centralized monitoring are particularly vulnerable because there is no external vantage point from which to detect event rate anomalies.

### 1.3 Attack Sequencing in Real Intrusions

BPF Map Poisoning is most dangerous as a **precursor action** in a multi-stage attack. The expected kill chain is:

1. **Initial access** -- Container escape, SSH compromise, supply chain attack
2. **Privilege escalation** -- Obtain `CAP_BPF` or `CAP_SYS_ADMIN`
3. **Detection evasion** -- BPF Map Poisoning to blind all eBPF monitors (this research)
4. **Objective execution** -- Data exfiltration, cryptomining, lateral movement, persistence
5. **Cleanup** -- Optionally restore maps to avoid detection during forensic analysis

Step 3 takes milliseconds and produces no artifacts. Once completed, steps 4 and 5 proceed entirely unmonitored.

## 2. Compliance Implications

### 2.1 SOC 2

SOC 2 Type II compliance requires continuous monitoring controls that demonstrate security events are detected and responded to. Common criteria include:

- **CC7.2:** The entity monitors system components for anomalies indicative of malicious acts and natural disasters.
- **CC7.3:** The entity evaluates security events to determine whether they could or have resulted in a failure.

If eBPF-based tools are cited as the monitoring control satisfying these criteria, BPF Map Poisoning demonstrates that an attacker can silently disable these controls without triggering any compensating detection. This creates a gap between the documented control and its actual effectiveness. An organization relying solely on eBPF monitoring for CC7.2 compliance has a control that can be defeated by the very threats it is designed to detect.

### 2.2 PCI DSS

PCI DSS v4.0 Requirement 10 mandates logging and monitoring:

- **10.2:** Audit logs are implemented to support detection of anomalies and suspicious activity.
- **10.4.1:** Audit logs are reviewed at least once daily.
- **10.7:** Failures of critical security control systems are detected, alerted, and addressed promptly.

BPF Map Poisoning produces a failure of a critical security control system (Requirement 10.7) that is not detected, alerted, or addressed -- precisely because the failure mode is silent suppression of event generation. If eBPF monitoring is the primary mechanism for satisfying Requirements 10.2 and 10.4.1, a poisoned tool generates no events to review, and the absence of events may be indistinguishable from a quiet period.

### 2.3 NIST 800-53

NIST SP 800-53 Rev. 5 controls relevant to this finding include:

- **AU-2:** Event Logging -- requires that the system generates audit records for defined events
- **AU-12:** Audit Record Generation -- requires audit records at the operating system level
- **SI-4:** System Monitoring -- requires monitoring for attacks, indicators of compromise, and unauthorized connections
- **SI-7:** Software, Firmware, and Information Integrity -- requires integrity verification mechanisms

BPF Map Poisoning undermines AU-2, AU-12, and SI-4 by preventing event generation at the kernel level. It also highlights a gap in SI-7: the integrity of the monitoring tool's runtime state (BPF maps) is not verified.

### 2.4 Practical Compliance Impact

Organizations should consider:

1. **Compensating controls.** eBPF-based monitoring should not be the sole control satisfying audit and monitoring requirements. Independent mechanisms (kernel audit framework, log forwarding, network-level monitoring) should provide overlapping coverage.
2. **Control effectiveness testing.** Periodic "red team" testing of monitoring controls should include BPF Map Poisoning or equivalent attacks to verify resilience.
3. **Auditor awareness.** Compliance auditors assessing eBPF-based monitoring controls should understand the BPF map tampering risk and request evidence of tamper detection mechanisms.

## 3. "Quis Custodiet Ipsos Custodes" -- Who Monitors the Monitors?

### 3.1 The Recursive Monitoring Problem

eBPF security tools monitor the kernel from within the kernel. Their monitoring state (BPF maps) resides in kernel memory, accessible to any process with `CAP_BPF`. This creates a recursive problem: monitoring the monitor requires a meta-monitor, which itself would need to be protected from the same class of attacks.

Possible approaches to breaking this recursion:

**External monitoring.** A monitoring system that does not rely on BPF maps for its state (e.g., kernel audit framework, hardware-based monitoring, out-of-band management) can detect event rate anomalies that indicate a poisoned eBPF tool. However, this duplicates the monitoring infrastructure and may not provide the same granularity as eBPF-based tools.

**Hardware root of trust.** Hardware security modules (HSMs), Trusted Platform Modules (TPMs), or hardware performance counters could provide tamper-evident monitoring that is not susceptible to software-level map manipulation. This approach is architecturally sound but introduces significant deployment complexity.

**Kernel-level integrity enforcement.** Modifications to the BPF subsystem itself (per-map ACLs, map owner processes, write notifications) could prevent unauthorized map access without requiring external monitoring. This is the most promising long-term solution but requires kernel upstream changes.

### 3.2 The Monitoring Stack Fallacy

Many organizations believe they have defense-in-depth because they deploy multiple monitoring layers: eBPF-based runtime monitoring, log aggregation, network monitoring, and SIEM. However, if all kernel-level event generation is suppressed by BPF Map Poisoning, the upstream layers (SIEM, log aggregation) receive no events to process. The defense-in-depth is illusory because the layers are serially dependent rather than independently redundant.

True defense-in-depth requires monitoring systems that generate events through independent observation paths. For example:

- Network monitoring via packet capture (independent of BPF maps)
- File integrity monitoring via inotify or fanotify (independent of BPF maps)
- Process monitoring via the kernel audit subsystem (independent of BPF maps)
- Host-based intrusion detection via syscall interception (may or may not use eBPF)

## 4. Supply Chain and Single Point of Failure

### 4.1 Monitoring Tools as Critical Infrastructure

In the cloud-native security model, the monitoring tool is a single point of failure for detection. If Falco is the sole detector of container escapes, and Falco can be silently disabled, then container escape detection has a single point of failure that is exploitable from the same privilege level as the threats it monitors.

This is compounded by fleet-wide deployment patterns. A DaemonSet vulnerability or a shared `CAP_BPF` credential could allow an attacker to poison monitoring across an entire cluster in seconds, achieving cluster-wide blindness before any centralized system detects anomalies.

### 4.2 Supply Chain Considerations

The BPF program bytecode and map definitions are part of the tool's supply chain. If an attacker can influence the BPF program loaded by a security tool (through a compromised build pipeline, modified container image, or man-in-the-middle during BPF program loading), they can pre-configure maps without write protection, ensuring that BPF Map Poisoning remains viable even if the tool's default configuration is hardened.

This extends the attack surface from runtime map manipulation to the tool's entire distribution and deployment pipeline.

## 5. MITRE ATT&CK Mapping

BPF Map Poisoning maps to the following MITRE ATT&CK techniques:

| Technique ID | Name | Relevance |
|-------------|------|-----------|
| T1562.001 | Impair Defenses: Disable or Modify Tools | Direct mapping: BPF Map Poisoning disables security monitoring tools |
| T1562.006 | Impair Defenses: Indicator Blocking | Events are blocked at generation, before reaching any log or alert pipeline |
| T1014 | Rootkit | The attack achieves rootkit-equivalent stealth by operating at the kernel data layer |
| T1070 | Indicator Removal | No indicators are generated, so removal is unnecessary |

The most precise mapping is **T1562.001** (Disable or Modify Tools) with the sub-technique context that the modification is performed at the kernel data plane level rather than through process termination or configuration file modification.

## 6. Implications for eBPF Security Research

### 6.1 Beyond Code Safety

The eBPF security narrative has focused heavily on BPF program safety: the verifier ensures programs cannot crash the kernel, access arbitrary memory, or enter infinite loops. BPF Map Poisoning demonstrates that program safety is necessary but not sufficient. A perfectly safe BPF program can be rendered useless by modifying the data it operates on.

This shifts the security research focus from "can BPF programs harm the kernel?" to "can BPF data structures be weaponized against the programs that depend on them?" The latter question has received comparatively little attention.

### 6.2 Expanding the BPF Attack Surface

BPF Map Poisoning is one instance of a broader class: **BPF data plane attacks.** Related attack surfaces that warrant investigation include:

- **Ring buffer poisoning:** Corrupting `BPF_MAP_TYPE_RINGBUF` entries to inject false events into userspace consumers
- **Perf event manipulation:** Modifying perf event map configurations to redirect or suppress event delivery
- **Prog_array hijacking:** Replacing tail-call targets in prog_arrays with attacker-controlled BPF programs (requires `CAP_BPF` + program loading)
- **Map-of-maps redirection:** Modifying inner map pointers in `BPF_MAP_TYPE_ARRAY_OF_MAPS` to redirect data flow

Each of these represents a distinct attack surface that shares the same root cause: insufficient access control on BPF map operations.
