# Discussion

## 1. Interpretation of Results

The empirical results demonstrate a consistent telemetry trust boundary weakness across all three tested eBPF security monitoring tools. The 100% event suppression observed against Tracee, Tetragon, and Falco is not an artifact of contrived test conditions or tool misconfiguration — each tool was deployed in its documented default configuration, which is also the configuration most operators use in production.

The consistency of the result across three architecturally distinct tools is the most significant finding. Tracee uses a policy-driven hash map for event filtering. Tetragon uses tail-call prog_arrays for execution pipeline routing. Falco uses a flat array for syscall dispatch. These are fundamentally different design patterns, yet all are equally vulnerable because they share a single underlying assumption: that BPF maps, once populated, will not be modified by an unauthorized party.

This assumption is nowhere documented, nowhere enforced, and nowhere verified.

## 2. An Architectural Problem, Not a Bug

It is important to frame BPF map state poisoning correctly. This is not a bug in Falco, Tracee, or Tetragon. It is not a missing bounds check, a use-after-free, or a logic error. The tools behave exactly as the kernel BPF subsystem intends: BPF maps are mutable shared state, accessible to any process with `CAP_BPF`, and the kernel provides no mechanism to restrict map access to the program or process that created it.

The vulnerability is architectural in two senses:

**First, at the kernel level.** The BPF map access model was designed for cooperative multi-program environments (networking, tracing, profiling) where all BPF programs on a host are assumed to be under the same administrative domain. There is no concept of map ownership, per-map ACLs, or cross-program isolation. The `bpf_map_freeze()` helper, introduced in kernel 5.2 (commit 87df15de441b), provides write-once semantics but is unsuitable for maps that require legitimate runtime updates. The `BPF_F_RDONLY_PROG` flag restricts BPF-side writes but does not prevent userspace modification via `bpf(BPF_MAP_UPDATE_ELEM)`.

**Second, at the tool level.** All three tools treat their BPF maps as trusted internal state. None implements any form of integrity verification, tamper detection, or consistency checking. This is a rational design choice under the assumption that an attacker with `CAP_BPF` already has sufficient privilege to load arbitrary BPF programs. However, this reasoning conflates two distinct threat models: (a) an attacker who can load new BPF programs and (b) an attacker who can silently disable existing ones. The latter is strictly more dangerous because it undermines the detection layer that would otherwise observe the former.

## 3. The Fundamental Tension

BPF map state poisoning exposes a fundamental tension in the eBPF security architecture:

- **BPF maps must be mutable at runtime.** Security tools need to update policies, refresh process caches, toggle features, and communicate between BPF programs and userspace. Freezing all maps is not viable.

- **BPF maps must be trustworthy.** Security tools make access-control and event-generation decisions based on map contents. If an adversary can alter those contents, the tool's security guarantees collapse.

These two requirements are in direct conflict under the current BPF access model, which provides no mechanism to distinguish between legitimate updates (from the tool's own userspace daemon) and malicious updates (from an attacker process with `CAP_BPF`).

This tension is not unique to eBPF. It is a specific instance of a general problem in systems security: **how to maintain mutable shared state with integrity guarantees in the presence of a same-privilege-level adversary.** The analogous problem appears in:

- **Antivirus kernel drivers** that expose IOCTL interfaces, allowing malware to disable scanning (the "BYOVD" attack pattern)
- **SELinux/AppArmor policy stores** that reside in kernel memory accessible to processes with `CAP_MAC_ADMIN`
- **Hypervisor control structures** that must be mutable for VM management but immutable to guest-initiated attacks

In each case, the solution has required architectural changes that go beyond simple access control: memory protection keys, separate trust domains, hardware-backed integrity, or privileged monitor processes in isolated execution contexts.

## 4. Why Existing Kernel Mechanisms Are Insufficient

### 4.1 bpf_map_freeze()

Introduced in Linux 5.2 (2019), `bpf_map_freeze()` makes a map permanently read-only from userspace. Once frozen, any `bpf(BPF_MAP_UPDATE_ELEM)` call returns `-EPERM`.

**Limitation:** Freeze is permanent and total. It cannot be applied to maps that require legitimate runtime updates, which includes most maps used by security tools. Tracee's `config_map` must be updated when policies change. Tetragon's `execve_map` must be updated on every process exec/exit. Falco's `interesting_syscalls` must be updated when rule sets change. Freezing any of these maps would break the tool's core functionality.

**Partial applicability:** Some secondary configuration maps could be frozen after initial population (e.g., static lookup tables, compile-time constants). However, the critical maps targeted in our attacks are, by design, runtime-mutable.

### 4.2 BPF_F_RDONLY_PROG

This flag, set at map creation time, prevents BPF programs from writing to the map. It does not restrict userspace access via the `bpf()` syscall.

**Limitation:** This flag protects against rogue BPF programs modifying another program's maps, but BPF Map Poisoning operates from userspace (via `bpftool` or direct `bpf()` syscall), so `BPF_F_RDONLY_PROG` provides no defense against our attack vector.

### 4.3 BPF Token (Kernel 6.9+)

BPF tokens, introduced in kernel 6.9, allow delegating a subset of BPF operations to unprivileged processes within specific mount namespaces. Tokens scope the `bpf()` syscall's capabilities.

**Limitation:** BPF tokens restrict who can perform BPF operations, not which maps a BPF-capable process can access. A process with a BPF token that grants `BPF_MAP_UPDATE_ELEM` can still update any map it can reference by file descriptor or ID. Tokens do not provide per-map access control.

### 4.4 Capability Namespacing

Since kernel 5.8, `CAP_BPF` is separated from `CAP_SYS_ADMIN`, allowing finer-grained capability assignment. However, `CAP_BPF` is a single binary capability: a process either has full BPF access or none. There is no mechanism to grant a process the ability to manage its own maps while preventing it from accessing other processes' maps.

### 4.5 Summary of Gaps

| Mechanism | Prevents Map Poisoning? | Why Not |
|-----------|------------------------|---------|
| `bpf_map_freeze()` | Partially | Cannot freeze runtime-mutable maps |
| `BPF_F_RDONLY_PROG` | No | Only restricts BPF-side writes, not userspace |
| BPF Token (6.9+) | No | No per-map access control |
| `CAP_BPF` separation | Partially | Binary capability, no map-level granularity |
| BPF LSM hooks | Potentially | Not implemented for map update operations |

## 5. Implications for the eBPF Security Ecosystem

### 5.1 Trust Model Inversion

The conventional security model assumes a hierarchy: the kernel is more trusted than userspace, and security tools operate at a higher trust level than the processes they monitor. BPF map state poisoning inverts this model. An attacker who has achieved `CAP_BPF` (through container escape, privilege escalation, or misconfiguration) can disable the very tools designed to detect such compromises, creating a blind spot that persists until the tool is restarted or the maps are manually inspected.

This creates a **detection paradox**: the tools that should detect post-exploitation activity are themselves vulnerable to post-exploitation tampering. The attacker's first action after gaining `CAP_BPF` can be to disable all monitoring, ensuring that subsequent actions (data exfiltration, lateral movement, persistence establishment) proceed undetected.

### 5.2 False Sense of Security

Organizations deploying Falco, Tracee, or Tetragon may believe they have runtime visibility into kernel-level events. BPF map state poisoning demonstrates that this visibility can be silently revoked without any indication in the tool's logs, metrics, or health checks. The tool continues to run, consume resources, and report "healthy" status while detecting nothing.

This is worse than having no monitoring at all, because it creates a false sense of security that may delay incident detection and response.

### 5.3 Ecosystem-Wide Impact

The three tools tested in this research represent the dominant eBPF security monitoring ecosystem:

- **Falco** (CNCF graduated project, 7,000+ GitHub stars, widely deployed in Kubernetes environments)
- **Tetragon** (Cilium/Isovalent project, CNCF incubating, integrated with Cilium CNI)
- **Tracee** (Aqua Security project, 3,500+ GitHub stars, integrated with Aqua's commercial platform)

The vulnerability is not specific to these implementations but is inherent to any eBPF-based security tool that uses mutable BPF maps for event-generation control logic. Tools not yet tested (e.g., Pixie, Inspektor Gadget, KubeArmor) likely share the same vulnerability class if they follow the same architectural pattern.

## 6. Comparison to Analogous Security Domains

### 6.1 EDR/Antivirus Evasion

BPF map state poisoning is analogous to the well-documented practice of disabling EDR (Endpoint Detection and Response) agents on Windows systems. Techniques such as unhooking NTDLL, patching ETW providers, or abusing vulnerable kernel drivers (BYOVD) achieve the same goal: suppressing telemetry so that subsequent activity proceeds undetected. The security industry has invested significantly in hardening EDR agents against these attacks, including kernel-level self-protection, anti-tamper mechanisms, and out-of-band health monitoring.

The eBPF security ecosystem has not yet undergone this hardening process. BPF map state poisoning represents the eBPF equivalent of BYOVD: using legitimate kernel interfaces to suppress security tool telemetry without exploiting any software vulnerability.

### 6.2 Audit Log Tampering

BPF map state poisoning is also analogous to audit log tampering, a classic post-exploitation technique. However, it operates at a different layer: rather than modifying historical records (which can be detected through log forwarding, checksums, or write-once storage), map state poisoning prevents events from being generated in the first place. There are no records to tamper with because the kernel-side BPF program never produced them.

### 6.3 Control Plane Attacks in SDN

In software-defined networking, attacks against the control plane (e.g., poisoning OpenFlow flow tables) can redirect or drop traffic without detection. BPF map state poisoning is the security monitoring equivalent: the "flow table" that determines which events are processed is itself the attack surface.

## 7. The "Quis Custodiet" Dimension

The Latin phrase "quis custodiet ipsos custodes" (who watches the watchmen) captures the core dilemma. eBPF security tools are deployed to monitor the kernel, but they are themselves kernel-resident programs whose state is accessible to anything with `CAP_BPF`. There is no watcher watching the watchers.

This is not merely a theoretical concern. In a post-exploitation scenario, the attacker's priority is to establish persistence and avoid detection. BPF map state poisoning provides a zero-artifact method to achieve the latter. The attacker does not need to kill the security process (which would trigger a health check failure), modify files (which could be detected by file integrity monitoring), or create network connections (which might be logged by network monitoring). They modify kernel-resident data structures using a legitimate kernel interface, and the security tool silently stops working.

Addressing this requires either (a) an external monitor that is not itself implemented in eBPF and not susceptible to BPF map tampering, or (b) architectural changes to the BPF subsystem that provide map-level access control. Both approaches represent significant engineering effort and are discussed further in the defensive considerations.
