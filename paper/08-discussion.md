# 8. Discussion

## 8.1 An Architectural Problem, Not a Bug

BPF map poisoning is not a vulnerability in the kernel's BPF subsystem. The `bpf(2)` syscall correctly implements its documented interface: any process with `CAP_BPF` can modify any BPF map. The kernel provides no ownership model for maps, and this is by design -- BPF maps are intended as shared-state primitives for composing BPF programs from multiple producers. The vulnerability lies in the *security tools' failure to use available protection mechanisms* and their *implicit assumption that map contents are trustworthy*.

This is an architectural problem for three reasons:

First, the trust boundary is misplaced. Security tools treat the kernel/userspace boundary as their security perimeter: events generated in kernel space are trusted, and userspace policy evaluation operates on trusted input. BPF maps straddle this boundary -- they reside in kernel memory but are writable from userspace. The tools do not account for this in their threat models.

Second, the BPF programming model encourages the vulnerable pattern. BPF maps are the *only* mechanism for BPF programs to receive configuration from userspace and share state across programs. Every BPF-based security tool must use maps for configuration, and the default map creation path does not apply any access restrictions. Developers must opt in to protection via `bpf_map_freeze()` or creation flags, and the documentation does not highlight the security implications of unprotected maps.

Third, the failure mode is silent. When map contents are modified, the BPF programs continue executing correctly -- they simply operate on poisoned data. No error is raised, no crash occurs, and no log entry is generated. The tool's userspace daemon sees an absence of events, which is indistinguishable from a genuinely quiet system. This makes the attack difficult to detect through monitoring of the security tool itself.

## 8.2 Why Tools Do Not Use Available Protections

We identify three reasons why none of the tested tools employ `bpf_map_freeze()` or `BPF_F_RDONLY_PROG`:

**Dynamic configuration requirements.** All three tools update map contents during runtime. Tracee updates `config_map` when policies change. Tetragon continuously inserts and removes entries in `execve_map` as processes start and exit. Falco populates `interesting_syscalls` at startup and may update it on rule reload. Freezing these maps would break the tools' own operations.

This constraint is not insurmountable. Tracee could freeze `config_map` after initial policy loading and implement policy changes through map recreation. Falco could freeze `interesting_syscalls` after initialization. However, map recreation is not a trivial change: it requires re-attaching all BPF programs that reference the old map to the new map, which involves program re-loading or fd replacement via `bpf_map__reuse_fd()`.

**Incomplete threat model.** The tool developers have not considered same-capability adversaries as a threat. The implicit assumption is that `CAP_BPF` is a trusted capability -- any process that has it is assumed to be legitimate. This assumption was reasonable when `CAP_BPF` was part of `CAP_SYS_ADMIN` (pre-kernel 5.8), but the separation of `CAP_BPF` as a distinct capability has expanded the population of processes that hold it. Container runtimes, observability agents, and networking tools increasingly require `CAP_BPF`, and compromise of any of these processes grants the attacker map write access.

**Performance considerations.** `bpf_map_freeze()` adds a check on every userspace map operation (though not on BPF-side operations). The performance impact is negligible, but the perception that "frozen maps are less flexible" may deter adoption. `BPF_F_RDONLY_PROG` restricts BPF-side access, not userspace access, so it is not directly relevant to the poisoning threat but could be part of a defense-in-depth strategy.

## 8.3 Defense Analysis

We evaluate potential defenses against BPF map poisoning, assessing their effectiveness and implementation complexity.

### 8.3.1 Map Freezing (`bpf_map_freeze()`)

**Effectiveness:** High for configuration maps that are populated once at startup (Falco's `interesting_syscalls`, Tracee's `config_map` after initial policy load). After freezing, `BPF_MAP_UPDATE_ELEM` returns `-EPERM`, completely preventing the poisoning attack.

**Limitations:** Not applicable to maps that require ongoing userspace writes. Tetragon's `execve_map` is continuously updated by BPF programs (via `bpf_map_update_elem()` from BPF context, which is *not* blocked by freezing) and by userspace (which *would* be blocked). However, if Tetragon's architecture ensures that only BPF programs write to `execve_map` and userspace only reads it, freezing would work. The `execve_calls` prog\_array is populated at load time and could be frozen after setup.

**Implementation complexity:** Low. A single `bpf(BPF_MAP_FREEZE, map_fd)` call after initialization. The main challenge is identifying the correct point in the tool's lifecycle to freeze each map.

### 8.3.2 Runtime Integrity Monitoring

**Approach:** The security tool's userspace daemon periodically reads critical map values and verifies them against expected state. For example, Tracee could periodically verify that `enabled_policies` in `config_map` matches the expected policy bitmask.

**Effectiveness:** Medium. Can detect poisoning after the fact (with a delay proportional to the polling interval) but cannot prevent it. The attacker and the monitoring thread race: the attacker can re-poison the map after each integrity check, leading to a cat-and-mouse dynamic.

**Limitations:** Polling introduces latency (events generated between poisoning and detection are lost). High-frequency polling increases CPU overhead. The integrity check itself uses `bpf(BPF_MAP_LOOKUP_ELEM)`, which the attacker could potentially detect and respond to (though this requires a more sophisticated attacker).

### 8.3.3 BPF Token Scoping (Kernel 6.9+)

**Approach:** BPF tokens, introduced in kernel 6.9, allow fine-grained delegation of BPF operations. A token can restrict which map operations are permitted and to which maps.

**Effectiveness:** Potentially high, but the mechanism is not yet integrated into any security tool's architecture. Token-based access control could enforce that only the security tool's own processes can modify its maps.

**Limitations:** Requires kernel 6.9+, which limits deployment scope. The token infrastructure is new and its integration patterns for security tools are not yet established.

### 8.3.4 LSM-Based BPF Syscall Filtering

**Approach:** Use a BPF LSM program to intercept `bpf(2)` syscall invocations and deny map modification operations from unauthorized processes.

**Effectiveness:** High in principle. An LSM hook on `security_bpf_map()` can inspect the calling process and the target map, and deny access if the caller is not the authorized security tool.

**Limitations:** Circular dependency risk: the LSM program protecting the security tool's maps is itself a BPF program with maps that could be targeted. However, LSM programs have a stronger attachment model (they cannot be detached without `CAP_SYS_ADMIN` and specific program replacement), making this defense more robust than map-level protections alone.

### 8.3.5 Userspace Heartbeat Mechanisms

**Approach:** The security tool's BPF programs write a heartbeat value to a dedicated map on every invocation. The userspace daemon monitors this heartbeat: if the BPF programs are executing (heartbeat incrementing) but no events are being emitted, the daemon raises an alert about potential map tampering.

**Effectiveness:** Medium. Detects total blindness (P1, P4) where BPF programs execute but produce no output. Does not detect selective suppression (P5) where some events are still generated. Requires the heartbeat map itself to be protected from poisoning (the attacker could simulate heartbeats).

**Implementation complexity:** Low. Requires adding a single `bpf_map_update_elem()` call to each BPF program's entry point and a periodic check in the userspace daemon.

## 8.4 Implications for the eBPF Security Ecosystem

The findings of this paper have implications beyond the three tools tested:

**All BPF-based security tools are likely vulnerable.** The vulnerable pattern (unprotected configuration and state maps) is inherent to the BPF programming model. Any tool that stores security-critical decisions in BPF maps without applying `bpf_map_freeze()` is susceptible to map poisoning. This includes commercial eBPF-based security products that likely share the same architectural patterns.

**`CAP_BPF` is a security-critical capability.** The separation of `CAP_BPF` from `CAP_SYS_ADMIN` was intended to reduce the privilege required for legitimate BPF usage. However, this paper demonstrates that `CAP_BPF` alone is sufficient to disable all BPF-based security monitoring on a host. Security policies that grant `CAP_BPF` to workloads should consider this implication.

**Defense-in-depth is necessary.** No single mitigation is sufficient. A robust defense requires combining map freezing (where possible), runtime integrity monitoring, heartbeat mechanisms, and external monitoring of the security tool's output rate. The architectural constraint that BPF maps must be writable for tools to function means that complete prevention of map poisoning may not be achievable within the current BPF API.

## 8.5 Responsible Disclosure

The findings in this paper were reported to the maintainers of all affected tools prior to public release. We note that the techniques described require elevated privileges (`CAP_BPF`) that already grant significant kernel access. The contribution of this work is not the discovery of a new exploitation primitive but the systematic demonstration that current eBPF security tools do not defend against same-privilege-level tampering of their own runtime state. This gap represents a missing layer in the defense-in-depth model, not a privilege escalation path.
