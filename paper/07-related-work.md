# 7. Related Work

## 7.1 BPF Verifier and JIT Vulnerabilities

The BPF verifier has been a persistent source of privilege escalation vulnerabilities. Horn (2021) demonstrated speculative execution side channels in verified BPF programs, achieving out-of-bounds kernel memory reads. CVE-2021-3490 (Paul) exploited an ALU32 bounds tracking flaw in the verifier for local privilege escalation from unprivileged BPF access. CVE-2023-2163 demonstrated a verifier state pruning bug enabling out-of-bounds map access. Nelson et al. (OSDI 2020) formalized JIT correctness with the Jitterbug framework and identified classes of JIT compiler bugs enabling arbitrary kernel code execution.

These works focus on the *program loading* attack surface -- exploiting the verifier to load programs that violate the BPF safety contract. Subsequent hardening (`unprivileged_bpf_disabled=2` as default since kernel 5.16, `CAP_BPF` separation from `CAP_SYS_ADMIN` in kernel 5.8, continuous verifier tightening) has substantially raised the bar for this attack class. BPF map poisoning operates on an orthogonal surface: it requires no program loading, no verifier interaction, and no JIT involvement. The attack uses only the `bpf(2)` map manipulation syscalls, which are designed, documented, and tested operations.

## 7.2 Offensive BPF Programs

Several projects have demonstrated the use of BPF programs for offensive purposes.

**ebpfkit** (Fournier, 2021) implemented a BPF-based rootkit that hooks security-relevant kernel functions to hide processes, files, and network connections. **TripleCross** (S., 2023) extended this concept with a modular rootkit framework supporting backdoor execution, library injection, and execution hijacking via BPF programs. **bad-bpf** (Hogan, 2022) demonstrated PID hiding through BPF tracepoint hooking that modifies the output of process enumeration syscalls.

All of these approaches require the attacker to *load BPF programs* into the kernel, which requires `CAP_BPF` plus `CAP_PERFMON` (for tracepoint/kprobe attachment) or `CAP_SYS_ADMIN`, and the loaded program must pass the BPF verifier. BPF map poisoning requires only `CAP_BPF` and does not load any programs, making it a strictly weaker capability requirement. Additionally, BPF program loading is increasingly monitored (Tracee tracks `bpf` syscalls with `BPF_PROG_LOAD` commands), whereas map updates via `BPF_MAP_UPDATE_ELEM` are not monitored by any tested tool.

## 7.3 BPF Map Security Analysis

Hejazi et al. ("Evil eBPF: Practical Abuses of an In-Kernel Bytecode Runtime," BlackHat 2024) discussed BPF maps as covert communication channels for rootkits, using attacker-created maps to pass data between malicious BPF programs and userspace command-and-control components. Their analysis focused on maps created by the attacker, not on tampering with maps belonging to defensive tools.

Path et al. (2022) cataloged BPF helper functions by danger level and analyzed the capability requirements for each, but did not examine the access control model for map operations or consider cross-program map access as an attack vector.

The BPF map access model has been discussed in kernel development contexts (BPF mailing list, LPC conferences) primarily in the context of namespace isolation and multi-tenancy, not in the context of defensive tool integrity. The introduction of `bpf_map_freeze()` in kernel 5.2 and BPF token scoping in kernel 6.9 indicates awareness of the need for finer-grained map access control, but these mechanisms are opt-in and currently unused by the major security tools.

## 7.4 Runtime Monitoring Evasion

The evasion of runtime security monitoring systems has a substantial history predating eBPF-based tools.

**TOCTOU attacks.** Guo and Zeng ("Phantom Attack: Evading System Call Monitoring," NDSS 2023) demonstrated time-of-check-to-time-of-use (TOCTOU) attacks against syscall argument tracing, where an attacker modifies syscall arguments between the monitoring tool's inspection and the kernel's use. These attacks target the *data plane* of individual events. BPF map poisoning targets the *control plane*, disabling event generation entirely rather than corrupting individual event data.

**ptrace-based evasion.** Techniques for evading ptrace-based monitoring (anti-debugging, ptrace detachment, PTRACE_TRACEME self-attachment) are well-documented but apply to a different instrumentation mechanism. eBPF-based tools are not affected by ptrace evasion techniques.

**Audit subsystem evasion.** The Linux audit subsystem (`auditd`) can be evaded through audit rule manipulation (requiring root), log file tampering, or `auditctl` reconfiguration. These are analogous to BPF map poisoning in that they target the monitoring system's configuration rather than individual events, but operate at the userspace level and leave filesystem artifacts.

**Container escape and monitoring bypass.** Techniques for escaping container isolation (e.g., via privileged containers, `CAP_SYS_ADMIN` abuse, kernel exploits) often include monitoring evasion as a secondary objective. BPF map poisoning is complementary: after achieving the capability prerequisite through container escape, the attacker can use map poisoning to suppress alerts about the escape itself and subsequent activities.

## 7.5 Kernel Self-Protection and Integrity Monitoring

**LKRG (Linux Kernel Runtime Guard).** LKRG monitors kernel integrity by detecting unauthorized modifications to kernel code and critical data structures. LKRG does not monitor BPF map contents, as maps are legitimately modified by both userspace and BPF programs during normal operation. Extending LKRG to monitor security-critical BPF maps would require tool-specific knowledge of which maps and which fields are security-relevant.

**IMA (Integrity Measurement Architecture).** IMA provides file-based integrity measurement and appraisal. BPF maps are kernel-resident data structures, not filesystem objects (even pinned maps -- the BPF filesystem is a pseudo-filesystem), and are outside IMA's measurement scope.

**dm-verity and secure boot.** These mechanisms protect the integrity of on-disk boot and rootfs images but do not extend to runtime kernel data structures such as BPF maps.

## 7.6 Positioning of This Work

BPF map poisoning occupies a distinct position in the attack taxonomy:

| Dimension | Prior work | This work |
|-----------|-----------|-----------|
| Attack target | Kernel integrity, program loading | Defensive tool configuration |
| Requires BPF program load | Yes | No |
| Requires verifier bypass | Often | Never |
| Capability requirement | CAP\_SYS\_ADMIN or vuln | CAP\_BPF |
| Operates via | Unauthorized operations | Legitimate API |
| Effect | Kernel compromise | Monitoring suppression |
| Detection by target | Possible (LSM hooks) | Not detected |

The key novelty is that BPF map poisoning uses the *legitimate, documented BPF API* to achieve a security-relevant effect that the API designers did not anticipate as a threat. The vulnerability lies not in the kernel but in the *failure of defensive tools to protect their own runtime state* using available kernel mechanisms.
