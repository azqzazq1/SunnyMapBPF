# Related Work

## 1. eBPF Verifier and JIT Vulnerabilities

The Linux eBPF verifier has been a persistent source of privilege escalation vulnerabilities. Jann Horn's work on speculative execution in BPF (2021) demonstrated that verifier-approved programs could perform out-of-bounds memory reads through speculative side channels. Nelson et al. (OSDI 2020, "Specification and verification with the Jitterbug framework") formalized JIT correctness and identified classes of JIT compiler bugs enabling arbitrary kernel code execution. CVE-2021-3490 (Manfred Paul) exploited an ALU32 bounds tracking flaw in the verifier to achieve LPE from unprivileged BPF. CVE-2023-2163 demonstrated a verifier state pruning bug allowing out-of-bounds map access. These works focus on *loading* malicious BPF programs; our work requires no program loading.

Subsequent hardening -- `unprivileged_bpf_disabled=2` (default since kernel 5.16), CAP_BPF separation from CAP_SYS_ADMIN (kernel 5.8), and continuous verifier tightening -- has made BPF program injection increasingly difficult. This has shifted attacker focus away from the verifier as a vector, leaving the *runtime data plane* (maps) comparatively under-examined.

## 2. BPF-Based Runtime Security Tools

Three major open-source tools define the eBPF runtime security landscape:

**Tracee** (Aqua Security). Uses BPF tracepoints and kprobes to generate security events. Architecture: BPF programs attach to kernel hooks, filter events through a policy engine implemented in-kernel via `match_scope_filters()`, and emit events to userspace via perf/ring buffers. Policy configuration stored in `config_map`, a BPF ARRAY map. Rex Guo and Junyuan Zeng ("Phantom Attack: Evading System Call Monitoring," NDSS 2023) showed TOCTOU attacks against syscall argument tracing, but did not address config-plane tampering.

**Tetragon** (Cilium/Isovalent). Uses BPF LSM and tracepoints with a process-tracking architecture centered on `execve_map`. All maps pinned to `/sys/fs/bpf/tetragon/` for cross-program state sharing. Uses `PROG_ARRAY` tail calls to compose event processing pipelines. Fournier et al. (2023, "Tetragon: eBPF-Based Security Observability and Runtime Enforcement") describe the architecture but do not analyze the integrity of pinned maps against external modification.

**Falco** (Sysdig/CNCF). BPF probes gate syscall processing on the `interesting_syscalls` array -- a 512-entry BPF ARRAY where each byte indicates whether a given syscall number should be traced. The libs driver (libscap/libsinsp) populates this at startup. Falco's architecture documentation discusses performance filtering but not map integrity.

All three tools assume exclusive ownership of their BPF maps. None implement `bpf_map_freeze()`, `BPF_F_RDONLY_PROG`, or runtime integrity monitoring.

## 3. Known BPF Attack Surfaces

Prior work on BPF attack surfaces clusters into three categories:

**Program injection.** Loading malicious BPF programs to hijack kernel execution. Requires bypassing the verifier or exploiting verifier bugs. Heavily studied and increasingly mitigated by `unprivileged_bpf_disabled`, seccomp filters, and LSM hooks (`bpf` LSM hook, BPF token).

**Helper function abuse.** BPF helpers like `bpf_probe_read_kernel`, `bpf_override_return`, and `bpf_send_signal` provide powerful capabilities. Path et al. (2022) cataloged helper functions by danger level. `bpf_override_return` (error injection) has been discussed as an evasion primitive but requires program attachment, not just map access.

**Map-based data exfiltration.** Hejazi et al. ("Evil eBPF: Practical Abuses of an In-Kernel Bytecode Runtime," BlackHat 2024) discussed using BPF maps as covert communication channels for rootkits. Their focus was on *creating* maps for attacker-controlled programs, not modifying maps belonging to defensive tools.

**eBPF rootkits.** "ebpfkit" (Guillaume Fournier, 2021) and "TripleCross" (Marcos S., 2023) demonstrated offensive BPF programs that hook security-relevant functions. These require loading attacker-controlled BPF programs. "bad-bpf" (Pat Hogan, 2022) showed BPF-based PID hiding via tracepoint hooking. All of these assume the attacker can load BPF programs, a strictly stronger requirement than map write access.

## 4. How BPF Map Poisoning Differs

BPF map poisoning is a fundamentally different attack class:

| Property | Prior BPF attacks | BPF map poisoning |
|---|---|---|
| Requires program load | Yes | No |
| Verifier bypass needed | Often | Never |
| Kernel code execution | Yes | No |
| Modifies control plane | No | Yes |
| Target | Kernel integrity | Defensive tool integrity |
| Capability required | CAP_SYS_ADMIN or verifier bug | CAP_BPF (weaker) |
| Detection by target tool | Possible (LSM hooks) | Not detected (no self-monitoring) |

The key distinction: BPF map poisoning operates entirely within the *legitimate BPF API*. The `bpf(BPF_MAP_UPDATE_ELEM)` syscall is the intended interface for map modification. No verifier is involved because no program is loaded. The kernel correctly processes the update -- the vulnerability lies in the *defensive tool's failure to protect its own configuration state*.

This is analogous to modifying a firewall's rule database while the firewall process is running, except the "database" is a kernel-resident BPF map shared between the tool's kernel and userspace components.

## 5. Gap in Existing Literature

The security of BPF maps as a *runtime attack surface against defensive tools* has not been systematically studied. Existing work addresses:

- Verifier correctness (program loading safety)
- Helper function capabilities (program execution safety)
- BPF for offense (rootkits using BPF programs)
- BPF for defense (tool architecture and policy enforcement)

The gap lies at the intersection: **what happens when a defensive tool's own BPF maps are writable by an adversary who has already achieved some level of privilege?** This is a post-exploitation scenario, but a critical one: an attacker with CAP_BPF (obtainable via container escape, kernel exploit, or misconfigured capability sets) can silently disable all BPF-based monitoring on a host without triggering any alerts from the tools being disabled.

No existing paper, tool documentation, or security advisory addresses this attack class. The BPF subsystem provides `bpf_map_freeze()` (kernel 5.2+) and `BPF_F_RDONLY_PROG` as mitigation primitives, but none of the major runtime security tools use them. This suggests the threat model has not been considered by tool developers.
