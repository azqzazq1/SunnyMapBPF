# 3. Threat Model

## 3.1 Attacker Profile

We consider a post-exploitation attacker who has achieved code execution on a Linux host where eBPF-based security monitoring is deployed. The attacker's immediate objective is to disable or evade the monitoring tool to operate undetected for subsequent attack phases (lateral movement, data exfiltration, persistence establishment).

## 3.2 Attacker Capabilities

The attacker possesses the following capabilities:

**C1: Code execution.** The attacker can execute arbitrary user-space code on the target host. This is a prerequisite for any post-exploitation activity.

**C2: `CAP_BPF` capability.** The attacker's process holds `CAP_BPF` (or `CAP_SYS_ADMIN`, which subsumes it). This capability is required to invoke `bpf(2)` syscall operations on maps. `CAP_BPF` is obtainable through:
- Container escape from a privileged container (common in Kubernetes environments where security tools themselves run privileged)
- Exploitation of a kernel vulnerability granting capability escalation
- Misconfigured capability sets (e.g., Docker's `--cap-add=BPF` or deployment manifests that grant `CAP_BPF` or `CAP_SYS_ADMIN`)
- Compromise of a process that already holds `CAP_BPF` (e.g., any process in the host PID namespace with `CAP_SYS_ADMIN`)

**C3: No BPF program loading required.** The attacker does *not* need the ability to load BPF programs. This distinguishes BPF map poisoning from prior BPF-based attacks (rootkits, offensive BPF programs) that require passing the BPF verifier. The attack uses only `bpf(BPF_MAP_GET_NEXT_ID)`, `bpf(BPF_MAP_GET_FD_BY_ID)`, `bpf(BPF_MAP_UPDATE_ELEM)`, and `bpf(BPF_MAP_DELETE_ELEM)` -- read and write operations on existing maps.

**C4: Knowledge of target tool.** The attacker knows (or can determine) which security tool is running. This is achievable through process enumeration (`ps`, `/proc`), BPF program enumeration (`bpf(BPF_PROG_GET_NEXT_ID)`), or map name inspection. Map names such as `config_map`, `execve_map`, and `interesting_syscalls` are stable across tool versions and serve as reliable fingerprints.

## 3.3 Attacker Limitations

The attacker is subject to the following constraints:

**L1: No kernel code execution.** The attacker cannot execute arbitrary code in kernel context. The attack operates entirely through the `bpf(2)` syscall from userspace.

**L2: No kernel module loading.** The attacker cannot load kernel modules (`CAP_SYS_MODULE` is not assumed).

**L3: No `bpf(2)` syscall suppression.** The attacker cannot prevent other processes from invoking `bpf(2)`. If the security tool implements runtime integrity checks via periodic `bpf(BPF_MAP_LOOKUP_ELEM)` calls, the attacker cannot prevent those checks from executing (though they can race against them).

**L4: No host filesystem write access (optional constraint).** For the Tracee and Falco attacks, which use map ID enumeration, the attacker does not require filesystem write access. The Tetragon attack via pinned maps requires read access to `/sys/fs/bpf/` but not write access to the host filesystem (the `bpf(BPF_OBJ_GET)` call on pinned paths returns a file descriptor for map operations).

## 3.4 Assumptions About the Target Environment

**A1: eBPF security tool is running.** At least one of Falco, Tracee, or Tetragon is deployed and actively monitoring the host. The tool has successfully loaded its BPF programs and populated its BPF maps.

**A2: BPF maps are not frozen.** The target tool has not called `bpf_map_freeze()` on its critical maps. This assumption is empirically validated: none of the three tools freeze any maps as of their tested versions.

**A3: No external map integrity monitoring.** No separate process monitors BPF map contents for unauthorized modifications. The security tools do not implement self-monitoring of their own map state.

**A4: Standard kernel configuration.** The kernel has not been patched with custom BPF access control mechanisms beyond the upstream capability model. `CONFIG_BPF_SYSCALL=y` and `CONFIG_BPF_JIT=y` are enabled (standard on all major distribution kernels).

## 3.5 Attack Goals

The attacker seeks to achieve one or more of the following goals, in order of increasing scope:

**G1: Selective event suppression.** Suppress monitoring of specific syscalls, processes, or containers while leaving monitoring of other activity intact. This is achievable via Falco's per-syscall `interesting_syscalls` array or Tracee's per-policy `enabled_policies` bitmask.

**G2: Total event blindness.** Suppress all security event generation from the targeted tool, causing it to report zero events regardless of system activity. All three attacks presented in this paper achieve this goal.

**G3: Persistent evasion.** Maintain the suppression state across time without repeated intervention. Because BPF maps persist in kernel memory as long as the tool's BPF programs are loaded, a single poisoning operation persists until the tool is restarted or the map contents are explicitly restored.

**G4: Stealth.** Execute the attack without generating alerts from the targeted tool or producing log entries that indicate tampering. All three attacks satisfy this goal: the BPF programs continue executing normally (they are not modified), the userspace daemon continues running (it simply receives no events), and no error conditions are triggered.

## 3.6 Scope and Non-Goals

This work does not address:

- Attacks against the BPF verifier or JIT compiler
- Attacks that require loading malicious BPF programs
- Denial-of-service attacks that crash or terminate the security tool process
- Attacks against the userspace components of security tools (rule engine, alert pipeline)
- Kernel vulnerabilities in the BPF subsystem itself

The focus is exclusively on the integrity of BPF map contents as a security-relevant property that current tools fail to protect.
