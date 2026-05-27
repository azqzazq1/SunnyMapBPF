# eBPF Security Research Landscape

## Overview

Extended Berkeley Packet Filter (eBPF) has evolved from a simple packet filtering mechanism into a general-purpose in-kernel virtual machine, enabling programmable instrumentation of virtually every kernel subsystem. This power has made eBPF both a critical security tool and a significant attack surface. This survey covers the major security research directions in the eBPF ecosystem, with emphasis on areas relevant to BPF map poisoning.

---

## 1. BPF Verifier Vulnerabilities

The BPF verifier is the kernel's gatekeeper for eBPF programs: it performs static analysis to ensure memory safety, bounded execution, and privilege enforcement. Verifier bugs have been among the most impactful Linux kernel vulnerabilities, as they enable loading programs that violate safety invariants and achieve arbitrary kernel read/write.

### Key CVEs

- **CVE-2020-8835** (Manfred Paul, ZDI-20-394). Bounds tracking error in `adjust_scalar_min_max_vals()` for 32-bit ALU operations. The verifier failed to properly track register bounds after ALU32 operations, allowing crafted programs to bypass bounds checks. Exploited for LPE on Ubuntu 20.04. Disclosed at Pwn2Own 2020.

- **CVE-2021-3490** (Manfred Paul). ALU32 bounds tracking flaw in the BPF verifier where bitwise AND/OR operations on 32-bit sub-registers produced incorrect `tnum` (tracked number) states. An unprivileged user could load a BPF program achieving out-of-bounds memory access in kernel space. Awarded at Pwn2Own Vancouver 2021. Root cause: `scalar32_min_max_and()` did not properly intersect `var_off` with `[smin, smax]` after AND operations.

- **CVE-2021-3489**. BPF ringbuf helper `bpf_ringbuf_reserve()` did not properly validate memory boundaries, enabling out-of-bounds access from within BPF programs.

- **CVE-2021-33200**. The verifier failed to account for `BPF_FETCH` (atomic fetch-and-add) side effects on register state, allowing programs to bypass bounds tracking after atomic operations.

- **CVE-2022-23222** (tr3e). Type confusion in the verifier's handling of pointer arithmetic on `PTR_TO_MEM` registers. The verifier allowed `PTR_TO_MEM + offset` to escape type tracking, enabling controlled out-of-bounds reads and writes. Exploited for LPE on kernels 5.8-5.16.

- **CVE-2022-0185**. Heap overflow in the legacy BPF `setsockopt` path (not the modern eBPF verifier per se, but in the FSConfig/BPF interaction). Exploited for container escape from unprivileged user namespaces.

- **CVE-2022-2905**. Incorrect bounds propagation when the verifier processed `BPF_ADD` on already-bounded registers, creating a window for OOB access.

- **CVE-2023-2163** (Google Project Zero). Verifier state pruning bug: the verifier's pruning logic incorrectly determined that two verification states were equivalent when they were not, allowing a malicious program to reach states the verifier believed were unreachable. Enabled out-of-bounds map access.

- **CVE-2023-39191**. Insufficient validation of `BPF_BTF_LOAD` commands allowed a privileged attacker to craft BTF data that confused the verifier's type system.

- **CVE-2024-41009**. Double-free in BPF ringbuf when `bpf_ringbuf_reserve()` was used with specific ring buffer configurations.

### Verifier Hardening Timeline

| Kernel Version | Hardening Measure |
|---|---|
| 5.8 (2020) | `CAP_BPF` separated from `CAP_SYS_ADMIN` |
| 5.10 (2020) | `unprivileged_bpf_disabled` sysctl introduced |
| 5.16 (2022) | `unprivileged_bpf_disabled=2` as default (distros) |
| 5.18 (2022) | `BPF_PROG_TYPE_SOCKET_FILTER` restrictions tightened |
| 6.0 (2022) | Precision tracking improvements for ALU operations |
| 6.1 (2022) | `bpf_log` reworked, better verifier error diagnostics |
| 6.9 (2024) | BPF token for delegated, scoped capability management |

---

## 2. JIT Compiler Vulnerabilities

The BPF JIT compiler translates verified bytecode into native machine instructions. JIT bugs can create exploitable divergences between the verifier's model and actual execution behavior.

### Key Research

- **Nelson et al., "Specification and Verification of BPF JIT Compilers" (OSDI 2020)**. Formalized JIT correctness using the Jitterbug framework. Identified multiple classes of JIT bugs on x86-64, ARM64, RISC-V, and s390x architectures. Demonstrated that many JIT bugs were *semantic* -- the generated code was syntactically valid but violated the verifier's assumptions about register state.

- **Vishwanathan and Shacham, "JIT-Picking: Differential Testing of BPF JIT Compilers" (2024)**. Developed differential fuzzing between the BPF interpreter and JIT compilers across architectures. Found divergences where JIT-compiled code produced different results than interpreted execution, any of which could be exploitable.

- **CVE-2020-27194**. x86-64 JIT bug in `BPF_RSH` (right shift) for 64-bit operations: the JIT emitted an incorrect shift amount, causing the actual program behavior to diverge from the verifier's model. Exploitable for OOB reads.

- **CVE-2021-29154**. The x86-64 BPF JIT did not properly emit branch target instructions for certain conditional jump patterns, allowing branch misprediction to execute unverified code paths.

- **Constant blinding bypass (2018-2020)**. The JIT uses constant blinding (XOR-masking immediate values) to mitigate JIT spraying. Multiple researchers demonstrated bypasses where carefully chosen constants survived the blinding transformation, enabling JIT spray attacks.

---

## 3. Speculative Execution Attacks on BPF

BPF's in-kernel execution model makes it a uniquely powerful vehicle for speculative execution attacks.

### Key Work

- **Jann Horn (Google Project Zero, 2021), "Speculative execution attacks on BPF"**. Demonstrated that even *verified* BPF programs could perform speculative out-of-bounds reads if the CPU's branch predictor mispredicted the outcome of bounds checks that the verifier had approved. The verifier proves safety for the *architectural* execution path, but speculative execution follows *predicted* paths that may violate bounds. This was a fundamental challenge: the verifier cannot model microarchitectural behavior.

- **Kernel mitigations**: `BPF_JIT_ALWAYS_ON` (disabling the interpreter to prevent interpreter-based gadgets), speculative load hardening in JIT output (inserting `lfence` or masking instructions after conditional branches), and `bpf_spec_v1` / `bpf_spec_v4` annotations in the verifier to track speculation-relevant state.

- **Simon et al. (2022)**. Extended speculative analysis to show that BPF helper function calls could serve as speculation gadgets, particularly `bpf_probe_read_kernel()` and `bpf_map_lookup_elem()`, both of which perform memory accesses whose addresses could be speculatively controlled.

---

## 4. Privilege Escalation via BPF

BPF has been a consistent vector for local privilege escalation, particularly in container escape scenarios.

### Attack Patterns

- **Unprivileged BPF exploitation (pre-5.16)**. When `unprivileged_bpf_disabled=0`, any user could load `BPF_PROG_TYPE_SOCKET_FILTER` programs. Combined with verifier bugs, this provided a reliable LPE path from unprivileged users. This was the primary exploitation path for CVE-2020-8835, CVE-2021-3490, and CVE-2022-23222.

- **Container escape via BPF**. Containers with `CAP_SYS_ADMIN` (or `CAP_BPF` + `CAP_PERFMON` + `CAP_NET_ADMIN`) could load BPF programs and exploit verifier bugs for kernel code execution. CVE-2022-0185 was a prominent example of BPF-adjacent container escape.

- **Capability confusion**. `CAP_BPF` was introduced in kernel 5.8 to provide finer-grained control than `CAP_SYS_ADMIN`. However, the actual power granted by `CAP_BPF` -- including the ability to read and write *all* BPF maps on the system -- far exceeds what most administrators expect from a "monitoring" capability. This gap is central to the BPF map poisoning threat model.

---

## 5. BPF as an Offensive Platform

### Key Projects and Research

- **ebpfkit (Guillaume Fournier, DefCon 29, 2021)**. A comprehensive rootkit framework using eBPF. Hooks network functions to perform man-in-the-middle attacks, hides processes via `getdents64` interception, and provides persistent backdoor access. Demonstrated the feasibility of BPF-based rootkits but required loading attacker-controlled BPF programs.

- **TripleCross (Marcos S., 2023)**. Open-source eBPF rootkit with modules for backdoor execution, library injection, execution hijacking, and rootkit hiding. Uses BPF trampolines and fentry/fexit hooks. Academic analysis of offensive BPF capabilities.

- **bad-bpf (Pat Hogan / Datadog, 2022)**. Collection of proof-of-concept offensive BPF programs: PID hiding via `getdents64` tracepoint hooking, sudo credential theft via `bpf_probe_read_user`, and command-and-control via BPF maps as covert channels.

- **Hejazi et al., "Evil eBPF: Practical Abuses of an In-Kernel Bytecode Runtime" (BlackHat 2024)**. Cataloged offensive uses of BPF including covert communication channels via BPF maps, data exfiltration through BPF ringbuffers, and network traffic manipulation. Discussed BPF maps as C2 channels but did not analyze modification of defensive tool maps.

- **Brendan Gregg, "BPF Security Auditing" (2021)**. Practical guide to auditing BPF programs and maps on production systems. Noted the visibility challenge: an adversary with BPF access can observe and potentially interfere with other BPF programs on the same host.

---

## 6. Key Researchers

- **Jann Horn** (Google Project Zero). Speculative execution attacks on BPF, multiple verifier vulnerability discoveries.
- **Manfred Paul**. CVE-2020-8835, CVE-2021-3490 -- two of the most impactful BPF verifier LPE bugs. Pwn2Own winner.
- **Daniel Borkmann** (Isovalent). BPF co-maintainer, author of many verifier hardening patches, BPF token designer.
- **Alexei Starovoitov** (Meta). BPF co-maintainer, original eBPF designer, verifier architect.
- **Andrii Nakryiko** (Meta). BPF library (libbpf) maintainer, BTF/CO-RE architect.
- **Guillaume Fournier** (Datadog). ebpfkit author, Tetragon contributor, offensive/defensive BPF research.
- **KP Singh** (Google). BPF LSM author, kernel security subsystem contributor.
- **Luke Nelson** (University of Washington). JIT verification with Jitterbug/Serval.

---

## 7. Relevance to BPF Map Poisoning

The eBPF security research landscape has overwhelmingly focused on two vectors: (1) exploiting the verifier to load malicious programs, and (2) using legitimately loaded programs for offensive purposes. Both require **program loading** as a prerequisite.

BPF map poisoning exploits a third, understudied vector: the **runtime data plane**. After kernel hardening made program injection increasingly difficult (unprivileged BPF disabled by default, continuous verifier tightening, BPF token scoping), the BPF map interface -- which requires only `CAP_BPF` and no verifier interaction -- remains a permissive, unmonitored attack surface.

The extensive verifier hardening effort demonstrates the kernel community's recognition that BPF is a security-critical subsystem. The absence of equivalent hardening for map access control represents a gap: the code plane is heavily guarded, but the data plane is open.
