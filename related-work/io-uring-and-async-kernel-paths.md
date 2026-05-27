# io_uring and Asynchronous Kernel Paths

## Overview

io_uring is a high-performance asynchronous I/O framework introduced in Linux kernel 5.1 (2019) by Jens Axboe. It allows user-space applications to submit I/O operations via shared memory rings, which the kernel processes asynchronously without requiring per-operation system calls. io_uring has become both a significant performance enabler and a major kernel attack surface. This survey covers io_uring's security implications, its syscall bypass properties, and the parallels with BPF map poisoning as another kernel-level evasion mechanism.

---

## 1. io_uring Architecture

### Core Design

io_uring uses two lock-free ring buffers shared between user space and the kernel:

- **Submission Queue (SQ)**: User space writes submission queue entries (SQEs) describing I/O operations
- **Completion Queue (CQ)**: Kernel writes completion queue entries (CQEs) with operation results

After initial setup (`io_uring_setup()` syscall), all I/O operations are submitted by writing to the SQ and consumed by reading from the CQ, with minimal syscall involvement:

- `io_uring_enter()`: Optional syscall to notify the kernel of new submissions (can be avoided with `IORING_SETUP_SQPOLL`)
- **SQPOLL mode**: A kernel thread polls the SQ for new entries, eliminating the need for *any* syscall for I/O submission

### Supported Operations

io_uring supports a wide range of operations beyond simple file I/O:

| Category | Operations |
|---|---|
| File I/O | `read`, `write`, `readv`, `writev`, `fsync`, `fallocate` |
| Network | `accept`, `connect`, `send`, `recv`, `sendmsg`, `recvmsg` |
| File management | `openat`, `close`, `renameat`, `unlinkat`, `mkdirat` |
| Memory | `madvise`, `fadvise` |
| Polling | `poll_add`, `poll_remove` |
| Linking | `link_timeout`, `async_cancel` |
| Misc | `timeout`, `nop`, `provide_buffers` |
| Fixed resources | `register_files`, `register_buffers` |

---

## 2. io_uring as a Security Concern

### The Syscall Bypass Problem

Traditional security monitoring (including eBPF-based tools) instruments **system calls** as the primary observation point. io_uring fundamentally changes this model:

1. **Initial setup**: `io_uring_setup()` and `io_uring_register()` are syscalls and are observable
2. **Subsequent operations**: All I/O operations are submitted via shared memory, not syscalls
3. **In SQPOLL mode**: Even the `io_uring_enter()` syscall is eliminated -- a kernel thread processes submissions autonomously

This means that after io_uring is set up, an attacker can perform file reads, writes, network connections, and file management operations **without generating any syscall events** that tracepoint-based security tools would capture.

### Tool-Specific Impact

| Tool | io_uring Visibility | Gap |
|---|---|---|
| **Falco** (eBPF driver) | Monitors `sys_enter`/`sys_exit` tracepoints | io_uring operations bypass syscall tracepoints entirely |
| **Tracee** | Primarily syscall tracepoints | Same gap; some kprobe-based detection possible |
| **Tetragon** | Kprobes and LSM hooks | LSM hooks are called for io_uring operations (e.g., `security_file_open` for `IORING_OP_OPENAT`), providing visibility. Kprobes on VFS functions also catch io_uring paths. |
| **Audit subsystem** | Syscall-based auditing | io_uring operations are not logged by default audit rules |

### Research on io_uring Evasion

- **"io_uring and the Dark Side of the Ring" (CNCF blog, 2023)**. Detailed analysis of how io_uring operations bypass Falco and other syscall-based monitoring tools. Demonstrated that file reads, writes, and network connections via io_uring are invisible to Falco's default configuration.

- **"The state of io_uring security" (LWN.net, 2023)**. Covered the kernel community's debate on io_uring security. Discussed proposals to restrict io_uring via seccomp and LSM hooks.

- **Google's io_uring restrictions**. Google restricted io_uring in ChromeOS and Android due to its attack surface. The `io_uring_disabled` sysctl was introduced (kernel 6.6) to allow system-wide disabling: `0` = unrestricted, `1` = require `CAP_SYS_ADMIN`, `2` = fully disabled.

---

## 3. io_uring CVEs and Attack Surface

### Vulnerability History

io_uring has been a prolific source of kernel vulnerabilities:

- **CVE-2021-3491**. io_uring buffer registration bug leading to kernel heap overflow. Exploited for LPE.

- **CVE-2021-41073**. `io_uring` type confusion in `IORING_OP_PROVIDE_BUFFERS`, allowing out-of-bounds access.

- **CVE-2022-1043**. Use-after-free in io_uring's fixed file handling. The `io_uring_register()` operation for registering fixed files contained a race condition.

- **CVE-2022-29582**. Use-after-free when io_uring timeout was canceled concurrently with completion. Exploited for container escape (demonstrated by Ruia and others).

- **CVE-2023-2598**. io_uring `IORING_OP_READ_FIXED` did not properly validate buffer addresses with registered fixed buffers, enabling OOB kernel read.

- **CVE-2023-21400**. io_uring use-after-free in `io_install_fixed_file()`. Affected Android devices.

- **CVE-2024-0582**. io_uring `IORING_OP_MADVISE` reference counting bug. The `madvise(MADV_DONTNEED)` operation via io_uring did not properly handle page reference counts, enabling use-after-free on freed pages.

### Attack Surface Analysis

io_uring's attack surface is exceptionally large because:

1. **Complex kernel code path**: io_uring re-implements syscall functionality in a non-standard path (async worker threads), duplicating logic that has been hardened over decades in the standard syscall path
2. **Concurrency**: io_uring operations execute asynchronously, creating race condition opportunities absent from synchronous syscalls
3. **Resource management**: Fixed files, fixed buffers, and registered resources add complex lifetime management
4. **Feature velocity**: Rapid feature additions (new operations, new flags) outpace security review

---

## 4. Comparison: io_uring Evasion vs. BPF Map Poisoning

### Shared Properties

Both io_uring evasion and BPF map poisoning are **kernel-level evasion techniques** that bypass eBPF-based security monitoring. They share several characteristics:

| Property | io_uring Evasion | BPF Map Poisoning |
|---|---|---|
| Operates in kernel | Yes (io_uring worker threads) | Yes (BPF map data plane) |
| Bypasses syscall tracing | Yes (no syscalls generated) | Yes (events suppressed at source) |
| Requires capabilities | Not necessarily (unprivileged io_uring until 6.6) | Yes (`CAP_BPF`) |
| Affects Falco | Yes | Yes |
| Affects Tracee | Yes | Yes |
| Affects Tetragon | Partially (LSM hooks still fire) | Yes |
| Requires program loading | No | No |
| Uses legitimate kernel API | Yes (`io_uring_setup()`) | Yes (`bpf(BPF_MAP_UPDATE_ELEM)`) |

### Key Differences

1. **Mechanism**: io_uring evades monitoring by performing operations through a path that monitoring does not observe. BPF map poisoning evades monitoring by modifying the monitor's own state to suppress event generation. The former is a **bypass**; the latter is a **sabotage**.

2. **Scope of evasion**: io_uring evasion only hides operations performed via io_uring. An attacker must rewrite their tooling to use io_uring APIs. BPF map poisoning suppresses *all* events from the monitoring tool, including syscall-based operations, regardless of how the attacker performs them.

3. **Persistence**: io_uring evasion requires the attacker to use io_uring for each operation. BPF map poisoning is a one-time action: after poisoning the map, all subsequent monitoring is suppressed without further attacker action.

4. **Mitigation difficulty**: io_uring evasion can be mitigated by monitoring at the VFS/LSM layer instead of the syscall layer (as Tetragon does). BPF map poisoning is harder to mitigate because the attack targets the monitoring infrastructure itself.

### Combined Attack Scenario

The most potent evasion scenario combines both techniques:

1. Attacker gains `CAP_BPF` (via container escape or privilege escalation)
2. Attacker poisons BPF maps of security tools (disabling all monitoring)
3. Attacker uses io_uring for subsequent operations (belt-and-suspenders evasion)
4. Neither syscall-based nor BPF-based monitoring observes the attacker's activity

---

## 5. io_uring Restrictions and Hardening

### Kernel-Level Restrictions

- **`io_uring_disabled` sysctl (kernel 6.6)**: System-wide io_uring disable flag. `2` fully disables io_uring for all users.
- **Seccomp io_uring support (kernel 6.6)**: Seccomp can now filter `io_uring_setup()` and `io_uring_enter()`, preventing io_uring initialization.
- **io_uring cgroup controller**: Proposed but not yet merged; would allow per-cgroup io_uring restrictions.

### Monitoring Mitigations

- **LSM hook monitoring**: LSM hooks (e.g., `security_file_open`, `security_socket_connect`) are called from io_uring operation paths, providing visibility independent of syscall tracing. Tetragon's LSM-based approach catches most io_uring operations.
- **io_uring tracepoints**: The kernel provides io_uring-specific tracepoints (`io_uring:io_uring_submit_sqe`, `io_uring:io_uring_complete`) that eBPF tools can attach to.
- **VFS kprobes**: Monitoring at the VFS layer (e.g., kprobes on `vfs_read`, `vfs_write`, `do_filp_open`) captures operations regardless of whether they originate from syscalls or io_uring.

---

## 6. io_uring in Container Environments

### Container Runtime Restrictions

- **Docker**: Default seccomp profile blocks `io_uring_setup()` and `io_uring_enter()` since Docker 24.0
- **containerd**: Default seccomp profile blocks io_uring since 1.7
- **Kubernetes**: Depends on container runtime's seccomp profile
- **gVisor**: Does not implement io_uring
- **Kata Containers**: io_uring available inside the guest VM but does not affect host monitoring

### When Containers Need io_uring

High-performance applications (databases, file servers, network proxies) may require io_uring for performance. These workloads must have io_uring allowed in their seccomp profiles, creating the same tension seen with `CAP_BPF`: legitimate performance needs conflict with security restrictions.

---

## 7. Audit Subsystem and io_uring

### The Audit Gap

The Linux audit subsystem (`auditd`) historically logs syscall invocations based on audit rules. io_uring operations bypass this logging:

- Audit rules like `-a always,exit -S openat` capture `openat()` syscalls but not `IORING_OP_OPENAT` io_uring operations
- The audit subsystem has been working on io_uring-aware audit rules, but coverage remains incomplete
- This mirrors the gap in eBPF-based monitoring tools

### Kernel Patches

Patches by Paul Moore and Richard Guy Briggs have added io_uring audit support for some operations, but the coverage is not comprehensive. The `AUDIT_URING` event type was introduced to capture io_uring operations.

---

## 8. Sendmsg and io_uring (CVE-2024-0582 class)

### sendmsg_zc (Zero-Copy Send)

`IORING_OP_SEND_ZC` and `IORING_OP_SENDMSG_ZC` enable zero-copy network sends via io_uring. These operations pin user-space buffers in kernel memory, creating complex lifetime management. Bugs in this path have led to use-after-free vulnerabilities (CVE-2024-0582).

### Relevance

The sendmsg_zc attack surface is relevant to this research as an example of how asynchronous kernel paths create vulnerabilities distinct from their synchronous counterparts. Both sendmsg_zc bugs and BPF map poisoning exploit the gap between the security model of the original (synchronous) path and the actual behavior of the asynchronous/data-plane path.

---

## 9. Relevance to BPF Map Poisoning

io_uring and BPF map poisoning represent two instances of a broader class: **kernel-level evasion of security monitoring**. Both exploit the fact that modern security tools were designed around the syscall interface as the primary observation point. io_uring creates a parallel execution path that bypasses the observation point; BPF map poisoning modifies the observer itself.

The comparison is instructive:

1. **io_uring evasion has received significant attention** (CVE advisories, kernel mitigations, seccomp support, sysctl disable flag, container runtime defaults). The kernel community recognized and addressed the threat within a few years of io_uring's introduction.

2. **BPF map poisoning has received no attention**. No CVE, no kernel mitigation, no tool-level hardening, no seccomp or sysctl mechanism to prevent it. This disparity suggests that the threat has not been recognized.

3. **BPF map poisoning is arguably more severe**: io_uring evasion requires the attacker to use io_uring for each operation; BPF map poisoning disables monitoring with a single operation and persists without further attacker action. io_uring evasion can be mitigated by monitoring at non-syscall layers (LSM, VFS); BPF map poisoning attacks the monitoring infrastructure itself.
