# Linux Kernel Security

## Overview

The Linux kernel implements a multi-layered security architecture comprising capabilities, namespaces, mandatory access control (MAC) frameworks, and system call filtering. This survey examines how these mechanisms interact with eBPF, focusing on the capability model that governs BPF access and the gap between the intended scope of `CAP_BPF` and its actual power -- a gap that is central to the BPF map poisoning threat model.

---

## 1. The Linux Capabilities Model

### Design and Evolution

Linux capabilities decompose the monolithic root privilege into fine-grained units. Introduced in kernel 2.2 (1999) and significantly expanded through subsequent versions, the capability model aims to follow the principle of least privilege: a process should hold only the capabilities it needs.

As of kernel 6.9, Linux defines 41 capabilities. Key capabilities relevant to BPF:

| Capability | Introduced | Scope |
|---|---|---|
| `CAP_SYS_ADMIN` | 2.2 | Catch-all administrative privilege |
| `CAP_BPF` | 5.8 (2020) | BPF program loading and map operations |
| `CAP_PERFMON` | 5.8 (2020) | Performance monitoring, perf_event access |
| `CAP_NET_ADMIN` | 2.2 | Network administration, XDP/TC attachment |
| `CAP_SYS_PTRACE` | 2.2 | Process tracing, /proc access |

### CAP_BPF: Design Intent vs. Actual Power

`CAP_BPF` was introduced by Daniel Borkmann in kernel 5.8 (commit `2c78ee89, "bpf: implement CAP_BPF"`) to decouple BPF operations from the overly broad `CAP_SYS_ADMIN`. The design intent was to allow BPF-based monitoring tools to operate without full administrative privilege.

**Intended scope (documentation):**
- Load and manage BPF programs
- Create and access BPF maps
- Attach BPF programs to hooks (with additional capabilities for some hook types)
- Read kernel memory via `bpf_probe_read_kernel()` (with `CAP_PERFMON`)

**Actual power granted:**
- Read, modify, and delete entries in **any** BPF map on the system, regardless of creator
- Enumerate all BPF programs, maps, and links via `BPF_*_GET_NEXT_ID`
- Read map contents and program bytecode via `BPF_*_GET_INFO_BY_FD`
- Pin and unpin BPF objects in the BPF filesystem (`/sys/fs/bpf/`)

The gap between intent ("manage your own BPF resources") and reality ("access all BPF resources system-wide") is the foundation of BPF map poisoning. There is no per-map or per-program ownership enforcement -- `CAP_BPF` is a system-wide capability granting uniform access to all BPF objects.

### Capability Inheritance

Capabilities propagate through `execve()` according to the capability bounding set, permitted set, effective set, and ambient set. In container environments:

- Privileged containers inherit all capabilities from the host
- Non-privileged containers can be granted specific capabilities via `--cap-add`
- `CAP_BPF` can be granted independently: `docker run --cap-add BPF`
- Kubernetes SecurityContext: `capabilities: { add: ["BPF"] }`

A container with only `CAP_BPF` (no `CAP_SYS_ADMIN`) can still access all BPF maps on the host, including those belonging to security tools running as DaemonSets.

---

## 2. Linux Namespaces

### Namespace Types

| Namespace | Isolates | BPF Impact |
|---|---|---|
| `user` | UIDs, GIDs, capabilities | Capability checks use user-ns-relative IDs |
| `pid` | Process IDs | BPF can trace across PID namespaces |
| `net` | Network devices, sockets | Some BPF programs are per-netns |
| `mnt` | Mount points | `/sys/fs/bpf/` visibility |
| `cgroup` | cgroup hierarchy | BPF programs can attach to cgroups |
| `ipc` | IPC resources | Not directly BPF-relevant |
| `uts` | Hostname | Not directly BPF-relevant |
| `time` (5.6) | Boot/monotonic clocks | Not directly BPF-relevant |

### BPF and Namespace Isolation

BPF objects (programs, maps, links) exist in a **global namespace**. There is no BPF namespace. This means:

- A BPF map created in one container's context is accessible from any other container with `CAP_BPF` (in the initial user namespace)
- BPF program IDs and map IDs are globally unique integers, not namespace-relative
- `/sys/fs/bpf/` is a single global filesystem (though it can be mounted per-container, the underlying BPF objects remain global)
- The `bpf()` syscall operates in the global BPF object space regardless of the caller's namespace context

This global-namespace design is intentional -- BPF programs need to trace across namespace boundaries to provide system-wide visibility. However, it also means that namespace isolation (the foundation of container security) does not apply to BPF object access.

### User Namespace Restrictions

Since kernel 4.4, `unprivileged_bpf_disabled` (default 2 since 5.16) prevents BPF program loading from non-initial user namespaces. However, this restriction applies to program *loading*, not map *access*. A process with `CAP_BPF` in the initial user namespace can access all maps regardless of which user namespace context they were created in.

---

## 3. Seccomp-BPF

### Architecture

Seccomp-BPF (kernel 3.5, 2012) uses *classic* BPF (cBPF, not eBPF) to filter system calls. A seccomp filter is a BPF program that examines the syscall number and arguments and returns an action (allow, kill, trap, trace, or log).

### Seccomp and eBPF Interaction

- Seccomp filters can block the `bpf()` syscall entirely (`syscall number 321 on x86-64`), preventing all BPF operations.
- Container runtimes (Docker, containerd) apply seccomp profiles by default that block `bpf()` for unprivileged containers.
- However, containers that require BPF access (networking, monitoring) must have `bpf()` allowed in their seccomp profile, creating the access needed for map poisoning.

### Seccomp as Mitigation

Seccomp-BPF can partially mitigate BPF map poisoning by restricting which processes can call `bpf()`. However:

1. The security tools themselves need `bpf()` access to function
2. Seccomp cannot distinguish between a tool's legitimate `bpf(BPF_MAP_UPDATE_ELEM)` and an attacker's
3. Seccomp filters operate on syscall-level granularity; they cannot inspect BPF command arguments in a way that distinguishes "update your own maps" from "update another tool's maps"

---

## 4. Mandatory Access Control: AppArmor and SELinux

### AppArmor

AppArmor uses pathname-based access control with per-program profiles. AppArmor does not currently have BPF-specific policy hooks -- there is no AppArmor rule to control which BPF maps a process can access. AppArmor can restrict access to `/sys/fs/bpf/` (the BPF filesystem where pinned maps are stored), but cannot control access to maps via `bpf()` syscall with map IDs.

### SELinux

SELinux provides more granular control via its BPF policy hooks (added in kernel 5.0):

- `bpf_map_create`: Control which domains can create maps
- `bpf_map_read`: Control which domains can read map contents
- `bpf_map_write`: Control which domains can write map contents
- `bpf_prog_load`: Control which domains can load programs

SELinux BPF policy is defined per-domain, allowing rules like:
```
allow tetragon_t self:bpf { map_create map_read map_write prog_load prog_attach };
deny attacker_t tetragon_t:bpf { map_write };
```

However, in practice:

1. Most Kubernetes deployments do not use SELinux (or use it in permissive mode)
2. SELinux BPF policy definitions are complex and not widely deployed
3. The default SELinux policy for container runtimes does not define per-tool BPF map access rules
4. Cloud-native ecosystems (CNCF tooling) primarily target Ubuntu/Debian (AppArmor) rather than RHEL/CentOS (SELinux)

### LSM BPF Hooks

The kernel's BPF LSM hooks (`security_bpf`, `security_bpf_map`, `security_bpf_prog`) provide the most flexible control mechanism. A BPF LSM program can implement arbitrary access control logic for BPF operations. However, this creates a circular dependency for BPF map poisoning: the LSM program that would protect BPF maps is itself a BPF program whose maps could be poisoned (see `lsm-and-policy-enforcement.md`).

---

## 5. The Capability Hierarchy and BPF

### Privilege Levels for BPF Operations

| Operation | Required Capabilities |
|---|---|
| Load BPF program (general) | `CAP_BPF` + `CAP_PERFMON` (or `CAP_SYS_ADMIN`) |
| Load networking BPF program | `CAP_BPF` + `CAP_NET_ADMIN` |
| Attach to LSM hooks | `CAP_BPF` + `CAP_PERFMON` + `CAP_MAC_ADMIN` |
| Create BPF map | `CAP_BPF` |
| Read/write any BPF map | `CAP_BPF` |
| Enumerate BPF objects | `CAP_BPF` |
| Pin to `/sys/fs/bpf/` | `CAP_BPF` |
| Access perf events | `CAP_PERFMON` |

### The CAP_BPF Paradox

The capability design creates a paradox:

1. Security tools (Falco, Tracee, Tetragon) require `CAP_BPF` to load their programs and manage their maps
2. The maps they create are accessible to any other process with `CAP_BPF`
3. Removing `CAP_BPF` from potential attackers also removes it from legitimate monitoring tools
4. `CAP_BPF` cannot be scoped to "only your own maps" -- it is a system-wide capability

This is fundamentally different from, say, `CAP_NET_ADMIN`, where network namespace isolation limits the scope: a process with `CAP_NET_ADMIN` in a network namespace can only affect that namespace's networking. There is no equivalent BPF namespace to scope `CAP_BPF`.

---

## 6. Kernel Hardening Features

### KASLR (Kernel Address Space Layout Randomization)

KASLR randomizes the kernel's base address at boot, making exploit development harder. KASLR does not affect BPF map poisoning -- the attack operates through the legitimate `bpf()` API and does not require knowledge of kernel addresses.

### SMEP/SMAP/PXN

Supervisor Mode Execution Prevention (SMEP) and Supervisor Mode Access Prevention (SMAP) prevent the kernel from executing or accessing user-space memory. These mitigate kernel exploit techniques but are irrelevant to BPF map poisoning, which does not involve kernel code execution.

### Kernel Lockdown Mode

Kernel lockdown (kernel 5.4, LSM-based) restricts kernel functionality that could compromise integrity:

- **Integrity mode**: Prevents unsigned module loading, `/dev/mem` access, kexec of unsigned images
- **Confidentiality mode**: Additionally prevents kernel memory access via debugfs, kprobes, BPF reads

In confidentiality lockdown mode, BPF program loading is restricted. However, the lockdown policy does not specifically address BPF map modification -- if a process has already been granted `CAP_BPF` (and BPF is not fully disabled), map operations are permitted.

### kptr_restrict and dmesg_restrict

These sysctl settings limit kernel pointer and log access. They reduce information leakage but do not affect BPF map operations.

---

## 7. cgroups and BPF

### cgroup BPF Programs

BPF programs can be attached to cgroups, affecting all processes in the cgroup hierarchy:

- `BPF_PROG_TYPE_CGROUP_SKB`: Network packet filtering
- `BPF_PROG_TYPE_CGROUP_SOCK`: Socket creation/binding
- `BPF_PROG_TYPE_CGROUP_SYSCTL`: Sysctl access control
- `BPF_PROG_TYPE_CGROUP_DEVICE`: Device access control

These programs use BPF maps for configuration and state, subject to the same poisoning risk. A compromised process in one cgroup could poison BPF maps used by cgroup programs enforcing policy on other cgroups.

### cgroup v2 and BPF

cgroup v2 (unified hierarchy) integrates with BPF for resource accounting and access control. Kubernetes uses cgroup v2 with BPF for pod-level resource management. The BPF maps backing cgroup programs are global and unprotected.

---

## 8. The Fundamental Gap

### Capability Intent vs. Actual Power

The Linux security model aspires to least privilege, but the BPF capability design violates this principle:

| Principle | Expected BPF Behavior | Actual BPF Behavior |
|---|---|---|
| Least privilege | Access only your own BPF objects | Access all BPF objects system-wide |
| Isolation | BPF objects scoped to namespace | BPF objects are global |
| MAC enforcement | Per-map access control | No per-map MAC (without SELinux) |
| Audit | Map modifications logged | No audit trail for map operations |
| Ownership | Map creator has exclusive write | Any CAP_BPF process can write |

This gap exists because the BPF subsystem was designed for observability (where global visibility is a feature) and extended to security (where isolation is a requirement) without redesigning the access control model.

---

## 9. Relevance to BPF Map Poisoning

The Linux kernel security architecture provides robust isolation for most resources (files, network, processes) but provides essentially no isolation for BPF objects. The capability model -- the primary access control mechanism for BPF -- grants all-or-nothing access. The namespace model -- the foundation of container isolation -- does not apply to BPF objects. And the MAC frameworks -- the fine-grained access control layer -- either lack BPF-specific hooks (AppArmor) or have them but they are not deployed in practice (SELinux).

This creates the conditions for BPF map poisoning: a security tool and an attacker operating on the same host, both with `CAP_BPF`, have identical access to the tool's BPF maps. The kernel's security architecture does not provide any mechanism for the tool to claim exclusive ownership of its maps, except for `bpf_map_freeze()` (which is rarely used) and BPF token (kernel 6.9+, not yet widely adopted).
