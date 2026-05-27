# Container and BPF Isolation

## Overview

Container security relies on kernel isolation primitives (namespaces, cgroups, seccomp, capabilities) to confine workloads. Advanced sandboxing technologies (gVisor, Kata Containers) provide stronger isolation by interposing additional layers between containers and the host kernel. This survey examines how these isolation mechanisms interact with BPF, evaluates the BPF token mechanism introduced in kernel 6.9, and analyzes why current isolation is insufficient against BPF map poisoning.

---

## 1. Container Isolation Mechanisms

### Standard Container Isolation

A typical container (Docker, containerd, CRI-O) uses:

1. **Linux namespaces**: PID, network, mount, UTS, IPC, user, cgroup namespaces isolate the container's view of system resources.
2. **cgroups**: Resource limits (CPU, memory, I/O, PIDs).
3. **Seccomp-BPF**: System call filtering. Default Docker/containerd profiles block ~44 syscalls including `bpf()`.
4. **Capabilities**: Default containers run with a reduced capability set (~14 of 41 capabilities). `CAP_BPF` is not in the default set.
5. **AppArmor/SELinux**: MAC profiles restricting file, network, and capability access.
6. **Read-only root filesystem**: Prevents modification of container image contents.

### When Isolation Breaks Down for BPF

BPF isolation fails in several common configurations:

| Configuration | BPF Map Access | Prevalence |
|---|---|---|
| `--privileged` container | Full access (CAP_SYS_ADMIN) | Common in legacy workloads, CI/CD |
| `--cap-add BPF` | Full map access | Required for monitoring pods |
| `--cap-add SYS_ADMIN` | Full access | Common for system containers |
| Custom seccomp allowing `bpf()` | Depends on capabilities | Networking, monitoring workloads |
| Host PID namespace (`--pid=host`) | Can see host BPF context | Monitoring DaemonSets |
| Kubernetes privileged pods | Full access | Node-level agents |

### Kubernetes-Specific Considerations

In Kubernetes, eBPF security tools typically run as privileged DaemonSets:

```yaml
securityContext:
  privileged: true
  # or equivalently:
  capabilities:
    add: ["BPF", "SYS_ADMIN", "PERFMON", "NET_ADMIN"]
```

Any pod on the same node that obtains `CAP_BPF` (through privilege escalation, misconfiguration, or legitimate need) can access the security DaemonSet's BPF maps. Kubernetes Pod Security Standards (PSS) at the "restricted" level block `CAP_BPF`, but many workloads require "baseline" or "privileged" levels.

---

## 2. gVisor

### Architecture

gVisor (Google) implements a user-space kernel (the "Sentry") that intercepts and re-implements system calls for sandboxed containers. Instead of containers sharing the host kernel, gVisor interposes its own syscall implementation layer:

- **Sentry**: User-space Go application that implements Linux syscall semantics
- **Gofer**: File system proxy for host file access
- **Platform**: Mechanism for syscall interception (KVM or ptrace)
- **Seccomp**: Additional seccomp filters between Sentry and host kernel

### BPF in gVisor

gVisor does **not** implement the `bpf()` system call. Any `bpf()` call from within a gVisor-sandboxed container returns `ENOSYS` (function not implemented). This means:

- Containers running in gVisor cannot load BPF programs
- Containers running in gVisor cannot access BPF maps
- BPF-based security tools cannot run *inside* gVisor containers
- BPF map poisoning from within gVisor-sandboxed containers is impossible

### Limitations

- **Performance**: gVisor incurs significant syscall overhead (2-10x for syscall-heavy workloads) due to the user-space syscall re-implementation.
- **Compatibility**: Not all Linux syscalls and features are implemented. Complex workloads may be incompatible.
- **Scope**: gVisor protects individual containers but does not protect the host's BPF maps. If the gVisor Sentry or the host is compromised, BPF maps are still accessible.
- **Deployment**: Primarily used in Google Cloud Run, some GKE configurations, and select high-security workloads.

---

## 3. Kata Containers

### Architecture

Kata Containers runs each container in a lightweight virtual machine (microVM) using hardware virtualization (KVM, QEMU, Cloud Hypervisor, Firecracker). The container processes run in a separate kernel instance inside the VM, providing strong isolation:

- **Guest kernel**: A minimal Linux kernel running inside the VM
- **Agent**: A process inside the VM that manages containers
- **Shim**: Host-side component that communicates with the VM agent
- **Hypervisor**: KVM-based hardware isolation

### BPF Isolation in Kata

Because each Kata container has its own kernel:

- BPF programs and maps created inside a Kata container exist in the guest kernel's BPF subsystem, not the host's
- A compromised Kata container cannot access host BPF maps (the hypervisor boundary prevents this)
- Host-level BPF security tools (running on the host kernel) are isolated from Kata container attacks
- BPF map poisoning across the hypervisor boundary is not possible

### Limitations

- **Overhead**: VM startup time (100-500ms) and memory overhead (per-VM kernel, ~20-50 MB)
- **BPF visibility loss**: Host-level BPF security tools cannot observe processes inside Kata VMs at the same granularity as regular containers. The hypervisor boundary that provides isolation also limits monitoring.
- **Deployment complexity**: Requires hardware virtualization support, additional runtime configuration
- **Networking**: Network traffic must cross the hypervisor boundary, adding latency

---

## 4. Firecracker

### Architecture

Firecracker (Amazon) is a microVM monitor designed for serverless computing (AWS Lambda, Fargate). It provides a minimal virtual machine with:

- Minimal device model (~5 emulated devices)
- Fast boot times (<125ms)
- Low memory overhead (~5 MB per VM)
- Jailer component for additional host-side sandboxing

### BPF Implications

Like Kata Containers, Firecracker provides kernel-level isolation. BPF maps in the guest and host are completely separate. However, Firecracker's minimal kernel does not typically run eBPF programs, so the isolation benefit is primarily about *protecting* host BPF maps from guest compromise.

---

## 5. BPF Token (Kernel 6.9+)

### Design

BPF token, introduced by Andrii Nakryiko in kernel 6.9 (2024), provides a delegation mechanism for BPF capabilities. Instead of granting `CAP_BPF` directly, a privileged process creates a BPF token with specific permissions and delegates it to less-privileged processes.

### Mechanism

```c
// Privileged process creates a token
struct bpf_token_create_attr {
    __u32 flags;       // Permissions to delegate
    __u32 bpffs_fd;    // BPF filesystem instance
};
int token_fd = bpf(BPF_TOKEN_CREATE, &attr, sizeof(attr));

// Token is passed to unprivileged process (via fd passing)
// Unprivileged process uses token for BPF operations
struct bpf_attr attr = {
    .map_type = BPF_MAP_TYPE_HASH,
    .map_token_fd = token_fd,  // Token instead of capability
};
```

### Token Capabilities

A BPF token can delegate specific subsets of BPF operations:

- `BPF_TOKEN_CREATE_MAP`: Allow map creation (specific map types can be restricted)
- `BPF_TOKEN_CREATE_PROG`: Allow program loading (specific program types can be restricted)
- `BPF_TOKEN_ATTACH`: Allow program attachment

### Token and Map Isolation

BPF tokens improve the situation but do **not** fully solve BPF map poisoning:

1. **Token scope is per-operation, not per-object**: A token that allows `BPF_MAP_UPDATE_ELEM` allows it on *any* map the token holder can access, not just maps the holder created.

2. **Map access still uses global IDs**: Even with tokens, maps are identified by global IDs. There is no mechanism to restrict a token to only access maps created with the same token.

3. **BPF filesystem isolation**: Tokens are associated with a BPF filesystem instance (`/sys/fs/bpf/`). Mounting separate BPF filesystems per container provides some isolation for *pinned* maps, but does not affect access to maps via `BPF_MAP_GET_NEXT_ID` (ID-based access bypasses the BPF filesystem).

4. **Adoption**: BPF token is new (kernel 6.9, May 2024). No major security tool has yet adopted it for map protection. The mechanism requires kernel 6.9+ and user-space support in libbpf.

### Token as Partial Mitigation

BPF token moves in the right direction by introducing scoped delegation, but the current design addresses program loading delegation (allowing unprivileged containers to load pre-approved program types) rather than map access control. Future extensions could add per-map token binding.

---

## 6. Seccomp-BPF as BPF Restriction

### Restricting the bpf() Syscall

Seccomp-BPF can filter `bpf()` calls by inspecting the command argument:

```c
// Allow only BPF_MAP_LOOKUP_ELEM, block BPF_MAP_UPDATE_ELEM
BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bpf, 0, ALLOW),
BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, BPF_MAP_UPDATE_ELEM, BLOCK, 0),
BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, BPF_MAP_DELETE_ELEM, BLOCK, 0),
```

### Limitations

1. **Argument inspection depth**: Seccomp can inspect the first 6 arguments of a syscall (via `struct seccomp_data`), which includes the BPF command. However, it cannot inspect the *contents* of the `bpf_attr` struct (which is a user-space pointer), so it cannot filter by map ID. This means seccomp can block all `BPF_MAP_UPDATE_ELEM` calls but cannot allow updates to "your" maps while blocking updates to "their" maps.

2. **Self-restriction**: If the security tool applies a seccomp filter that blocks `BPF_MAP_UPDATE_ELEM`, the tool itself cannot update its own maps. This is incompatible with tools that dynamically update policies.

3. **Inheritance**: Seccomp filters apply to the calling process and all descendants. A filter applied to a container restricts all processes in that container but does not affect other containers or host processes.

---

## 7. User Namespace Restrictions on BPF

### Current Restrictions

- `unprivileged_bpf_disabled=2` (default since kernel 5.16): Prevents BPF program loading from non-initial user namespaces
- `CAP_BPF` in non-initial user namespaces does not grant BPF access (capability is namespace-relative, but BPF checks the initial user namespace)
- User namespace BPF restrictions focus on program *loading*, not map *access*

### Proposed Enhancements

Ongoing kernel discussions have considered:
- BPF namespace (not yet implemented, no consensus on design)
- Per-map ownership tracking with user namespace awareness
- BPF token integration with user namespaces (partially implemented in 6.9)

---

## 8. Runtime Container Security Benchmarks

### CIS Benchmarks for Docker/Kubernetes

The CIS (Center for Internet Security) benchmarks for Docker and Kubernetes recommend:

- Run containers as non-root (`--user`)
- Do not run privileged containers
- Drop all capabilities and add only required ones
- Use seccomp profiles that block unnecessary syscalls
- Use AppArmor/SELinux profiles

These recommendations, if followed strictly, would prevent BPF map poisoning from most containers. However, they do not address:

- Legitimate workloads that require `CAP_BPF` (monitoring agents, networking tools)
- Host-level processes with `CAP_BPF`
- Post-exploitation scenarios where an attacker escalates to `CAP_BPF`

### Pod Security Standards (PSS)

Kubernetes Pod Security Standards define three levels:

| Level | CAP_BPF | BPF Map Poisoning Risk |
|---|---|---|
| Privileged | Allowed | Full risk |
| Baseline | Allowed with explicit `capabilities.add` | Risk if BPF granted |
| Restricted | Blocked (only NET_BIND_SERVICE allowed) | No risk from this pod |

Most production clusters run some pods at baseline or privileged level, particularly infrastructure pods (monitoring, networking, logging).

---

## 9. Why Current Isolation Is Insufficient

### The Isolation Gap

| Isolation Layer | Protects Against BPF Map Poisoning? | Why Not |
|---|---|---|
| Namespaces | No | BPF maps are global, no BPF namespace |
| cgroups | No | Resource limits, not access control |
| Seccomp | Partially | Can block `bpf()` entirely, not selectively |
| Capabilities | No | `CAP_BPF` grants access to all maps |
| AppArmor | No | No BPF-specific hooks |
| SELinux | Partially | Has BPF hooks but rarely configured |
| BPF token | Partially | Scopes creation, not per-map access |
| gVisor | Yes (for gVisor containers) | No `bpf()` syscall support |
| Kata/Firecracker | Yes (for VM containers) | Separate kernel, but performance cost |

### The Fundamental Problem

Current container isolation was designed to restrict access to kernel resources that are namespace-aware (files, network, processes). BPF objects are not namespace-aware -- they exist in a global flat namespace with capability-based access control. Until BPF objects gain namespace awareness or fine-grained access control, any process with `CAP_BPF` on the host (regardless of container context) has full access to all BPF maps.

The only complete isolation mechanisms (gVisor, Kata Containers) achieve it by running separate kernels, completely eliminating shared BPF state. This is effective but comes with significant performance, compatibility, and operational costs.

---

## 10. Relevance to BPF Map Poisoning

The isolation and sandboxing landscape reveals that BPF map poisoning operates in a gap between two extremes:

1. **Standard containers**: Provide no BPF map isolation. Any container with `CAP_BPF` can poison any map.
2. **Hardware-isolated containers** (gVisor, Kata): Provide complete BPF isolation but at significant cost.

There is no middle ground -- no mechanism to provide selective, per-map access control within a shared kernel. BPF token (kernel 6.9) begins to address this gap but currently focuses on program loading delegation rather than map access control.

For the BPF map poisoning threat model, this means that any deployment using standard containers (the vast majority of production Kubernetes deployments) and granting `CAP_BPF` to any workload is vulnerable. The security tools deployed to protect these environments (Falco, Tracee, Tetragon) are themselves running in the same flat BPF namespace as potential attackers.
