# Problem Statement

## The Map State Integrity Gap in eBPF Security Tools

### 1. The Premise

The cloud-native security ecosystem has converged on eBPF as the preferred mechanism for runtime threat detection. Falco (Sysdig/CNCF), Tracee (Aqua Security), and Tetragon (Cilium/Isovalent) collectively protect a substantial fraction of production Kubernetes clusters worldwide. Each tool loads BPF programs into the kernel that attach to syscall tracepoints, kprobes, or LSM hooks, generating security events when monitored activity occurs.

All three tools rely on **BPF maps** as their kernel-side control plane: configuration registers, event routing tables, process tracking databases, and syscall filter arrays. The correctness of every security decision these tools make depends on the integrity of these maps.

### 2. The Gap

The Linux kernel's BPF subsystem enforces access control at **program and map creation time** via capability checks (`CAP_BPF`, `CAP_SYS_ADMIN`). However, once a BPF map exists, **any process with `CAP_BPF` can read, modify, or delete its entries**, regardless of which process or program created the map. There is no ownership model, no mandatory access control, and no audit trail for map modifications.

The kernel provides two optional hardening mechanisms:

- **`bpf_map_freeze()`** (kernel 5.2+): Makes a map permanently read-only from userspace after initial setup. Once frozen, `BPF_MAP_UPDATE_ELEM` and `BPF_MAP_DELETE_ELEM` return `-EPERM`. This is a one-way operation; a frozen map cannot be unfrozen.

- **`BPF_F_RDONLY_PROG` / `BPF_F_WRONLY_PROG`** (kernel 5.2+): Map creation flags that restrict BPF-program-side access. `BPF_F_RDONLY_PROG` prevents BPF programs from writing to the map (but does not restrict userspace). These flags are orthogonal to `bpf_map_freeze()`.

Neither mechanism is used by Falco, Tracee, or Tetragon on any of their security-critical maps.

### 3. The Disconnect

Each tool's documentation and threat model implicitly assumes that its kernel-side state is trustworthy. Their detection logic is designed to catch malicious activity by *other* processes -- container escapes, privilege escalation, suspicious file access. None of them consider the possibility that an attacker operating at the same privilege level (`CAP_BPF`) could directly manipulate their internal BPF map state to suppress event generation.

This creates a critical disconnect:

| Assumption | Reality |
|-----------|---------|
| BPF maps are private to the tool | Any `CAP_BPF` process can modify any map |
| Configuration set at load time persists | Map values can be overwritten at any time |
| Event pipeline integrity is guaranteed | Tail-call prog_arrays can be emptied |
| Process tracking state is authoritative | Hash maps can be cleared entirely |
| Syscall filters reflect policy intent | Array entries can be zeroed silently |

### 4. Why This Matters

The threat scenarios in which BPF map poisoning is most relevant are precisely the scenarios these tools are deployed to detect:

- **Container escape**: An attacker who escapes a container to the host typically gains `CAP_SYS_ADMIN` (and thus `CAP_BPF`). Before proceeding with further exploitation, they can suppress the host's eBPF security monitor's telemetry with a single command, ensuring all subsequent activity goes undetected.

- **Kernel exploit post-exploitation**: After achieving kernel code execution, an attacker can trivially obtain `CAP_BPF` and silence monitoring before performing persistence actions.

- **Privileged containers**: Containers running with `--privileged` or with `CAP_BPF` in their capability set can directly poison host BPF maps via `/sys/fs/bpf/` (for pinned maps) or `bpf(BPF_MAP_GET_NEXT_ID)` (for unpinned maps).

- **Kubernetes node compromise**: In Kubernetes environments, Tetragon and Falco are typically deployed as DaemonSets. An attacker who compromises the node (via kubelet exploit, hostPath mount abuse, or privileged pod scheduling) can disable the monitoring DaemonSet's BPF maps without killing its process, avoiding the restart alerts that process termination would trigger.

- **eBPF-capable pods**: Some workloads legitimately require `CAP_BPF` (networking, observability). These pods can poison security tool maps as a side channel.

In each scenario, the attacker's action (a single `bpftool map update` command) is faster, quieter, and harder to detect than killing the monitoring process, which would at minimum generate a process exit event and likely trigger a restart via the container orchestrator.

### 5. The Core Problem

**The eBPF security monitoring ecosystem has built a detection architecture whose kernel-side integrity depends entirely on the absence of a co-located process with the same privilege level (`CAP_BPF`) that the tools themselves require to operate. To our knowledge, no tool validates, monitors, or protects the integrity of its own BPF map state at runtime. The kernel provides mechanisms to harden maps (`bpf_map_freeze()`, `BPF_F_RDONLY_PROG`), but none of the major tools use them. This constitutes a systemic, cross-tool trust boundary weakness in the cloud-native security stack.**

### 6. Scope of This Work

This research:

1. **Identifies** the BPF map access control gap as a cross-tool telemetry suppression vector
2. **Develops** concrete proof-of-concept attacks against each of the three major tools
3. **Empirically verifies** that each attack achieves 100% event suppression
4. **Analyzes** the root cause (missing use of available kernel hardening primitives)
5. **Proposes** concrete mitigations at both the tool and kernel levels

This work does **not** present new kernel vulnerabilities. The `bpf()` syscall behaves as designed. The vulnerability lies in the security tools' failure to use available hardening mechanisms and their implicit trust in the integrity of their own runtime state.
