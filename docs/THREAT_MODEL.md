# Threat Model

## BPF Map State Poisoning: Attacker Model and Scenario Analysis

---

## 1. Attacker Capabilities

### 1.1 Minimum Required Capability

The attack requires **one** of the following:

| Capability | Kernel Version | Notes |
|-----------|---------------|-------|
| `CAP_BPF` | 5.8+ | Dedicated BPF capability, sufficient alone for map read/write/delete |
| `CAP_SYS_ADMIN` | Any | Legacy capability that subsumes `CAP_BPF`; typical for privileged containers |

`CAP_BPF` grants access to the `bpf()` syscall with the following relevant commands:

- `BPF_MAP_GET_NEXT_ID` -- enumerate all BPF maps on the host
- `BPF_MAP_GET_FD_BY_ID` -- obtain a file descriptor to any map by its integer ID
- `BPF_MAP_LOOKUP_ELEM` -- read any entry from any map
- `BPF_MAP_UPDATE_ELEM` -- overwrite any entry in any map (unless frozen)
- `BPF_MAP_DELETE_ELEM` -- delete any entry from any map (hash/LRU types)
- `BPF_OBJ_GET` -- open pinned maps from `/sys/fs/bpf/`

### 1.2 Additional Requirements

- **bpftool or equivalent**: The `bpftool` utility is used in our PoCs for convenience, but the underlying `bpf()` syscall can be invoked from any language with syscall access (C, Go, Rust, Python via ctypes). An attacker could carry a static binary or use inline assembly.
- **Map identification**: The attacker must identify the target map. This is achieved through:
  - `bpf(BPF_MAP_GET_NEXT_ID)` to enumerate all maps, then matching by name (e.g., `config_map`, `interesting_syscalls`)
  - Direct access to pinned maps at known paths (e.g., `/sys/fs/bpf/tetragon/execve_map`)
  - `bpftool map list` output, which shows map name, type, key/value sizes

### 1.3 What the Attacker Does NOT Need

- Root shell (only `CAP_BPF` in the effective set)
- `CAP_NET_ADMIN`, `CAP_PERFMON`, or any other capability
- Kernel module loading (`CAP_SYS_MODULE`)
- `ptrace` access to the monitoring tool's process
- Knowledge of the tool's process ID
- Write access to the tool's configuration files
- Network access
- Persistence mechanisms

---

## 2. Attack Scenarios

### 2.1 Container Escape (Post-Exploitation)

**Context**: An attacker exploits a vulnerability in a containerized application (e.g., CVE in a web framework, deserialization bug) to escape the container namespace and gain host-level access.

**Relevance**: Container escapes typically result in `CAP_SYS_ADMIN` on the host. This is the exact scenario that Falco, Tracee, and Tetragon are deployed to detect. By poisoning BPF maps immediately after escape, the attacker can ensure that all subsequent host-level activity (lateral movement, credential harvesting, persistence) goes undetected.

**Attack sequence**:
1. Exploit containerized application vulnerability
2. Escape to host namespace (gain `CAP_SYS_ADMIN`)
3. Enumerate BPF maps: `bpftool map list`
4. Poison target map: single `bpftool map update` command
5. Proceed with post-exploitation (now invisible to eBPF monitors)

**Time to suppress telemetry**: < 1 second after obtaining host access.

### 2.2 Kernel Exploit Post-Exploitation

**Context**: An attacker achieves kernel code execution via a kernel vulnerability (use-after-free, heap overflow, type confusion in a subsystem such as io_uring, netfilter, or the BPF verifier itself).

**Relevance**: After kernel exploitation, the attacker has arbitrary kernel read/write. They can modify BPF maps directly from kernel memory (bypassing even `bpf_map_freeze()`), but the simpler path is to use `commit_creds()` to give their process `CAP_BPF` and then use the standard `bpf()` syscall. This is faster and more reliable than patching kernel memory.

**Attack sequence**:
1. Exploit kernel vulnerability for code execution
2. `commit_creds(prepare_kernel_cred(NULL))` for full capabilities
3. Return to userspace with `CAP_BPF`
4. Poison BPF maps via standard syscall interface
5. Install rootkit, establish persistence

### 2.3 Privileged Container

**Context**: Many production workloads run containers with `--privileged` or with explicitly granted `CAP_BPF`/`CAP_SYS_ADMIN`. This includes monitoring agents, network plugins (Cilium, Calico), log collectors, and some CI/CD runners.

**Relevance**: A compromised privileged container can directly access host BPF maps. For Tetragon specifically, maps are pinned to `/sys/fs/bpf/tetragon/`, which is often bind-mounted into the Tetragon container and thus accessible to any container that mounts the same BPF filesystem.

**Attack sequence**:
1. Compromise application running in privileged container
2. Access `/sys/fs/bpf/` or use `bpf()` syscall directly
3. Poison maps from within the container (no escape required)

### 2.4 Kubernetes Node Compromise

**Context**: In Kubernetes, security tools run as DaemonSets (one pod per node). An attacker who gains node-level access (kubelet exploit, hostPath abuse, privileged pod scheduling via RBAC misconfiguration) can target the security DaemonSet's BPF maps.

**Relevance**: This is particularly insidious because:
- The security tool's pod continues running (no restart, no CrashLoopBackOff)
- Kubernetes health checks (liveness/readiness probes) typically verify the process is alive, not that BPF maps are intact
- The control plane sees the DaemonSet as healthy
- No alerts are generated for the poisoning itself

**Attack sequence**:
1. Gain node access via Kubernetes attack vector
2. Identify security DaemonSet's BPF maps
3. Poison maps
4. Security tool reports healthy but detects nothing
5. Attacker operates freely on the node

### 2.5 eBPF-Capable Pods (Legitimate CAP_BPF)

**Context**: Some workloads legitimately need `CAP_BPF`: network observability (Hubble, Pixie), custom tracing (bpftrace scripts), performance profiling (BCC tools). These pods are granted `CAP_BPF` through Kubernetes SecurityContext.

**Relevance**: A compromised observability pod with `CAP_BPF` can poison security tool maps as a side effect of its legitimate capabilities. This represents a privilege boundary violation: the pod was trusted for observability, not for modifying security tool state, but the kernel enforces no such distinction.

### 2.6 Supply Chain Compromise

**Context**: A malicious eBPF program shipped as part of a legitimate tool (e.g., a compromised CNI plugin, a trojaned observability agent) could include map poisoning logic that executes silently alongside its intended functionality.

**Relevance**: The BPF verifier validates memory safety and termination, not intent. A verified BPF program can use `bpf_map_update_elem()` to write to maps belonging to other programs if it obtains a reference via `bpf_map_lookup_elem()` on a shared map, or if userspace helper code performs the poisoning via the `bpf()` syscall.

---

## 3. Attacker Goals

### 3.1 Primary: Telemetry Suppression

Suppress security event generation to operate undetected. This is the focus of this research and has been empirically demonstrated against all three tools.

### 3.2 Secondary: Persistence

Maintain telemetry suppression across tool restarts. Approaches include:
- Periodic re-poisoning via cron or a background process
- A BPF program that monitors `bpf(BPF_MAP_UPDATE_ELEM)` calls targeting the security tool's maps and re-poisons after each legitimate update
- Modifying the tool's configuration files to reduce detection scope, then restoring map state to avoid detection of the tampering itself

### 3.3 Tertiary: Disabling Enforcement

For tools with enforcement capabilities (Tetragon's `TracingPolicyEnforced` with `sigkill` action), map poisoning can disable kill decisions:
- Clearing Tetragon's policy maps prevents enforcement actions from matching
- Emptying `execve_calls` prevents the enforcement tail call from executing
- This converts an enforcement tool into a no-op without crashing it

---

## 4. Scope

### 4.1 In Scope

| Element | Description |
|---------|-------------|
| Target tools | Falco (CNCF), Tracee (Aqua), Tetragon (Cilium) |
| Attack primitive | `bpf()` syscall: `BPF_MAP_UPDATE_ELEM`, `BPF_MAP_DELETE_ELEM` |
| Required capability | `CAP_BPF` (Linux 5.8+) or `CAP_SYS_ADMIN` |
| Attack surface | BPF maps used for configuration, routing, and state |
| Verified effect | 100% event suppression (zero events/alerts) |
| Environment | Linux kernel 5.8+, Docker containers, host-level access |

### 4.2 Out of Scope

| Element | Rationale |
|---------|-----------|
| Kernel vulnerabilities | The `bpf()` syscall behaves as designed; no kernel bug is exploited |
| Userspace process attacks | Killing, ptrace-ing, or SIGSTOP-ing the monitoring process is a known and trivially detectable attack |
| Configuration file tampering | Modifying `/etc/falco/`, Tracee CLI flags, or Tetragon CRDs is a userspace attack, not a BPF map attack |
| Network-level evasion | Dropping events at the network layer (between agent and backend) is orthogonal |
| Log tampering | Deleting or modifying log files after event generation is a post-detection attack |
| BPF verifier bypass | Exploiting the BPF verifier to load malicious programs is a separate research area |
| Kernel memory corruption | Direct `/dev/kmem` or kernel exploit memory writes bypass all userspace controls and are out of scope |

---

## 5. Comparison to Each Tool's Stated Threat Model

### 5.1 Tracee (Aqua Security)

**Tracee's stated model**: Detects suspicious activity in containers and on the host using eBPF tracepoints. Focuses on detecting container escapes, fileless malware, kernel exploits, and policy violations.

**Implicit assumption**: The `config_map` array (which holds `config_entry_t` including `enabled_policies` and `policies_version`) is only modified by Tracee's own userspace process. BPF programs read `enabled_policies` on every event via `match_scope_filters()` (defined in `pkg/ebpf/c/tracee.bpf.c`). If `enabled_policies == 0`, no policy matches and the event is discarded.

**Gap**: No mechanism prevents an external process from writing to `config_map`. The map is not frozen. The `policies_version` field acts as a cache-invalidation counter -- bumping it forces BPF programs to re-read the poisoned `enabled_policies` value, ensuring immediate effect.

**Attack**: Two fields modified in a single map update: `enabled_policies=0` at offset 216, `policies_version++` at offset 14.

### 5.2 Tetragon (Cilium/Isovalent)

**Tetragon's stated model**: Provides runtime security enforcement and observability using eBPF. Designed for Kubernetes environments. Supports enforcement actions (SIGKILL) via TracingPolicy CRDs.

**Implicit assumption**: The pinned BPF maps at `/sys/fs/bpf/tetragon/` are only accessed by the Tetragon agent process. The `execve_calls` prog_array routes execution through tail calls (`event_execve` -> sub-programs). The `execve_map` hash map tracks all processes by their PID, enabling correlation across events.

**Gap**: All maps are pinned to a well-known, predictable filesystem path. Pinning is designed for persistence across program restarts, but it also makes maps trivially discoverable and accessible. No map is frozen. No runtime integrity checks exist. Tetragon does not monitor its own maps for unexpected modifications.

**Attack**: (1) Delete entries from `execve_calls` prog_array at `/sys/fs/bpf/tetragon/__base__/event_execve/execve_calls` -- tail calls fail silently (return to caller with no action). (2) Clear all entries from `execve_map` at `/sys/fs/bpf/tetragon/execve_map` -- all processes become invisible to sensors.

### 5.3 Falco (Sysdig/CNCF)

**Falco's stated model**: Runtime threat detection for containers and hosts. Uses eBPF (or kernel module) to capture system calls and applies rules to generate alerts. Part of the CNCF ecosystem with widespread production deployment.

**Implicit assumption**: The `interesting_syscalls` BPF array map is populated at initialization with a bitmask indicating which syscall numbers should be captured. BPF programs consult this array on every syscall entry; if `interesting_syscalls[NR] == 0`, the syscall is skipped entirely at the kernel level, never reaching userspace rule evaluation.

**Gap**: The map is not frozen after initialization. The map is not pinned (slightly harder to find than Tetragon's maps), but is trivially enumerable via `bpf(BPF_MAP_GET_NEXT_ID)` and identifiable by its name and type (array, 512 entries). No userspace polling or heartbeat verifies that map contents match the expected configuration.

**Attack**: Zero all 512 entries in the `interesting_syscalls` array. Every BPF probe returns early without capturing any data. The Falco userspace process continues running but receives no events from the kernel.

---

## 6. Detection Difficulty

BPF map state poisoning is difficult to detect with current tooling:

| Detection Method | Effectiveness | Limitation |
|-----------------|--------------|------------|
| Process monitoring | None | No process is killed or started |
| File integrity monitoring | None | No files are modified |
| Network monitoring | None | No network traffic is generated |
| Audit log (`auditd`) | Partial | `bpf()` syscalls can be audited, but the volume of legitimate BPF syscalls in a Kubernetes environment makes this impractical without significant filtering |
| BPF program self-checks | None currently | Tools would need to implement periodic map integrity verification, which none currently do |
| Userspace heartbeat | Possible but absent | A userspace thread could periodically read and verify critical map values, but no tool implements this |

The fundamental challenge is that map poisoning uses the **same API** (`bpf()` syscall) that the tools themselves use for legitimate operation. Distinguishing malicious map writes from legitimate ones requires understanding the caller's identity and intent, which the kernel does not currently enforce.
