# LSM Framework and BPF LSM Policy Enforcement

## Overview

The Linux Security Module (LSM) framework provides a kernel-level hook infrastructure for implementing mandatory access control policies. With the introduction of BPF LSM (kernel 5.7), security policies can be implemented as BPF programs that attach to LSM hooks, enabling dynamic, programmable security enforcement. This survey covers the LSM architecture, BPF LSM programs, how Tetragon and other tools use LSM for enforcement, and the irony that LSM BPF programs' state -- stored in BPF maps -- is itself unprotected against the very attack class that BPF map poisoning represents.

---

## 1. The LSM Framework

### Architecture

The Linux Security Module framework (introduced in kernel 2.6, circa 2003) places security hooks at critical kernel decision points. When the kernel is about to perform a privileged operation (opening a file, creating a socket, loading a module, etc.), it calls the registered LSM hooks, allowing each LSM to approve or deny the operation.

### Hook Points

The LSM framework defines approximately 230 hooks organized by subsystem:

| Category | Example Hooks | Count (~) |
|---|---|---|
| File operations | `file_open`, `file_permission`, `file_mmap` | ~20 |
| Inode operations | `inode_create`, `inode_link`, `inode_permission` | ~25 |
| Task operations | `task_alloc`, `task_kill`, `task_setrlimit` | ~15 |
| Socket operations | `socket_create`, `socket_connect`, `socket_sendmsg` | ~20 |
| BPF operations | `bpf`, `bpf_map`, `bpf_prog` | 3 |
| Network operations | `netlink_send`, `unix_stream_connect` | ~10 |
| IPC operations | `msg_queue_associate`, `shm_alloc_security` | ~15 |
| Key management | `key_alloc`, `key_permission` | ~5 |
| Misc | `capable`, `quotactl`, `syslog` | ~20 |

### Stacking

Since kernel 5.1 (major LSM stacking), multiple LSMs can be active simultaneously. The kernel calls each registered LSM's hook in order; if any LSM denies the operation, it is blocked. This enables configurations like:

```
SELinux + BPF LSM
AppArmor + BPF LSM
```

### Major LSM Implementations

| LSM | Type | Policy Model |
|---|---|---|
| SELinux | Compiled-in | Type enforcement, RBAC, MLS |
| AppArmor | Compiled-in | Path-based profiles |
| TOMOYO | Compiled-in | Path-based, learning mode |
| Smack | Compiled-in | Simplified mandatory access control |
| BPF LSM | BPF-based | Programmable, dynamic |
| Landlock | Compiled-in (5.13+) | Unprivileged sandboxing |
| Yama | Compiled-in | ptrace scope restrictions |
| LoadPin | Compiled-in | Restrict module/firmware loading |

---

## 2. BPF LSM Programs

### Introduction (Kernel 5.7, 2020)

BPF LSM, developed by KP Singh (Google), allows BPF programs to attach to LSM hooks. This enables:

- **Dynamic policy**: Policies can be loaded, modified, and unloaded at runtime without rebooting
- **Programmable logic**: Arbitrary policy logic in BPF (within verifier constraints)
- **Performance**: JIT-compiled BPF executes at near-native speed
- **Composition**: BPF LSM can stack with SELinux or AppArmor

### Program Type and Attachment

```c
// BPF LSM program example
SEC("lsm/file_open")
int BPF_PROG(restrict_file_open, struct file *file, int mask)
{
    // Read policy from BPF map
    struct policy *pol = bpf_map_lookup_elem(&policy_map, &key);
    if (!pol)
        return 0;  // Allow (no policy)

    // Check file against policy
    if (should_block(file, pol))
        return -EACCES;  // Deny

    return 0;  // Allow
}
```

- **Attachment**: `BPF_PROG_TYPE_LSM` programs attach to LSM hooks via `bpf_link`
- **Return value**: 0 allows the operation; negative errno denies it
- **Helper access**: BPF LSM programs can use most BPF helpers, including `bpf_probe_read_kernel()`, `bpf_get_current_pid_tgid()`, `bpf_send_signal()`, and `bpf_override_return()`
- **BTF support**: LSM hook arguments are available as BTF-typed parameters, enabling type-safe access to kernel data structures

### BPF LSM Hooks for BPF Operations

Three LSM hooks specifically govern BPF operations:

1. **`security_bpf(int cmd, union bpf_attr *attr, unsigned int size)`**: Called for every `bpf()` syscall. Can inspect the BPF command and attributes. Enables filtering BPF operations by command type.

2. **`security_bpf_map(struct bpf_map *map, fmode_t fmode)`**: Called when a process opens a BPF map file descriptor. Can inspect the map's properties (type, name, flags) and the requested access mode.

3. **`security_bpf_prog(struct bpf_prog *prog)`**: Called when a process acquires a BPF program file descriptor.

### The Self-Protection Problem

A BPF LSM program could theoretically protect BPF maps from unauthorized modification:

```c
SEC("lsm/bpf_map")
int BPF_PROG(protect_maps, struct bpf_map *map, fmode_t fmode)
{
    // Check if the map belongs to a protected tool
    u32 map_id = map->id;
    u32 *protected = bpf_map_lookup_elem(&protected_maps, &map_id);
    if (protected && (fmode & FMODE_WRITE)) {
        // Check if the caller is the authorized tool
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u32 *authorized = bpf_map_lookup_elem(&authorized_pids, &pid);
        if (!authorized)
            return -EACCES;  // Block unauthorized write
    }
    return 0;
}
```

However, this creates a **circular dependency**:

1. The BPF LSM program stores its policy in BPF maps (`protected_maps`, `authorized_pids`)
2. These policy maps are themselves BPF maps accessible to any `CAP_BPF` process
3. An attacker can poison the policy maps to remove the protection, then poison the target maps
4. The protection is only as strong as the protection of the policy maps, which is... zero

This is the fundamental irony of using BPF LSM to protect BPF maps: the guardian's own state is unguarded.

---

## 3. Tetragon's Use of LSM for Enforcement

### Architecture

Tetragon uses BPF LSM hooks for runtime enforcement (not just detection). When a TracingPolicy specifies an enforcement action, Tetragon attaches BPF LSM programs that can:

- **Override return values**: Using `bpf_override_return()` to block syscalls
- **Send signals**: Using `bpf_send_signal()` to kill violating processes
- **Log violations**: Emitting events via ring buffer

### Enforcement Pipeline

1. TracingPolicy defines enforcement rules (YAML):
```yaml
spec:
  kprobes:
    - call: sys_openat
      matchArgs:
        - index: 1
          operator: Prefix
          values: ["/etc/shadow"]
      matchActions:
        - action: Override
          argError: -1  # Return EPERM
```

2. Tetragon compiles this into BPF programs attached to the specified hooks
3. BPF programs consult BPF maps for policy configuration and process context
4. Enforcement decisions depend on map integrity

### Enforcement Maps

Tetragon's enforcement relies on several maps:

- **`filter_map`**: Stores compiled filter expressions for matching
- **`argfilter_maps`**: Per-argument filter values
- **`override_tasks`**: Tracks which tasks should have syscalls overridden
- **`enforcer_data`**: Enforcement action configuration

All of these maps are accessible to any `CAP_BPF` process. Poisoning `override_tasks` could disable enforcement for specific processes; poisoning `filter_map` could disable all policy matching.

### The Enforcement Integrity Problem

Tetragon's enforcement model assumes:

1. The BPF LSM program correctly implements the policy (guaranteed by Tetragon's code generation)
2. The map data accurately reflects the configured policy (NOT guaranteed -- maps are writable)
3. The enforcement decision is authoritative (undermined if map data is poisoned)

This means Tetragon's "enforcement" guarantee is actually a "detection-and-enforcement-if-maps-are-intact" guarantee. An attacker who can modify Tetragon's maps can:

- Prevent enforcement by clearing policy maps
- Selectively allow specific operations by modifying filter entries
- Break the process tracking that links enforcement to specific containers

---

## 4. The BPF LSM Security Gap

### What BPF LSM Can Protect

- File access, network connections, process operations -- any operation with an LSM hook
- BPF program loading (via `security_bpf_prog`)
- BPF map creation (via `security_bpf_map`)

### What BPF LSM Cannot Protect (Against Map Poisoning)

The BPF LSM hook `security_bpf_map` is called when a file descriptor to a map is *opened*, not when the map is *modified*. The lifecycle:

1. Process calls `bpf(BPF_MAP_GET_FD_BY_ID, map_id)` -- `security_bpf_map` is called
2. If the LSM allows, the process gets an fd
3. Process calls `bpf(BPF_MAP_UPDATE_ELEM, fd, key, value)` -- `security_bpf` is called (with cmd=BPF_MAP_UPDATE_ELEM)

The `security_bpf` hook receives the cmd and the `bpf_attr` struct, which contains the fd and key/value pointers. A sufficiently sophisticated BPF LSM program could inspect these to implement per-map write access control. However:

1. The `bpf_attr` is a userspace pointer that must be read with `bpf_probe_read_user()`
2. The key and value are also userspace pointers requiring additional reads
3. This creates a TOCTOU window: the values read by the LSM program may differ from the values the kernel ultimately uses
4. The LSM program's own policy (stored in BPF maps) is vulnerable to the same attack

### Comparison with Traditional LSMs

| Aspect | SELinux/AppArmor | BPF LSM |
|---|---|---|
| Policy storage | Kernel memory (non-BPF) | BPF maps |
| Policy modification | Requires `CAP_MAC_ADMIN` + special interfaces | Any `CAP_BPF` process (via map write) |
| Policy integrity | Protected by LSM itself | Unprotected (circular dependency) |
| Persistence | Survives across reboots (filesystem) | Ephemeral (kernel memory) |
| Attack surface | SELinux policy load interface | BPF map interface |

The critical difference: SELinux and AppArmor store their policies in kernel data structures that are protected by their own access control. Their policy modification interfaces (`/sys/fs/selinux/policy`, `apparmor_parser`) require specific capabilities and pass through the LSM's own hooks. BPF LSM stores its policy in BPF maps that are accessible to any `CAP_BPF` process, and the BPF LSM cannot protect its own maps without a circular dependency.

---

## 5. Landlock LSM

### Architecture (Kernel 5.13+)

Landlock is an LSM designed for unprivileged sandboxing. Unlike other LSMs, Landlock policies can be applied by unprivileged processes to restrict their own capabilities (and their children's).

### BPF Relevance

Landlock does not currently provide hooks for BPF operations. A process cannot use Landlock to restrict its own BPF map access. If Landlock were extended with BPF hooks, it could allow a process to voluntarily drop the ability to modify maps other than its own, providing a defense-in-depth mechanism against map poisoning.

---

## 6. Academic Research on LSM and BPF

### Key Papers

- **KP Singh, "MAC and Audit policy using eBPF (KRSI)" (Linux Plumbers Conference, 2019)**. Original proposal for BPF LSM. Described the design goals: dynamic policy, low overhead, composability with existing LSMs. Did not address the self-protection problem for BPF LSM policy maps.

- **Smalley and Craig, "Security Enhanced (SE) Android" (NDSS 2013)**. Demonstrated the value of mandatory access control in mobile environments. SELinux's BPF hooks were later modeled on the general SELinux architecture. Relevant as the gold standard for MAC policy integrity (SELinux protects its own policy).

- **Schreuders et al., "Towards Usable Application-Oriented Access Controls" (Int. J. Information Security, 2013)**. Surveyed application-oriented MAC frameworks and their usability challenges. The difficulty of writing correct MAC policies is relevant to BPF LSM: even if BPF LSM could protect its own maps, writing correct protection policies is non-trivial.

- **Jaeger et al., "Analyzing Integrity Protection in the SELinux Example Policy" (USENIX Security 2003)**. Formal analysis of SELinux policy integrity. The methodology -- analyzing whether the policy itself is protected against modification -- is directly applicable to BPF LSM policy integrity analysis.

---

## 7. The Irony of BPF LSM for Security

### The Promise

BPF LSM promises programmable, dynamic security enforcement at the kernel level. It is the foundation of Tetragon's runtime enforcement and an increasingly important component of cloud-native security stacks.

### The Irony

BPF LSM programs enforce security policies based on data stored in BPF maps. These maps are the BPF LSM program's "policy database." Unlike traditional LSMs (SELinux, AppArmor) whose policies are stored in protected kernel data structures, BPF LSM policies are stored in the most permissive kernel data structure available: BPF maps, which any `CAP_BPF` process can modify.

This creates a situation where:

1. A BPF LSM program enforces a policy that says "deny file X to process Y"
2. The policy data (file X, process Y) is stored in a BPF map
3. An attacker modifies the BPF map to remove the policy entry
4. The BPF LSM program now enforces an empty policy (allow everything)
5. The BPF LSM program is still attached to the hook, still executing, still "enforcing" -- but the policy it enforces has been gutted

The enforcement mechanism is intact; the enforcement data has been poisoned. The tool reports that enforcement is active (the BPF program is attached), but enforcement is effectively disabled.

---

## 8. Potential Solutions

### Map Freezing for Policy Maps

BPF LSM programs whose policies are static (e.g., "always block X") could use `bpf_map_freeze()` on their policy maps after initialization. This would prevent both the attacker and the tool itself from modifying the policy at runtime.

### Kernel-Side Policy Storage

Instead of storing policy in BPF maps, a BPF LSM program could encode policy directly in the BPF program bytecode (e.g., as hardcoded constants or as `rodata` in `.rodata` sections). The verifier already supports read-only data sections. This eliminates the map poisoning vector but removes the ability to dynamically update policies.

### Signed Map Contents

A future kernel extension could support cryptographic verification of map contents: the tool signs critical map entries with a key, and the BPF program verifies the signature before using the data. This would be costly (crypto in BPF is limited) but would provide integrity guarantees even against `CAP_BPF` attackers.

### Hybrid Approach

Separate policy into static and dynamic components:
- Static policy (immutable after load): Encoded in `.rodata` or frozen maps
- Dynamic policy (updated at runtime): Protected by userspace integrity checks (heartbeat, hash verification)

---

## 9. Relevance to BPF Map Poisoning

The LSM framework and BPF LSM are directly relevant to BPF map poisoning in two ways:

1. **BPF LSM is itself vulnerable**: BPF LSM programs' policies, stored in BPF maps, can be poisoned to disable enforcement. This is the most impactful form of map poisoning because it directly defeats a security enforcement mechanism.

2. **BPF LSM could be a mitigation**: The `security_bpf` and `security_bpf_map` hooks provide the kernel-level interception points needed to implement per-map access control. However, the circular dependency problem (the protector's own state is unprotected) must be solved, likely by storing the access control policy outside of BPF maps (e.g., in the BPF program's `.rodata` section or in kernel data structures).

The irony that the most sophisticated eBPF security mechanism (BPF LSM enforcement) is vulnerable to the simplest eBPF attack (map write) underscores the systemic nature of the BPF map access control gap.
