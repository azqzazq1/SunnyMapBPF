# Design Assumptions Analysis

This document examines the implicit security assumptions made by Tracee, Tetragon, and Falco regarding the integrity of their BPF maps, and demonstrates why each assumption is incorrect in a post-exploitation threat model.

---

## Assumption 1: "BPF maps are only writable by our daemon"

### The Assumption

All three tools operate under the implicit assumption that the BPF maps they create are private to their process. No tool documents or acknowledges the possibility of external map modification.

### Why It Is Wrong

The Linux BPF subsystem provides two mechanisms for external map access:

**Mechanism A: Map ID enumeration.**
Any process with `CAP_BPF` can enumerate all BPF maps on the system:

```c
// Iterate all maps
__u32 id = 0;
while (bpf_map_get_next_id(id, &id) == 0) {
    int fd = bpf_map_get_fd_by_id(id);
    struct bpf_map_info info = {};
    __u32 info_len = sizeof(info);
    bpf_obj_get_info_by_fd(fd, &info, &info_len);
    // info.name, info.type, info.key_size, info.value_size available
    // fd is now usable for bpf_map_update_elem()
}
```

This is the path used for Tracee and Falco attacks. The maps are not pinned, but they are fully enumerable by name and type.

**Mechanism B: Pinned paths.**
Tetragon pins all maps to `/sys/fs/bpf/tetragon/`. Any process can open these paths via `bpf_obj_get()`:

```c
int fd = bpf_obj_get("/sys/fs/bpf/tetragon/execve_map");
// fd is now usable for read/write operations
```

This is even simpler than enumeration -- the map path is deterministic and documented.

### Code Evidence

**Tracee** -- no map protection at creation (`pkg/ebpf/c/maps.h`):
```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, config_entry_t);
} config_map SEC(".maps");
```
No `BPF_F_RDONLY_PROG`, no `map_flags`, no `bpf_map_freeze()` call after initialization.

**Tetragon** -- maps pinned with no access control (`pkg/sensors/base.go`, map pin logic):
```go
MapDir: filepath.Join(mapDir, m.Name),
```
Pinned to world-readable paths under `/sys/fs/bpf/tetragon/`. No filesystem ACLs applied beyond standard bpffs permissions.

**Falco** -- map created without protection (`driver/bpf/maps.h` in falcosecurity/libs):
```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, SYSCALL_TABLE_SIZE); // 512
    __type(key, u32);
    __type(value, u8);
} interesting_syscalls SEC(".maps");
```
No freeze, no read-only flag, no integrity check.

### Impact

An attacker who gains `CAP_BPF` through any means (container escape, kernel exploit, capability misconfiguration, privileged container) can write to any of these maps immediately. The daemon has no way to detect or prevent this.

---

## Assumption 2: "CAP_BPF is rare in practice"

### The Assumption

Tool developers implicitly assume that the capability required to modify BPF maps (`CAP_BPF`) represents a high privilege bar that limits the practical relevance of map modification attacks.

### Why It Is Wrong

`CAP_BPF` (or the superset `CAP_SYS_ADMIN`) is available in multiple common post-exploitation scenarios:

**Scenario 1: Privileged containers.**
The most common deployment of BPF security tools involves running them in privileged containers with `--privileged` or with explicit `CAP_SYS_ADMIN`/`CAP_BPF`. Docker's default daemon configuration grants full capabilities to `--privileged` containers. Any process that escapes a privileged container into the host namespace has `CAP_BPF`.

**Scenario 2: Default Kubernetes configurations.**
`CAP_BPF` is not dropped by default in many Kubernetes distributions. Pods with `privileged: true` in the security context (common for monitoring agents, log collectors, and -- ironically -- security tools themselves) have unrestricted BPF access.

**Scenario 3: Container runtime exploits.**
Container escape vulnerabilities (runc CVEs, kernel namespace bugs) frequently yield root with full capabilities. At the point of container escape, the attacker has `CAP_BPF`.

**Scenario 4: Kernel exploits.**
Local privilege escalation to root (e.g., via filesystem, scheduler, or memory management bugs) yields all capabilities including `CAP_BPF`. The first action an attacker takes post-LPE is to disable monitoring -- BPF map poisoning enables this without triggering the monitoring tool.

**Scenario 5: Capability misconfigurations.**
`CAP_BPF` was separated from `CAP_SYS_ADMIN` in kernel 5.8 specifically to allow finer-grained delegation. Environments that grant `CAP_BPF` for debugging or monitoring purposes inadvertently expose the map modification attack surface.

### The Critical Context

BPF map poisoning is a **post-exploitation technique**, not an initial access vector. The relevant question is not "how hard is it to get `CAP_BPF`?" but "once an attacker has elevated privileges, can they disable monitoring silently?" The answer is yes, and the tools provide no defense against this.

The comparison is to other post-exploitation defense evasion techniques: killing the monitoring process (detectable via process monitoring), deleting log files (detectable via file integrity monitoring), or loading a rootkit (detectable via module loading monitoring). BPF map poisoning is **unique in being undetectable by the tool being evaded** because it operates within the tool's own data plane.

---

## Assumption 3: "Configuration state is trustworthy once set"

### The Assumption

All three tools write configuration to BPF maps during initialization and then trust those values for the lifetime of the program. There is no periodic re-validation, no checksum, no expected-value comparison.

### Why It Is Wrong

BPF maps are mutable shared memory. The value read by a BPF program at time T+1 may differ from the value written by the daemon at time T. The tools treat map reads as equivalent to reading a local variable, when they are actually reading shared mutable state accessible to the entire system.

### Code Evidence

**Tracee** -- `match_scope_filters()` in `tracee.bpf.c`:
```c
statfunc u64 match_scope_filters(...)
{
    // ...
    policies_config_t *policies_cfg = &config->policies_config;
    // ...
    res &= policies_cfg->enabled_policies;
    return res;
}
```
The function reads `enabled_policies` from the map value and uses it directly as a bitmask. If the value is 0, `res & 0 == 0` for all events. There is no validation that `enabled_policies` is non-zero or matches an expected set.

**Tracee** -- per-CPU caching with version check:
```c
// Simplified from tracee BPF code
config_entry_t *config = bpf_map_lookup_elem(&config_map, &zero);
if (!config)
    return 0;

// Check if cached version matches
if (cached_version != config->policies_version) {
    // Re-read and cache
    cached_config = *config;  // <-- reads poisoned values
    cached_version = config->policies_version;
}
```
The version check is intended for the daemon's policy updates, but it also serves as an attacker's cache invalidation trigger. By bumping `policies_version` alongside the poison write, the attacker forces all CPUs to re-read the poisoned config.

**Tetragon** -- tail call lookup in exec event handler:
```c
bpf_tail_call(ctx, &execve_calls, 0);
// If tail call fails (entry deleted), execution continues here
return 0;  // Event silently dropped
```
The BPF tail call specification defines failure (missing entry, recursion limit) as a no-op: the tail call instruction is skipped and the next instruction executes. Tetragon's next instruction after the tail call is `return 0`, meaning a deleted prog_array entry causes silent event loss.

**Falco** -- syscall filter check in probe entry:
```c
// Simplified from Falco BPF probe
u8 *is_interesting = bpf_map_lookup_elem(&interesting_syscalls, &syscall_id);
if (!is_interesting || *is_interesting == 0)
    return 0;  // Skip this syscall entirely
```
The check treats 0 as "not interesting" with no fallback or validation. There is no mechanism to ensure the map was populated correctly or hasn't been modified.

### Impact

Once poisoned, the tools faithfully execute the attacker's intended behavior. The BPF programs are *correctly implementing* the poisoned configuration. This is not a crash or undefined behavior -- it is the programs doing exactly what the (modified) configuration tells them to do.

---

## Assumption 4: "Our BPF programs are tamper-proof because they are verified"

### The Assumption

There is a general security narrative that BPF programs are safe because the verifier ensures they cannot perform invalid memory accesses or escape the sandbox. This creates a false sense of security around the entire BPF subsystem.

### Why It Is Wrong

The verifier protects the *code* (BPF programs), not the *data* (BPF maps). This is analogous to having a read-only text segment but a writable data segment -- code integrity does not imply data integrity.

The BPF verification model:
- **Verified:** program bytecode (instructions), memory access patterns, helper call arguments, loop termination
- **Not verified:** map *contents*, map access control (beyond type checking), map value semantics, runtime data integrity

The verifier ensures a BPF program *can* read from `config_map` safely (no OOB access, correct value type). It does *not* ensure that the value read from `config_map` is the value the daemon intended. The verifier has no concept of "this map should only be written by process X" or "this field should never be zero."

### Code Evidence

The kernel's `map_update_elem()` implementation (kernel/bpf/syscall.c) performs capability checks and map-type validation but no ownership verification:

```c
// Simplified from kernel source
static int map_update_elem(union bpf_attr *attr)
{
    // ... capability check (CAP_BPF) ...
    // ... fd-to-map lookup ...
    // ... key/value size validation ...
    err = bpf_map_update_value(map, f, key, value, attr->flags);
    // No check: "is the calling process the map creator?"
    // No check: "is this value semantically valid?"
    return err;
}
```

### Impact

This assumption conflates code safety with system safety. Verified BPF code operating on poisoned data produces "safe" but incorrect results -- events are silently dropped, not because of a crash, but because the logic correctly evaluates the poisoned predicate as "do not process this event."

---

## Summary

| Assumption | Status | Root Cause |
|---|---|---|
| Maps are only writable by our daemon | **WRONG** | No ownership model in BPF subsystem |
| CAP_BPF is rare | **WRONG** | Common in post-exploitation, privileged containers |
| Config state is trustworthy once set | **WRONG** | Maps are shared mutable memory, no integrity checks |
| BPF programs are tamper-proof | **WRONG** | Verifier protects code, not data |

All four assumptions stem from a single design gap: **BPF-based security tools do not consider themselves as targets**. They are designed to monitor other processes but have no self-monitoring capability for their own runtime state.
