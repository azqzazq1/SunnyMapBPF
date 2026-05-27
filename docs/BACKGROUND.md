# Technical Background

## eBPF Subsystem, BPF Maps, and Security Tool Architectures

---

## 1. The eBPF Subsystem

### 1.1 Overview

Extended Berkeley Packet Filter (eBPF) is a Linux kernel subsystem that allows sandboxed programs to run inside the kernel without modifying kernel source code or loading kernel modules. Originally designed for network packet filtering (classic BPF, 1992), eBPF was introduced in Linux 3.18 (2014) and has since evolved into a general-purpose kernel programmability framework.

eBPF programs are written in a restricted C dialect, compiled to BPF bytecode, verified by an in-kernel static analyzer (the BPF verifier), and JIT-compiled to native machine code. The verifier enforces memory safety, bounded loops, and termination guarantees, ensuring that BPF programs cannot crash the kernel or access arbitrary memory.

### 1.2 Program Types Relevant to Security Monitoring

| Program Type | Attach Point | Used By |
|-------------|-------------|---------|
| `BPF_PROG_TYPE_TRACEPOINT` | Kernel tracepoints (`sys_enter_*`, `sys_exit_*`, `sched_process_exec`) | Tracee, Falco |
| `BPF_PROG_TYPE_KPROBE` | Arbitrary kernel functions | Tracee, Tetragon |
| `BPF_PROG_TYPE_RAW_TRACEPOINT` | Raw tracepoint (no argument parsing) | Tracee, Tetragon |
| `BPF_PROG_TYPE_LSM` | LSM hook points (`bprm_check_security`, `file_open`, etc.) | Tetragon (for enforcement) |
| `BPF_PROG_TYPE_PERF_EVENT` | Performance monitoring events | Falco (legacy) |

### 1.3 The `bpf()` System Call

All BPF operations are performed through a single multiplexed syscall:

```c
int bpf(int cmd, union bpf_attr *attr, unsigned int size);
```

Key commands relevant to this research:

| Command | Purpose | Required Capability |
|---------|---------|-------------------|
| `BPF_MAP_CREATE` | Create a new BPF map | `CAP_BPF` |
| `BPF_MAP_LOOKUP_ELEM` | Read a value from a map | `CAP_BPF` |
| `BPF_MAP_UPDATE_ELEM` | Write/overwrite a value in a map | `CAP_BPF` |
| `BPF_MAP_DELETE_ELEM` | Delete an entry from a map | `CAP_BPF` |
| `BPF_MAP_GET_NEXT_KEY` | Iterate over map keys | `CAP_BPF` |
| `BPF_MAP_GET_NEXT_ID` | Enumerate all maps on the system | `CAP_BPF` |
| `BPF_MAP_GET_FD_BY_ID` | Get a file descriptor for a map by ID | `CAP_BPF` |
| `BPF_MAP_FREEZE` | Make a map read-only from userspace | `CAP_BPF` |
| `BPF_OBJ_PIN` | Pin a map/program to `/sys/fs/bpf/` | `CAP_BPF` |
| `BPF_OBJ_GET` | Open a pinned map/program | `CAP_BPF` |

**Critical observation**: All map operations require only `CAP_BPF`. There is no per-map ownership, no ACL, and no distinction between "the process that created this map" and "any other process with `CAP_BPF`." This is by design -- BPF maps are intended to be shared between programs and between kernel and userspace.

---

## 2. BPF Maps

### 2.1 Overview

BPF maps are kernel-resident key-value data structures that serve as the primary mechanism for:
- **Configuration**: Passing parameters from userspace to BPF programs
- **State**: Maintaining runtime state across BPF program invocations
- **Communication**: Passing data between BPF programs (via shared maps) and between BPF programs and userspace (via map read/write or ring buffers)
- **Routing**: Directing program flow via tail calls (`BPF_MAP_TYPE_PROG_ARRAY`)

### 2.2 Map Types Relevant to This Research

| Map Type | Kernel Constant | Key Characteristics | Used By |
|----------|---------------|-------------------|---------|
| **Array** | `BPF_MAP_TYPE_ARRAY` | Fixed-size, integer-indexed, pre-allocated. Keys are 32-bit indices. Entries cannot be deleted (only zeroed). | Tracee (`config_map`), Falco (`interesting_syscalls`) |
| **Hash** | `BPF_MAP_TYPE_HASH` | Dynamic key-value store. Entries can be inserted, updated, and deleted. | Tetragon (`execve_map`) |
| **Prog Array** | `BPF_MAP_TYPE_PROG_ARRAY` | Special array where values are file descriptors to other BPF programs. Used with `bpf_tail_call()` for program chaining. If a key is deleted, the tail call silently fails (returns to caller). | Tetragon (`execve_calls`) |
| **Perf Event Array** | `BPF_MAP_TYPE_PERF_EVENT_ARRAY` | Per-CPU ring buffer for high-performance event delivery to userspace. | Tracee, Falco |
| **Ring Buffer** | `BPF_MAP_TYPE_RINGBUF` | Single shared ring buffer (kernel 5.8+), more efficient than perf event arrays. | Tracee (recent versions) |

### 2.3 Map Access Model

The BPF map access model has two distinct planes:

**Userspace access** (via `bpf()` syscall):
- Create: `BPF_MAP_CREATE` -- requires `CAP_BPF`
- Read: `BPF_MAP_LOOKUP_ELEM` -- requires `CAP_BPF`, returns a copy of the value
- Write: `BPF_MAP_UPDATE_ELEM` -- requires `CAP_BPF`, atomic update
- Delete: `BPF_MAP_DELETE_ELEM` -- requires `CAP_BPF`, only for hash/LRU types
- Iterate: `BPF_MAP_GET_NEXT_KEY` -- requires `CAP_BPF`
- No per-map permissions, no ownership, no ACLs

**BPF program access** (via helper functions):
- Read: `bpf_map_lookup_elem(map, &key)` -- returns a direct pointer to the value in kernel memory
- Write: `bpf_map_update_elem(map, &key, &value, flags)` -- atomic update
- Delete: `bpf_map_delete_elem(map, &key)` -- only for hash/LRU types
- Tail call: `bpf_tail_call(ctx, prog_array_map, index)` -- transfers execution to another BPF program

**The gap**: Userspace access control is coarse-grained (capability-based, not map-specific). Any process with `CAP_BPF` can modify any map on the system. The kernel does not track which process created a map or which processes "should" have access to it.

### 2.4 Map Enumeration

An attacker can enumerate all BPF maps on the system:

```c
// Pseudocode: enumerate all maps
__u32 id = 0;
while (bpf(BPF_MAP_GET_NEXT_ID, &id, sizeof(id)) == 0) {
    int fd = bpf(BPF_MAP_GET_FD_BY_ID, &id, sizeof(id));
    struct bpf_map_info info = {};
    bpf(BPF_OBJ_GET_INFO_BY_FD, &{fd, &info, sizeof(info)});
    // info.name, info.type, info.key_size, info.value_size, info.max_entries
}
```

This reveals the map name, type, key/value sizes, and maximum entry count -- sufficient to identify target maps by matching against known tool-specific names (`config_map`, `interesting_syscalls`, `execve_map`).

For pinned maps (Tetragon), enumeration is even simpler:

```bash
ls /sys/fs/bpf/tetragon/
# execve_map  tg_conf_map  ...
ls /sys/fs/bpf/tetragon/__base__/event_execve/
# execve_calls  ...
```

---

## 3. Map Hardening Mechanisms

### 3.1 `bpf_map_freeze()` (Kernel 5.2+, commit 87df15de441b)

```c
int bpf_map_freeze(int map_fd);
// Invoked via: bpf(BPF_MAP_FREEZE, &attr, sizeof(attr));
```

Freezes a map, making it permanently read-only from userspace. After freezing:
- `BPF_MAP_UPDATE_ELEM` returns `-EPERM`
- `BPF_MAP_DELETE_ELEM` returns `-EPERM`
- `BPF_MAP_LOOKUP_ELEM` continues to work
- BPF-program-side writes via `bpf_map_update_elem()` are **also blocked** if the map was created with `BPF_F_RDONLY_PROG`

Freezing is a **one-way operation**. A frozen map cannot be unfrozen. This makes it ideal for maps that are populated at initialization and never modified at runtime (e.g., Falco's `interesting_syscalls`, which is set once based on the loaded ruleset).

**Limitation**: Maps that require runtime updates from userspace (e.g., Tracee's `config_map`, which is updated when policies change) cannot be frozen without architectural changes.

**Implementation** (kernel source, `kernel/bpf/syscall.c`):

```c
static int map_freeze(const union bpf_attr *attr)
{
    // ...
    if (map->map_type == BPF_MAP_TYPE_STRUCT_OPS ||
        map_value_has_timer(map) ||
        map_value_has_kptrs(map))
        return -ENOTSUPP;
    // ...
    WRITE_ONCE(map->frozen, true);
    return 0;
}
```

### 3.2 `BPF_F_RDONLY_PROG` and `BPF_F_WRONLY_PROG` (Kernel 5.2+)

Map creation flags that restrict BPF-program-side access:

```c
struct bpf_map_def {
    // ...
    __u32 map_flags;  // BPF_F_RDONLY_PROG, BPF_F_WRONLY_PROG
};
```

- `BPF_F_RDONLY_PROG` (`1 << 7`): BPF programs can only read the map, not write to it. The verifier rejects programs that call `bpf_map_update_elem()` or `bpf_map_delete_elem()` on such maps.
- `BPF_F_WRONLY_PROG` (`1 << 8`): BPF programs can only write to the map, not read from it.

**Important**: These flags restrict **BPF-program-side** access only. They do **not** restrict userspace access via the `bpf()` syscall. `BPF_F_RDONLY_PROG` alone would not prevent the attacks described in this research. However, combined with `bpf_map_freeze()`, they provide defense in depth: freeze prevents userspace writes, and `BPF_F_RDONLY_PROG` prevents BPF-side writes from a compromised or malicious BPF program.

### 3.3 BPF Token (Kernel 6.9+, commit a86d1942e424)

BPF tokens are a delegation mechanism for unprivileged BPF operations:

```c
int bpf_token_create(int bpffs_fd, struct bpf_token_create_attr *attr);
```

A privileged process creates a token pinned to a BPF filesystem instance, specifying which BPF operations are allowed. Unprivileged processes can then use the token to perform those operations without full `CAP_BPF`.

**Current limitations**: BPF tokens do not yet support per-map access control. A token that grants `BPF_MAP_UPDATE_ELEM` permission grants it for all maps accessible from that BPF filesystem instance. Future kernel development may add map-level scoping, but as of kernel 6.12, this is not implemented.

**Relevance to this research**: BPF tokens are primarily designed for enabling unprivileged BPF in containers (e.g., allowing a non-root process to load a specific BPF program). They do not currently address the scenario where a `CAP_BPF` process modifies another tool's maps.

---

## 4. Security Tool Architectures

### 4.1 Falco (Sysdig / CNCF)

**Repository**: `falcosecurity/falco` (rules engine) + `falcosecurity/libs` (kernel instrumentation)

**Architecture**:

```
+-------------------+       +------------------+       +----------------+
| Falco Engine      |       | libscap/libsinsp |       | BPF Programs   |
| (Rule evaluation) | <---> | (Event capture)  | <---> | (Kernel probes)|
+-------------------+       +------------------+       +----------------+
                                    |                          |
                              Ring buffer                 BPF Maps
                             (perf/ringbuf)          (interesting_syscalls,
                                                      syscall_args, ...)
```

**Kernel-side flow**:
1. BPF programs are attached to raw tracepoints (`sys_enter`, `sys_exit`) or individual syscall tracepoints.
2. On each syscall, the BPF program checks `interesting_syscalls[NR]`. If the value is 0, the program returns immediately without processing.
3. If the syscall is "interesting," the program captures arguments, metadata, and context into a perf event buffer or ring buffer.
4. The userspace `libscap` library reads events from the buffer and passes them to `libsinsp` for parsing and enrichment.
5. The Falco engine evaluates rules against enriched events and generates alerts.

**Critical BPF maps**:

| Map Name | Type | Size | Purpose |
|----------|------|------|---------|
| `interesting_syscalls` | Array | 512 entries, 1 byte each | Kernel-side syscall filter. Entry `NR` is nonzero if syscall `NR` should be captured. |
| `syscall_args_map` | Array | Per-CPU | Scratch space for syscall argument capture |

**Code path** (from `falcosecurity/libs`, `driver/bpf/`):

```c
// Simplified from filler_helpers.h / bpf_probe.c
SEC("raw_tracepoint/sys_enter")
int sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    int id = bpf_syscall_get_nr(ctx);
    // Check if this syscall is interesting
    u8 *is_interesting = bpf_map_lookup_elem(&interesting_syscalls, &id);
    if (!is_interesting || *is_interesting == 0)
        return 0;  // <-- SKIP: not interesting
    // ... capture event ...
}
```

**Attack surface**: Setting `interesting_syscalls[NR] = 0` for all `NR` causes every probe to return at the first check. No events are generated. The map is not frozen, not pinned, and not monitored.

### 4.2 Tracee (Aqua Security)

**Repository**: `aquasecurity/tracee`

**Architecture**:

```
+-------------------+       +------------------+       +----------------+
| Tracee Engine     |       | eBPF Loader      |       | BPF Programs   |
| (Policy + output) | <---> | (libbpfgo)       | <---> | (tracee.bpf.c) |
+-------------------+       +------------------+       +----------------+
                                    |                          |
                              Ring buffer                 BPF Maps
                             (events ringbuf)       (config_map, proc_info_map,
                                                     events_map, ...)
```

**Kernel-side flow**:
1. BPF programs attach to tracepoints (`sys_enter_*`, `sys_exit_*`, `sched_process_exec`, etc.), kprobes, and LSM hooks.
2. On each event, the BPF program reads `config_map[0]` to obtain the current `config_entry_t` structure.
3. The `match_scope_filters()` function checks `config_entry.enabled_policies` (a 64-bit bitmask). If no policy bit is set, the function returns 0 and the event is discarded.
4. The `policies_version` field acts as a generation counter. BPF programs cache the config locally; when `policies_version` changes, they re-read `config_map` to pick up the new values.
5. Events that pass scope filtering are written to the events ring buffer for userspace consumption.

**Critical BPF maps**:

| Map Name | Type | Key | Value | Purpose |
|----------|------|-----|-------|---------|
| `config_map` | Array | `u32` (index 0) | `config_entry_t` (~280 bytes) | Global config: `tracee_pid`, `policies_version`, `enabled_policies`, filter configs |
| `proc_info_map` | Hash | `u32` (PID) | `proc_info_t` | Process metadata cache |
| `events_map` | Array | `u32` (event ID) | `event_config_t` | Per-event configuration (which policies subscribe) |

**Key structure** (`pkg/ebpf/c/types.h`):

```c
typedef struct config_entry {
    u32 tracee_pid;           // offset 0
    // ... various fields ...
    u16 policies_version;     // offset 14
    // ... padding, filter configs ...
    u64 enabled_policies;     // offset 216
    // ... remainder ...
} config_entry_t;
```

**Code path** (`pkg/ebpf/c/tracee.bpf.c`):

```c
static __always_inline u64 match_scope_filters(event_config_t *event_cfg, ...) {
    config_entry_t *config = bpf_map_lookup_elem(&config_map, &zero);
    if (!config)
        return 0;
    u64 policies = config->enabled_policies;
    if (policies == 0)
        return 0;  // <-- No policies enabled, discard everything
    // ... per-policy scope checks ...
}
```

**Attack surface**: Writing `enabled_policies = 0` at offset 216 and bumping `policies_version` at offset 14 forces all BPF programs to re-read the config and immediately discard all events. Two fields, one map update, total blindness.

### 4.3 Tetragon (Cilium / Isovalent)

**Repository**: `cilium/tetragon`

**Architecture**:

```
+-------------------+       +------------------+       +--------------------+
| Tetragon Agent    |       | BPF Loader       |       | BPF Programs       |
| (gRPC + export)   | <---> | (sensors pkg)    | <---> | (bpf/process/*.c)  |
+-------------------+       +------------------+       +--------------------+
                                    |                          |
                            Perf buffers              BPF Maps (pinned)
                          (tcpmon_map, etc.)      /sys/fs/bpf/tetragon/
                                                  (execve_map, execve_calls,
                                                   tg_conf_map, ...)
```

**Kernel-side flow**:
1. BPF programs attach to tracepoints (`sys_enter_execve`, `sched_process_exec`) and kprobes.
2. The `event_execve` program is the entry point for exec events. It uses `bpf_tail_call()` with the `execve_calls` prog_array to dispatch to sub-handler programs.
3. Sub-handlers look up process information in `execve_map` (a hash map keyed by PID) to correlate events with process context (parent PID, binary path, capabilities, namespaces).
4. Events are written to per-CPU perf buffers for userspace consumption.
5. The Tetragon agent reads events via perf buffer polling and exports them via gRPC.

**Critical BPF maps**:

| Map Name | Type | Pinned Path | Purpose |
|----------|------|-------------|---------|
| `execve_map` | Hash | `/sys/fs/bpf/tetragon/execve_map` | Process tracking: PID to `execve_map_value` (binary, args, parent, creds) |
| `execve_calls` | Prog Array | `/sys/fs/bpf/tetragon/__base__/event_execve/execve_calls` | Tail call routing for exec event sub-handlers |
| `tg_conf_map` | Array | `/sys/fs/bpf/tetragon/tg_conf_map` | Tetragon global configuration |
| `tcpmon_map` | Perf Event Array | `/sys/fs/bpf/tetragon/tcpmon_map` | Event delivery to userspace |

**Pinned map architecture**: Tetragon pins all maps to `/sys/fs/bpf/tetragon/`. This is a design choice for operational convenience -- maps persist across agent restarts, enabling seamless upgrades. However, pinning also makes maps discoverable by pathname, eliminating the need for `BPF_MAP_GET_NEXT_ID` enumeration.

**Code path** (`bpf/process/bpf_execve_event.c`):

```c
SEC("tracepoint/sys_enter_execve")
int event_execve(struct sys_enter_args *ctx) {
    struct execve_map_value *enter;
    // ... setup ...
    bpf_tail_call(ctx, &execve_calls, 0);
    // If tail call fails (entry deleted), execution falls through here
    // and returns with no event generated
    return 0;
}
```

**Attack surface -- dual vector**:

1. **`execve_calls` deletion**: Deleting entries from the prog_array causes `bpf_tail_call()` to silently return. The BPF runtime does not generate an error or alert when a tail call target is missing; execution simply continues at the instruction after `bpf_tail_call()`, which typically returns 0. This breaks the entire exec event pipeline.

2. **`execve_map` clearing**: Deleting all entries from the process tracking hash map means that even if some events are still generated (e.g., via paths that don't use `execve_calls`), they cannot be correlated with process metadata. All processes appear as unknown/untracked.

Combined, these two attacks achieve total Tetragon blindness: zero events of any type during the test window.

---

## 5. How Each Tool Uses BPF Maps for Runtime State

### 5.1 Configuration Maps

| Tool | Map | Update Pattern | Frozen? |
|------|-----|---------------|---------|
| Tracee | `config_map` | Updated by userspace on policy changes (version bump + new `enabled_policies`) | No |
| Tetragon | `tg_conf_map` | Set at initialization; rarely updated at runtime | No |
| Falco | `interesting_syscalls` | Set at initialization based on loaded ruleset; static during runtime | No |

**Observation**: Falco's `interesting_syscalls` is the strongest candidate for `bpf_map_freeze()` -- it is set once and never modified during normal operation. Tracee's `config_map` requires runtime updates, making freezing more complex (would require map splitting). Tetragon's `tg_conf_map` is also a strong freeze candidate.

### 5.2 State Maps

| Tool | Map | Purpose | Entries |
|------|-----|---------|---------|
| Tracee | `proc_info_map` | Process metadata cache | Dynamic (hash) |
| Tetragon | `execve_map` | Process tracking (PID to context) | Dynamic (hash) |
| Falco | (handled in userspace) | Falco does process tracking in libsinsp, not BPF maps | N/A |

State maps are inherently mutable and cannot be frozen. Protection requires runtime integrity verification or access control mechanisms that the kernel does not currently provide.

### 5.3 Routing Maps (Prog Arrays)

| Tool | Map | Entries | Tail Call Failure Mode |
|------|-----|---------|----------------------|
| Tetragon | `execve_calls` | 2-4 entries (sub-handler programs) | Silent: `bpf_tail_call()` returns, caller proceeds with no event |
| Tracee | `prog_array` (various) | Multiple entries for event-specific handlers | Silent: same failure mode |

Prog arrays are particularly dangerous because tail call failure is **silent by design** in the BPF runtime. The `bpf_tail_call()` helper is defined to fall through if the target index is empty or the program is invalid. This is intentional (it enables optional/conditional tail calls), but it means that deleting a prog_array entry silently disables the corresponding code path with no error or log.

### 5.4 Event Delivery Maps

| Tool | Map | Type |
|------|-----|------|
| Tracee | `events` | Ring buffer (`BPF_MAP_TYPE_RINGBUF`) |
| Tetragon | `tcpmon_map` | Perf event array (`BPF_MAP_TYPE_PERF_EVENT_ARRAY`) |
| Falco | `perf_map` | Perf event array |

Event delivery maps are less useful as poisoning targets because they are output channels, not control channels. Disrupting them (e.g., filling the ring buffer) would cause event loss but might be detected by userspace as buffer overflow errors. The more effective attack targets the control maps that determine whether events are generated in the first place.

---

## 6. Summary: The Hardening Gap

The following table summarizes the available kernel hardening mechanisms and their adoption:

| Mechanism | Available Since | Tracee | Tetragon | Falco | Effect |
|-----------|----------------|--------|----------|-------|--------|
| `bpf_map_freeze()` | 5.2 (2019) | Not used | Not used | Not used | Prevents userspace writes post-freeze |
| `BPF_F_RDONLY_PROG` | 5.2 (2019) | Not used on critical maps | Not used on critical maps | Not used on critical maps | Prevents BPF-side writes |
| Map pinning ACLs | N/A | N/A | No filesystem ACLs on pinned maps | N/A | Could restrict `/sys/fs/bpf/` access |
| BPF token scoping | 6.9 (2024) | Not adopted | Not adopted | Not adopted | Per-token operation restrictions |
| Runtime integrity checks | Tool-level | Not implemented | Not implemented | Not implemented | Userspace verification of map state |
| `bpf()` audit rules | auditd | Not configured by default | Not configured by default | Not configured by default | Audit trail for BPF syscalls |

Every cell in the "used/implemented" columns is negative. The hardening mechanisms exist in the kernel; they have existed for years (`bpf_map_freeze()` since 2019); and none of the three major eBPF security tools use them on their security-critical maps. This is the foundational gap that BPF map poisoning exploits.
