# 4. Attack Design

## 4.1 Map Inventory Methodology

The first phase of the attack is identifying which BPF maps belong to the target security tool and which maps, when modified, will produce the desired evasion effect. We developed a systematic methodology for map inventory and triage.

**Step 1: Map enumeration.** Using `bpf(BPF_MAP_GET_NEXT_ID)`, we enumerate all BPF map IDs on the system. For each ID, `bpf(BPF_MAP_GET_FD_BY_ID)` obtains a file descriptor, and `bpf(BPF_OBJ_GET_INFO_BY_FD)` retrieves metadata: name, type, key size, value size, max\_entries, map flags, and the IDs of BPF programs that reference the map.

**Step 2: Tool attribution.** Maps are attributed to a security tool by correlating program IDs referenced in map metadata with the known program names or attach points of the target tool. For Tetragon, attribution is trivial: all maps are pinned under `/sys/fs/bpf/tetragon/`. For Tracee, the `config_map` name is unique and stable. For Falco, `interesting_syscalls` (or its truncated variant `interesting_sys` due to the 16-character BPF map name limit) is identifiable by name, type (`array`), and entry count (512).

**Step 3: Semantic classification.** Each map is classified by its role in the tool's architecture:
- *Configuration maps*: contain tool settings, policy definitions, feature flags
- *State maps*: contain runtime state such as process tracking tables, connection tables
- *Routing maps*: contain prog\_array entries for tail call dispatch
- *Output maps*: perf buffers, ring buffers for event emission
- *Filter maps*: contain per-event or per-syscall filtering decisions

**Step 4: Impact assessment.** For each map, we analyze the effect of modification on the tool's event pipeline by tracing the BPF program code paths that read the map. The critical question is: *does a specific map modification cause the BPF program to exit early (before emitting an event) on a code path that is reached for all events?*

## 4.2 Attack Primitive Taxonomy

We identify five distinct attack primitives achievable through BPF map poisoning. Each corresponds to a different semantic effect on the security tool's monitoring capability.

### 4.2.1 P1: Total Blindness (Policy Disablement)

Modify a configuration map to disable all monitoring policies. The BPF program continues to execute on every kernel event but evaluates to "no policy matches" and exits without emitting output.

*Applicable to:* Tracee (`config_map.enabled_policies = 0`)

*Mechanism:* The `match_scope_filters()` function in Tracee's BPF code iterates over enabled policies using the `enabled_policies` bitmask. When this bitmask is zero, the loop body never executes, and the function returns 0 (no match) for every event. Combined with a `policies_version` bump, this takes effect immediately by invalidating all cached policy state in the BPF programs.

### 4.2.2 P2: Pipeline Breakage (Tail Call Destruction)

Delete entries from a `PROG_ARRAY` map to break the tail call chain that composes the event processing pipeline. The initial BPF program executes but cannot dispatch to subsequent processing stages.

*Applicable to:* Tetragon (`execve_calls` prog\_array)

*Mechanism:* Tetragon's `sched_process_exec` handler calls `bpf_tail_call(ctx, &execve_calls, 0)` to dispatch to the exec event processing sub-program. When this entry is deleted, `bpf_tail_call()` silently returns (per kernel documentation: the helper "has no effect" on failure), and execution falls through. The exec event is never fully processed and never emitted to the ring buffer. This is architecturally significant because `bpf_tail_call()` was designed for extensibility, not reliability -- its failure mode is silent continuation, which the tool's code does not handle as an error condition.

### 4.2.3 P3: Process Invisibility (State Table Erasure)

Delete entries from a process tracking hash map, causing the tool to lose awareness of running processes. Subsequent events from those processes are discarded because the tool cannot associate them with a known process context.

*Applicable to:* Tetragon (`execve_map`)

*Mechanism:* Every Tetragon sensor performs `bpf_map_lookup_elem(&execve_map, &pid)` to retrieve process context (binary path, cgroup, namespace, parent process). When the lookup returns NULL, the sensor cannot construct a complete event and discards it. Clearing `execve_map` makes all processes invisible to all sensors simultaneously. New process executions after the clear are also invisible because the exec event handler itself depends on `execve_calls` (already broken by P2) to populate `execve_map`.

### 4.2.4 P4: Syscall Filter Suppression

Zero out a per-syscall filter array, causing the BPF program to skip processing for all syscall numbers.

*Applicable to:* Falco (`interesting_syscalls`)

*Mechanism:* Falco's BPF probe performs an array lookup at the current syscall number index. If the value is 0 (not interesting), the program returns immediately. Setting all 512 entries to 0 causes every syscall event to be dropped at the earliest possible point in the BPF program, before any data is copied or any event is constructed. This is the most efficient suppression because it eliminates per-event processing overhead entirely.

### 4.2.5 P5: Container Exemption (Selective Suppression)

Modify policy maps or container tracking maps to exempt specific containers or cgroups from monitoring while leaving monitoring of other containers intact.

*Applicable to:* Tracee (per-policy cgroup filtering), Tetragon (per-namespace policy maps)

*Mechanism:* Not fully implemented in our PoCs but architecturally feasible. Tracee's policy engine supports per-container scope filters stored in BPF maps. An attacker could modify these filters to exempt their own container from all policies. This primitive is more subtle than total blindness (P1) and harder to detect through external monitoring.

## 4.3 Per-Tool Attack Vectors

### 4.3.1 Tracee v0.24.1: `config_map` Poisoning

**Target map:** `config_map` (BPF\_MAP\_TYPE\_ARRAY, 1 entry, 256-byte value)

**Attack steps:**
1. Enumerate maps via `bpf(BPF_MAP_GET_NEXT_ID)`, identify `config_map` by name and type
2. Read current value via `bpf(BPF_MAP_LOOKUP_ELEM)` with key 0
3. Parse `config_entry_t`: extract `policies_version` (u16 at offset 14) and `enabled_policies` (u64 at offset 216)
4. Construct poisoned value: zero bytes 216-223 (`enabled_policies = 0`), increment bytes 14-15 (`policies_version += 1`)
5. Write poisoned value via `bpf(BPF_MAP_UPDATE_ELEM)` with key 0

**Why version bumping is necessary:** Tracee's BPF programs cache the `policies_version` value in a per-CPU variable. When processing an event, the program compares the cached version against the map version. If they match, the program uses cached policy state (which still has the old, non-zero `enabled_policies`). By incrementing `policies_version`, we force all BPF program instances to re-read the configuration on their next invocation, picking up the zeroed `enabled_policies` value.

**Code path affected:** In `pkg/ebpf/c/tracee.bpf.c`, the `match_scope_filters()` function is called from every event handler. The function's first operation is reading `enabled_policies` from `config_map`. When `enabled_policies == 0`, the policy iteration loop `for (int i = 0; i < MAX_POLICIES; i++) { if (!(enabled_policies & (1 << i))) continue; ... }` never executes, and the function returns 0. The calling event handler interprets 0 as "no policy matched" and drops the event.

### 4.3.2 Tetragon v1.4.0: Dual-Vector Pipeline Destruction

**Target maps:**
- `execve_calls` (BPF\_MAP\_TYPE\_PROG\_ARRAY, 2 entries, pinned at `/sys/fs/bpf/tetragon/__base__/event_execve/execve_calls`)
- `execve_map` (BPF\_MAP\_TYPE\_HASH, keyed by PID, pinned at `/sys/fs/bpf/tetragon/execve_map`)

**Attack steps (Vector 1 -- pipeline breakage):**
1. Access `execve_calls` via pinned path: `bpf(BPF_OBJ_GET, "/sys/fs/bpf/tetragon/__base__/event_execve/execve_calls")`
2. Delete entry at key 0: `bpf(BPF_MAP_DELETE_ELEM)` with key `0x00000000`
3. Delete entry at key 1: `bpf(BPF_MAP_DELETE_ELEM)` with key `0x01000000`

**Attack steps (Vector 2 -- state erasure):**
1. Access `execve_map` via pinned path: `bpf(BPF_OBJ_GET, "/sys/fs/bpf/tetragon/execve_map")`
2. Enumerate all keys via `bpf(BPF_MAP_GET_NEXT_KEY)`
3. Delete each entry via `bpf(BPF_MAP_DELETE_ELEM)`

**Combined effect:** Vector 1 prevents new exec events from being processed. Vector 2 erases all existing process context, causing all other sensors (file, network, syscall) to lose process association for already-running processes. The combination achieves total blindness: no events of any type are emitted.

**Code path affected:** In `bpf/process/bpf_execve_event.c`, the `sched_process_exec` tracepoint handler calls `bpf_tail_call(ctx, &execve_calls, 0)`. After the tail call fails (entry deleted), execution continues past the `bpf_tail_call` invocation. The code after the tail call is the error/fallthrough path, which does not emit a process exec event. For other sensors, the `__get_current_task_exec()` function lookups `execve_map` by current PID; a NULL return causes early exit.

### 4.3.3 Falco (Latest): `interesting_syscalls` Zeroing

**Target map:** `interesting_syscalls` (BPF\_MAP\_TYPE\_ARRAY, 512 entries, 1-byte values)

**Attack steps:**
1. Enumerate maps via `bpf(BPF_MAP_GET_NEXT_ID)`, identify by name fragment `interesting_sys` and array type with 512 entries
2. For each key from 0 to 511: `bpf(BPF_MAP_UPDATE_ELEM)` with value `0x00`

**Code path affected:** In `driver/bpf/fillers.h` and the syscall entry/exit tracepoint handlers in falcosecurity/libs, the first operation after basic context setup is:

```c
u8 *is_interesting = bpf_map_lookup_elem(&interesting_syscalls, &id);
if (!is_interesting || !*is_interesting)
    return 0;
```

When all entries are 0, this check causes immediate return for every syscall, preventing any event from reaching the ring buffer. The map is populated once by `libscap` at Falco startup and never refreshed during runtime.

## 4.4 Cross-Tool Generalization

The three attacks share a common structure that generalizes to any eBPF-based security tool:

1. **Map discovery** via the BPF enumeration API or pinned filesystem paths
2. **Map identification** via stable names, types, and entry counts
3. **Semantic understanding** of which map fields control event emission
4. **Atomic modification** via standard `bpf(2)` syscall operations
5. **Silent effect** due to the tools' lack of integrity verification

The attack surface is inherent to the eBPF architecture: BPF maps are designed as shared state with a flat access model. Any tool that stores security-critical decisions in BPF maps without applying protection mechanisms is vulnerable. The specific map names and struct layouts are tool-dependent, but the methodology is uniform.
