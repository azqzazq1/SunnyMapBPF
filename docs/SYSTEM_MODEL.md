# System Model

## 1. Components

A BPF-based runtime security tool consists of five core components:

### 1.1 Kernel BPF Subsystem

The kernel's BPF runtime environment provides:
- **Program loading and verification:** The verifier ensures memory safety, termination, and privilege checks before allowing program attachment.
- **Map management:** Kernel-resident key-value stores created via `bpf(BPF_MAP_CREATE)`. Maps persist as long as at least one file descriptor or pinned path references them.
- **Helper functions:** Kernel-provided functions callable from BPF programs (`bpf_map_lookup_elem`, `bpf_probe_read_kernel`, `bpf_perf_event_output`, etc.).
- **Attachment points:** Tracepoints, kprobes, fentry/fexit, LSM hooks, cgroup hooks, etc.

### 1.2 BPF Maps (Data Plane)

Maps serve as the shared state between BPF programs (kernel) and the userspace daemon. In security tools, maps fall into functional categories:

```
+------------------+------------------------------------------+------------------+
| Map Role         | Function                                 | Access Pattern   |
+------------------+------------------------------------------+------------------+
| Configuration    | Policy state, enabled features            | Read by BPF,     |
|                  | (config_map, interesting_syscalls)        | Write by daemon  |
+------------------+------------------------------------------+------------------+
| Process State    | Process tracking, ancestry                | Read/Write by    |
|                  | (execve_map, proc_info_map)               | BPF programs     |
+------------------+------------------------------------------+------------------+
| Tail Call Arrays | Program dispatch tables                   | Read by BPF,     |
|                  | (execve_calls, sys_*_calls)               | Write by daemon  |
+------------------+------------------------------------------+------------------+
| Event Buffers    | Event transport to userspace              | Write by BPF,    |
|                  | (perf buffers, ring buffers)              | Read by daemon   |
+------------------+------------------------------------------+------------------+
| Scratch/Heap     | Per-CPU temporary storage                 | Read/Write by    |
|                  | (heap, scratch maps)                      | BPF programs     |
+------------------+------------------------------------------+------------------+
```

### 1.3 BPF Programs (Kernel Logic)

Compiled BPF bytecode attached to kernel hooks. In security tools:
- **Entry programs** execute at tracepoints/kprobes, read configuration maps, and decide whether to process or skip the event.
- **Tail call targets** implement specific event processing stages, dispatched via PROG_ARRAY maps.
- **Filter logic** evaluates scope/policy predicates using configuration map values.

### 1.4 Userspace Daemon

The tool's user-space process (e.g., `tracee-ebpf`, `tetragon`, `falco`):
- Creates and initializes BPF maps
- Loads and attaches BPF programs
- Reads events from perf/ring buffers
- Applies userspace-side enrichment and alerting
- Manages policy configuration lifecycle

### 1.5 Event Pipeline

The end-to-end flow from kernel event to security alert:

```
Kernel Hook Trigger
       |
       v
BPF Program Entry
       |
       +---> Read config_map / interesting_syscalls
       |            |
       |      [value == 0?] ---YES---> return 0 (drop event)
       |            |
       |           NO
       |            |
       v            v
Tail Call Dispatch (PROG_ARRAY lookup)
       |
       +---> [entry missing?] ---YES---> return 0 (silent fail)
       |            |
       |           NO
       |            |
       v            v
Event Processing (read process state, collect args)
       |
       v
bpf_perf_event_output / bpf_ringbuf_submit
       |
       v
Userspace Daemon reads event
       |
       v
Policy evaluation + alert generation
```

## 2. Trust Boundaries

### 2.1 Kernel / Userspace Boundary

The traditional trust boundary. BPF programs execute in kernel context with verified memory safety. The userspace daemon runs with root or specific capabilities.

**Assumed property:** Only the kernel can execute BPF program logic; userspace can only interact via the `bpf()` syscall interface.

**Relevant to this work:** The `bpf()` syscall allows userspace processes to read and write BPF maps. The trust boundary permits map modification by *any* process with sufficient capabilities, not only the owning daemon.

### 2.2 BPF Program / BPF Map Boundary

BPF programs read map values and make control flow decisions based on them.

**Assumed property (by tool developers):** Map values are trustworthy because "we wrote them." BPF programs do not validate map contents beyond checking for null return from `bpf_map_lookup_elem`.

**Violated by this work:** Map values can be modified by external processes. A BPF program reading `config_map[0].enabled_policies == 0` cannot distinguish between "the daemon intentionally disabled all policies" and "an attacker zeroed this field."

### 2.3 Tool Daemon / External Process Boundary

The security tool daemon creates and manages BPF maps. External processes (including attacker-controlled processes) share the same kernel and can access the same BPF subsystem.

**Assumed property:** External processes lack the capability or knowledge to modify tool-internal maps.

**Violated by this work:** Post-exploitation, an attacker with `CAP_BPF` can:
1. Enumerate all maps via `bpf(BPF_MAP_GET_NEXT_ID)` and `bpf(BPF_MAP_GET_INFO_BY_FD)`
2. Identify target maps by name, type, and key/value sizes
3. Obtain file descriptors via `bpf(BPF_MAP_GET_FD_BY_ID)`
4. Read and write arbitrary map entries

For Tetragon, pinned maps at `/sys/fs/bpf/tetragon/` eliminate even the enumeration step.

### 2.4 Trust Boundary Diagram

```
+================================================================+
|                        KERNEL SPACE                             |
|                                                                 |
|  +------------------+    reads     +------------------------+   |
|  | BPF Programs     |<------------|  BPF Maps              |   |
|  | (verified,       |             |  (config, state,       |   |
|  |  immutable code) |             |   prog_arrays)         |   |
|  +--------+---------+             +----------+---+---------+   |
|           |                                  |   |              |
|           | events                     write |   | write        |
|           v                                  |   |              |
|  +------------------+                        |   |              |
|  | Perf/Ring Buffer |                        |   |              |
+==|==================|========================|===|==============+
   |     read          |                  bpf() |   | bpf()
   v                   |                 syscall|   | syscall
+------------------+   |              +---------+   +----------+
| Tool Daemon      |   |              |                        |
| (tracee/tetragon |<--+              |                        |
|  /falco)         |                  |                        |
| Creates maps,    |---> writes --->--+                        |
| loads programs   |                                           |
+------------------+                  +------------------------+
                                      | ATTACKER PROCESS       |
      USER SPACE                      | (CAP_BPF)             |
                                      | Enumerates maps,       |
                                      | writes poison values   |
                                      +------------------------+
```

The critical insight: the attacker process and the tool daemon use the *same kernel API* (`bpf()` syscall) to access maps. The kernel enforces capability checks but does not enforce ownership -- any process with `CAP_BPF` can write to any BPF map it can obtain an FD for.

## 3. Data Flow: Normal Operation vs. Poisoned State

### 3.1 Normal Operation (Tracee Example)

```
syscall tracepoint fires
    |
    v
BPF program reads config_map[0]
    |
    +---> policies_version matches cached? --YES--> use cached config
    |         |
    |        NO
    |         |
    |         v
    |     re-read config_entry_t from map
    |     update per-CPU cache
    |         |
    v         v
match_scope_filters(event, config)
    |
    +---> result = event_policies & config.enabled_policies
    |         |
    |     [result != 0?] --YES--> proceed to event collection
    |         |
    |        NO
    |         v
    |     return 0 (event filtered)
    v
event emitted to perf buffer -> daemon reads -> alert
```

### 3.2 Poisoned Operation (Tracee Example)

```
syscall tracepoint fires
    |
    v
BPF program reads config_map[0]
    |
    +---> policies_version matches cached? --NO (attacker bumped version)
              |
              v
          re-read config_entry_t from map
          cache now contains: enabled_policies = 0
              |
              v
match_scope_filters(event, config)
    |
    +---> result = event_policies & 0x0000000000000000
    |         |
    |     [result != 0?] --NO (always)
    |         |
    |         v
    |     return 0 (ALL events filtered)
    |
    (no events ever reach perf buffer)
    (daemon sees nothing)
    (no alerts generated)
```

### 3.3 Poisoned Operation (Tetragon Example)

```
sched_process_exec tracepoint fires
    |
    v
BPF entry program begins processing
    |
    +---> bpf_tail_call(ctx, execve_calls, 0)
              |
          [key 0 deleted from prog_array]
              |
              v
          tail call fails silently (BPF specification: no-op on failure)
              |
              v
          entry program returns 0
              |
          (no exec event emitted)

Meanwhile, for any sensor querying process context:

    sensor BPF program looks up execve_map[pid]
        |
        +---> bpf_map_lookup_elem returns NULL (entry deleted)
                  |
                  v
              sensor treats process as unknown, skips event
```

### 3.4 Poisoned Operation (Falco Example)

```
syscall raw_tracepoint fires (e.g., sys_enter for NR=59 execve)
    |
    v
BPF probe entry:
    val = bpf_map_lookup_elem(&interesting_syscalls, &syscall_nr)
    |
    +---> val != NULL && *val == 0  (attacker set it to 0)
              |
              v
          return 0 (syscall deemed "not interesting")
              |
          (no event processing occurs)
          (no data sent to userspace)
          (Falco sees no syscall activity)
```

## 4. Security Invariants Violated

BPF map poisoning violates the following security invariants that the tools implicitly depend on:

### Invariant 1: Configuration Integrity

**Statement:** The runtime configuration state in BPF maps reflects the intended policy set by the tool administrator.

**Violation:** An attacker modifies configuration maps to disable policies. The BPF programs faithfully execute the poisoned configuration. From the BPF program's perspective, the configuration is "valid" -- it simply says "monitor nothing."

### Invariant 2: Exclusive Map Ownership

**Statement:** BPF maps created by the security tool are only written by the tool's own processes.

**Violation:** The kernel's BPF subsystem enforces no ownership model. Map access is governed solely by capabilities (`CAP_BPF`), not by process identity. Any process with the required capability can obtain an FD to any map via `BPF_MAP_GET_FD_BY_ID`.

### Invariant 3: Pipeline Completeness

**Statement:** Every kernel event matching the tool's attachment points will be processed through the full event pipeline.

**Violation:** Deleting entries from PROG_ARRAY maps breaks tail call chains. The BPF specification mandates that failed tail calls are no-ops -- the calling program simply continues to the next instruction (typically a return). This is a feature for robustness but becomes an evasion vector when exploited.

### Invariant 4: Process State Consistency

**Statement:** The tool's process tracking state accurately reflects the set of running processes on the host.

**Violation:** Clearing `execve_map` entries removes process context without removing the actual processes. Sensors that depend on process context (file, network, etc.) cannot correlate events to processes and may drop them silently.

### Invariant 5: Self-Monitoring Capability

**Statement:** The security tool can detect tampering with its own state.

**Violation:** None of the three tools monitor their own BPF maps for unauthorized modifications. There is no watchdog, no periodic integrity check, no BPF LSM hook protecting against `bpf(BPF_MAP_UPDATE_ELEM)` calls from external processes. The attack is invisible to the tool being attacked.
