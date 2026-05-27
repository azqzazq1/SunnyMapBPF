# 2. Background

## 2.1 eBPF Architecture

The extended Berkeley Packet Filter (eBPF) is an in-kernel virtual machine that allows user-defined programs to execute safely at designated kernel attach points. The architecture comprises four principal components.

**Programs.** eBPF programs are sequences of BPF bytecode instructions loaded into the kernel via the `bpf(BPF_PROG_LOAD)` syscall. Each program has a defined type (e.g., `BPF_PROG_TYPE_TRACEPOINT`, `BPF_PROG_TYPE_KPROBE`, `BPF_PROG_TYPE_LSM`) that constrains its available attach points and helper function set. Programs execute in response to kernel events at their attach points and may read kernel data structures, call BPF helper functions, and access BPF maps.

**Verifier.** Before a program is loaded, the BPF verifier performs static analysis to ensure safety: bounded loops, no out-of-bounds memory access, no uninitialized register use, no unreachable instructions, and type-safe map access. The verifier guarantees that a loaded program cannot crash the kernel or access arbitrary kernel memory. Critically, the verifier operates *only at load time* -- it does not constrain runtime map contents.

**JIT Compiler.** Verified programs are compiled from BPF bytecode to native machine code by the architecture-specific JIT compiler. JIT compilation is mandatory on modern kernels (since 5.x defaults) and provides near-native execution performance.

**Maps.** BPF maps are kernel-resident key-value data structures that serve as the primary mechanism for (a) communication between BPF programs and userspace, (b) shared state between multiple BPF programs, and (c) persistent configuration storage. Maps are created via `bpf(BPF_MAP_CREATE)` and accessed from userspace via `bpf(BPF_MAP_LOOKUP_ELEM)`, `bpf(BPF_MAP_UPDATE_ELEM)`, and `bpf(BPF_MAP_DELETE_ELEM)`. From BPF program context, maps are accessed via helper functions `bpf_map_lookup_elem()`, `bpf_map_update_elem()`, and `bpf_map_delete_elem()`.

## 2.2 BPF Map Types Relevant to Security Tools

Four map types are central to the architectures of the security tools analyzed in this paper.

**BPF_MAP_TYPE_ARRAY.** Fixed-size array indexed by integer key (0 to `max_entries - 1`). Entries cannot be deleted; they are always present and initialized to zero. Array maps provide O(1) lookup and are used for configuration storage (e.g., Tracee's `config_map`) and syscall filtering (e.g., Falco's `interesting_syscalls`). The fixed-key property means an attacker always knows valid keys without enumeration.

**BPF_MAP_TYPE_HASH.** Hash table mapping arbitrary keys to values. Entries are dynamically inserted and deleted. Used for process tracking (e.g., Tetragon's `execve_map`, keyed by PID). An attacker must enumerate existing keys via `BPF_MAP_GET_NEXT_KEY` to discover entries, but can then delete them individually.

**BPF_MAP_TYPE_PROG_ARRAY.** A special array map whose values are file descriptors to other BPF programs. Used with the `bpf_tail_call()` helper to implement dynamic dispatch: a BPF program can transfer execution to another program indexed in the prog\_array. If the referenced index is empty or the entry has been deleted, the tail call silently fails and execution continues in the calling program. This silent-failure semantic is critical to the Tetragon attack: deleting prog\_array entries does not cause errors or crashes, but silently disables the entire tail-call-based event processing pipeline.

**BPF_MAP_TYPE_HASH_OF_MAPS.** A hash table where each value is a file descriptor to another BPF map. Used by tools that dynamically associate per-entity (per-container, per-policy) map instances. Not directly targeted in the attacks presented here but represents an additional attack surface.

## 2.3 Map Access Model and Capabilities

BPF map access from userspace is governed by Linux capabilities, not by a per-map ownership or access control model.

**Capability requirements.** Since kernel 5.8, the `CAP_BPF` capability (separated from `CAP_SYS_ADMIN`) is sufficient to perform all map operations: creation, lookup, update, deletion, and enumeration. The `CAP_SYS_ADMIN` capability also grants these permissions as a superset. No finer-grained access control exists: there is no concept of map ownership, no per-map permission bits, and no namespace-scoped isolation of map access (BPF maps exist in a single global namespace, though BPF token scoping was introduced in kernel 6.9).

**Enumeration.** The `bpf(BPF_MAP_GET_NEXT_ID)` syscall allows sequential enumeration of all BPF map IDs on the system. Combined with `bpf(BPF_OBJ_GET_INFO_BY_FD)` after `bpf(BPF_MAP_GET_FD_BY_ID)`, this reveals each map's name, type, key/value sizes, max\_entries, and associated program IDs. This provides an attacker with a complete inventory of all BPF maps, including those belonging to security tools.

**Cross-program access.** Given a map ID obtained via enumeration, `bpf(BPF_MAP_GET_FD_BY_ID)` returns a file descriptor that provides full read/write access to the map. There is no check that the calling process created the map or is associated with any BPF program that references it. Any process with `CAP_BPF` can write to any BPF map on the system.

**Pinned maps.** Maps can be pinned to the BPF filesystem (typically mounted at `/sys/fs/bpf/`) via `bpf(BPF_OBJ_PIN)`. Pinned maps are accessible via `bpf(BPF_OBJ_GET)` using the filesystem path, bypassing the need for ID enumeration entirely. Tetragon pins all its maps to `/sys/fs/bpf/tetragon/`, providing stable, predictable paths for an attacker.

## 2.4 Available Protection Mechanisms

The kernel provides several mechanisms that *could* protect map contents, but which are not employed by the tools we analyzed.

**`bpf_map_freeze()`.** Introduced in kernel 5.2 (commit `87df15de441`) , the `bpf(BPF_MAP_FREEZE)` syscall marks a map as frozen, making it read-only from userspace. After freezing, `BPF_MAP_UPDATE_ELEM` and `BPF_MAP_DELETE_ELEM` return `-EPERM`. BPF programs can still write to frozen maps. This is the most direct mitigation for map poisoning but requires that the map's contents are fully determined at freeze time -- maps that require ongoing userspace updates (e.g., dynamic policy changes) cannot be frozen without architectural changes.

**`BPF_F_RDONLY_PROG` and `BPF_F_WRONLY_PROG`.** Map creation flags that restrict BPF program access to read-only or write-only. These do *not* restrict userspace access -- they constrain the BPF program side. `BPF_F_RDONLY_PROG` prevents BPF programs from writing to the map; `BPF_F_WRONLY_PROG` prevents BPF programs from reading. These flags are orthogonal to the poisoning attack, which operates from userspace, but could be combined with `bpf_map_freeze()` for defense-in-depth.

**BPF token (kernel 6.9+).** BPF token scoping, introduced in kernel 6.9, allows delegating BPF operations to specific processes with fine-grained permissions. This mechanism could theoretically scope map access to authorized processes, but its integration into security tool architectures has not been demonstrated.

**Seccomp BPF.** Processes can restrict their own ability to invoke the `bpf(2)` syscall via seccomp filters. This is a defensive measure for *non-BPF processes* to prevent exploitation, not a mechanism for BPF tools to protect their maps from other BPF-capable processes.

## 2.5 Security Tool Architectures

### 2.5.1 Tracee (Aqua Security)

Tracee attaches BPF programs to kernel tracepoints and kprobes to detect security-relevant events. Its kernel-side filtering architecture centers on `config_map`, a `BPF_MAP_TYPE_ARRAY` with a single entry (key 0) containing a `config_entry_t` struct (256 bytes in v0.24.1).

The struct layout includes `tracee_pid` (u32, offset 0), `options` (u32, offset 4), `cgroup_v1_hid` (u32, offset 8), `padding` (u16, offset 12), `policies_version` (u16, offset 14), and `enabled_policies` (u64, offset 216). The `match_scope_filters()` function, called on every event, checks `enabled_policies`: if the bitmask is zero, no policy matches any event, and the function returns 0, causing the BPF program to drop the event before it reaches the perf buffer.

The `policies_version` field implements a caching optimization: BPF programs cache the current version and only re-read configuration when the version changes. An attacker must bump this field alongside zeroing `enabled_policies` to ensure the poisoned value takes effect immediately rather than being masked by cached state.

### 2.5.2 Tetragon (Cilium/Isovalent)

Tetragon implements process lifecycle tracking and policy enforcement through a set of BPF programs connected via tail calls and sharing state through pinned maps.

All maps are pinned to `/sys/fs/bpf/tetragon/`, making them directly accessible without enumeration. Two maps are critical:

`execve_calls` (`BPF_MAP_TYPE_PROG_ARRAY`, 2 entries, pinned at `/sys/fs/bpf/tetragon/__base__/event_execve/execve_calls`) contains tail call targets for the `sched_process_exec` tracepoint handler. The main handler dispatches to sub-programs for argument parsing, cgroup association, and event emission via `bpf_tail_call(ctx, &execve_calls, index)`. Deleting entries causes `bpf_tail_call()` to silently return (documented kernel behavior: "If the call fails, the helper has no effect and the caller continues to execute the rest of the eBPF program"), leaving the event partially processed and never emitted.

`execve_map` (`BPF_MAP_TYPE_HASH`, keyed by PID) tracks all executing processes. Every sensor (file, network, syscall) lookups the calling process in `execve_map` to associate events with process context. Clearing this map makes all processes invisible to all Tetragon sensors, as lookups return NULL and events are discarded for lack of process context.

### 2.5.3 Falco (Sysdig/CNCF)

Falco's BPF driver (`driver/bpf/` in falcosecurity/libs) gates all syscall event processing on the `interesting_syscalls` array. This is a `BPF_MAP_TYPE_ARRAY` with 512 entries (one per possible syscall number on x86\_64), where each entry is a single byte: 1 if the syscall should be traced, 0 if it should be skipped.

At every syscall entry/exit tracepoint, the BPF program performs:

```c
u8 *is_interesting = bpf_map_lookup_elem(&interesting_syscalls, &id);
if (!is_interesting || !*is_interesting)
    return 0;
```

If the lookup returns 0, the program exits immediately -- no event is generated, no data is copied to the ring buffer, and no signal reaches the Falco userspace engine. The `interesting_syscalls` map is populated by `libscap` during initialization based on the loaded ruleset. It is not repopulated during runtime unless Falco is restarted.

The map is not pinned to the BPF filesystem but is discoverable via `bpf(BPF_MAP_GET_NEXT_ID)` enumeration, identifiable by its name (`interesting_syscalls` or a truncated variant) and type (`array` with 512 entries and 1-byte values).
