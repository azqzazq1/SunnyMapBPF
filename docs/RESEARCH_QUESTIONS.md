# Research Questions

## BPF Map Poisoning: Cross-Tool Evasion of eBPF-Based Security Monitors

---

### RQ1: Can an attacker with `CAP_BPF` modify the BPF maps of a co-located eBPF security tool without cooperation from that tool?

**Answer: Yes.** The Linux kernel's BPF subsystem enforces capability checks (`CAP_BPF`) at syscall entry but does not implement per-map ownership or access control. Any process with `CAP_BPF` can enumerate all maps on the host via `bpf(BPF_MAP_GET_NEXT_ID)`, obtain file descriptors via `bpf(BPF_MAP_GET_FD_BY_ID)`, and read/write/delete entries via `BPF_MAP_LOOKUP_ELEM`, `BPF_MAP_UPDATE_ELEM`, and `BPF_MAP_DELETE_ELEM`. For tools that pin maps to `/sys/fs/bpf/` (Tetragon), access is even simpler: `bpf(BPF_OBJ_GET)` on the pinned path. No tool-specific knowledge is needed beyond the map name and value layout, both of which can be determined from public source code or runtime inspection via `bpftool map dump`.

---

### RQ2: Does BPF map modification achieve measurable evasion against production eBPF security tools?

**Answer: Yes -- complete evasion (100% event suppression) against all three tested tools.** We empirically verified the following results:

| Tool | Version | Baseline Events | Post-Poison Events | Suppression |
|------|---------|----------------|--------------------| ------------|
| Tracee | v0.24.1 | 16 | 0 | 100% |
| Tetragon | v1.4.0 | 14+ | 0 | 100% |
| Falco | latest | 1+ | 0 | 100% |

Each test followed a controlled five-phase protocol: deploy tool, establish baseline detection, poison maps, re-run identical activity, verify zero events. The identical activity workload (process execution, file reads, user enumeration) was used in both baseline and poisoned phases to ensure comparability.

---

### RQ3: What specific BPF map structures are critical to each tool's event pipeline, and what is the minimum modification required to achieve evasion?

**Answer:** Each tool has a small number of maps whose modification causes total blindness:

**Tracee** -- `config_map` (BPF array, key 0):
- `enabled_policies` field at byte offset 216 in `config_entry_t` (8 bytes, bitmask of active policies)
- `policies_version` field at byte offset 14 (2 bytes, cache invalidation counter)
- Setting `enabled_policies=0` and incrementing `policies_version` causes `match_scope_filters()` in `tracee.bpf.c` to return 0 for all events, as no policy bit is set. The version bump forces all BPF programs to re-read the config on their next invocation.
- **Minimum modification**: 10 bytes (8 bytes for `enabled_policies`, 2 bytes for `policies_version`).

**Tetragon** -- `execve_calls` (BPF prog_array, pinned) + `execve_map` (BPF hash, pinned):
- `execve_calls` at `/sys/fs/bpf/tetragon/__base__/event_execve/execve_calls` routes the `event_execve` BPF program to sub-handlers via `bpf_tail_call()`. Deleting entries 0 and 1 causes tail calls to silently fail (the BPF runtime returns to the caller with no error), breaking the exec event pipeline.
- `execve_map` at `/sys/fs/bpf/tetragon/execve_map` is a hash map keyed by PID that tracks all known processes. Clearing it makes all processes invisible to Tetragon's correlation logic.
- **Minimum modification**: 2 key deletions from `execve_calls` (sufficient for exec blindness); clearing `execve_map` provides complete state erasure.

**Falco** -- `interesting_syscalls` (BPF array, 512 entries):
- Each entry is a single byte. `interesting_syscalls[NR] != 0` means syscall number `NR` is captured; `== 0` means it is skipped at the BPF level before any data is copied to the ring buffer.
- Zeroing all 512 entries causes every BPF probe to return early.
- **Minimum modification**: 512 single-byte writes. In practice, targeting specific syscalls (e.g., entry 59 for `execve`, 257 for `openat`) achieves selective evasion with fewer writes.

---

### RQ4: Do any of the tested tools use available kernel hardening mechanisms (`bpf_map_freeze()`, `BPF_F_RDONLY_PROG`) on their security-critical maps?

**Answer: No.** None of the three tools use either mechanism on any map:

- **`bpf_map_freeze()`**: Not called on any map by Tracee, Tetragon, or Falco. This helper, available since kernel 5.2, makes a map permanently read-only from userspace. It would directly prevent the poisoning attacks described in this work (for maps that are static after initialization).
- **`BPF_F_RDONLY_PROG`**: Not used as a creation flag on any security-critical map. This flag restricts BPF-program-side access to read-only, but does not prevent userspace writes. It would not mitigate the attacks in this work but represents a general hardening gap.
- **Runtime integrity checks**: No tool implements periodic userspace verification of critical map contents (e.g., polling `enabled_policies`, verifying `interesting_syscalls` entries, checking `execve_calls` prog_array population).

Source code verification was performed against Tracee v0.24.1 (`pkg/ebpf/`), Tetragon v1.4.0 (`bpf/`, `pkg/sensors/`), and Falco's libs (`driver/bpf/`).

---

### RQ5: Is BPF map poisoning detectable by the targeted tool itself or by standard host-level monitoring?

**Answer: Not with current implementations.** The attack is undetectable by:

1. **The targeted tool**: Since event generation is suppressed at the BPF level, the tool's userspace process never learns that events are missing. There is no "expected event rate" check, no heartbeat, and no map integrity verification.
2. **Process monitoring**: No process is created, killed, or modified. The attacker uses the `bpf()` syscall from an existing process.
3. **File integrity monitoring**: No filesystem changes occur (except for pinned map state changes, which are on the `bpf` pseudo-filesystem and are not monitored by FIM tools).
4. **Network monitoring**: No network traffic is generated.
5. **Linux Audit (`auditd`)**: The `bpf()` syscall can be audited (`-a always,exit -F arch=b64 -S bpf`), but in environments running eBPF tools, the volume of legitimate `bpf()` calls makes this impractical without semantic filtering that distinguishes map updates by target map identity and caller, which auditd does not support.

Detection would require either (a) the tool implementing self-monitoring of its own maps, or (b) an independent BPF program that watches for `bpf(BPF_MAP_UPDATE_ELEM)` calls targeting known security tool maps and alerts on unexpected writers.

---

### RQ6: How quickly does BPF map poisoning take effect, and how long does the evasion persist?

**Answer: Immediate effect, indefinite persistence.**

- **Latency**: Map modifications take effect on the next BPF program invocation that reads the poisoned map. For syscall-attached programs, this is the next relevant syscall, typically within microseconds. For Tracee, the `policies_version` bump forces an immediate re-read of `enabled_policies`, so the effect is synchronous with the next event.
- **Persistence**: The evasion persists until one of: (a) the tool is restarted (which re-initializes maps from scratch), (b) the tool's userspace process detects the tampering and corrects it (no tool currently does this), or (c) the attacker's modification is accidentally overwritten by a legitimate tool operation (e.g., a policy change in Tracee that re-writes `enabled_policies`).
- **Across restarts**: Map poisoning does not survive tool restarts because maps are re-created and re-populated during initialization. However, an attacker with persistent access can re-poison maps after each restart, either manually or via a watchdog process.

---

### RQ7: What mitigations are available, and what are their trade-offs?

**Answer:** Mitigations exist at multiple levels, each with distinct trade-offs:

| Mitigation | Level | Effectiveness | Trade-off |
|-----------|-------|--------------|-----------|
| `bpf_map_freeze()` | Kernel API | Prevents all userspace writes after freeze | One-way; maps that need runtime updates (e.g., Tracee's `config_map` for policy changes) cannot be frozen without architectural changes |
| `BPF_F_RDONLY_PROG` | Map creation | Prevents BPF-side writes | Does not prevent userspace writes; orthogonal to this attack |
| Userspace heartbeat | Tool implementation | Detects tampering after the fact | Adds latency between poisoning and detection; attacker can race |
| BPF-side self-check | Tool implementation | Detects tampering inline with event processing | Adds overhead to every event; canary values can be reverse-engineered |
| BPF token (kernel 6.9+) | Kernel API | Scopes BPF operations to a delegation context | Does not yet support per-map access control; primarily targets unprivileged BPF |
| LSM BPF hooks | Kernel API | `bpf_map_update_elem` LSM hook could enforce per-map policy | Requires an LSM BPF program to guard other BPF programs; circular trust issue |
| Capability restriction | Deployment | Minimize processes with `CAP_BPF` | Difficult in practice; security tools themselves need `CAP_BPF` |

The most immediately actionable mitigation is `bpf_map_freeze()` for maps that are static after initialization (Falco's `interesting_syscalls`, Tetragon's `execve_calls`). Maps that require runtime updates (Tracee's `config_map`) need architectural changes such as splitting mutable and immutable fields into separate maps, freezing the immutable map, and implementing integrity verification for the mutable one.
