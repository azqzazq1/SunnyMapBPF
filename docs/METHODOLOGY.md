# Research Methodology

## Overview

This research follows a five-phase methodology progressing from static analysis through dynamic verification to cross-tool generalization. Each phase builds on the prior phase's outputs. The methodology is designed to systematically identify, classify, and exploit BPF map-based attack surfaces in runtime security tools.

## Phase 1: Static Analysis

**Objective:** Identify all BPF maps defined by each tool and understand their role in the event processing pipeline.

**Approach:**

1. **Source code review of BPF programs.** Each tool's kernel-side BPF C code was reviewed to identify:
   - Map declarations (`struct bpf_map_def`, `SEC(".maps")`, `BPF_MAP_*` macros)
   - Map access patterns (`bpf_map_lookup_elem`, `bpf_map_update_elem`, `bpf_map_delete_elem`)
   - Control flow dependencies on map values (conditional branches gated on map lookups)

2. **Userspace daemon analysis.** The userspace components were reviewed for:
   - Map creation parameters (type, key/value sizes, max entries, flags)
   - Map initialization sequences (what values are written at startup)
   - Runtime map update patterns (periodic refresh, event-driven, one-time)
   - Map protection mechanisms (freeze, read-only flags, integrity checks)

3. **Struct layout extraction.** For each security-critical map, the value struct was reconstructed from source code:
   - Field offsets calculated from struct definitions
   - Padding and alignment rules applied (BPF maps use natural alignment)
   - Cross-referenced with `bpftool map dump` output from running instances

**Tools used:** Manual source review (GitHub), `pahole` for struct layout verification, `bpftool` for runtime cross-reference.

**Tracee specifics:** Reviewed `pkg/ebpf/c/tracee.bpf.c`, `pkg/ebpf/c/types.h`, `pkg/ebpf/c/maps.h`. Key finding: `config_entry_t` contains `policies_config_t` at offset 216, which holds `enabled_policies` as a `u64` bitmask. The `policies_version` field at offset 14 of `config_entry_t` controls a per-CPU cache invalidation mechanism -- BPF programs compare the cached version against `config_map[0].policies_version` and re-read config only on mismatch.

**Tetragon specifics:** Reviewed `bpf/process/bpf_execve_event.c`, `bpf/process/types/basic.h`, `bpf/lib/process.h`. Key finding: `execve_map` (HASH) keyed by PID stores `msg_execve_key` structs used by all sensors to resolve process context. `execve_calls` (PROG_ARRAY) contains tail call targets for the exec event processing pipeline.

**Falco specifics:** Reviewed `driver/bpf/`, specifically `fillers.h`, `probe.c`, and `maps.h` in the libs repository (`falcosecurity/libs`). Key finding: `interesting_syscalls` is a 512-entry ARRAY map with 1-byte values. BPF probe entry points check `interesting_syscalls[syscall_nr]` and return early if the value is 0.

## Phase 2: Map Inventory and Classification

**Objective:** Build a complete inventory of BPF maps per tool and classify each by security criticality.

**Classification taxonomy:**

| Class | Definition | Example |
|---|---|---|
| **Control** | Determines whether events are processed at all | `config_map` (Tracee), `interesting_syscalls` (Falco) |
| **State** | Holds runtime state needed for event correlation | `execve_map` (Tetragon), `proc_info_map` (Tracee) |
| **Pipeline** | Contains program references for tail calls | `execve_calls` (Tetragon), `sys_*_calls` (Tetragon) |
| **Output** | Buffers for event data transport to userspace | `events` perf buffer (Tracee), ring buffers |
| **Auxiliary** | Scratch space, statistics, non-critical metadata | `stats_map`, `heap` |

**Security criticality scoring:**

Each map was scored on three axes:
- **Impact of modification (I):** 0 = no effect, 1 = degraded, 2 = partial bypass, 3 = total bypass
- **Accessibility (A):** 0 = not accessible, 1 = enumerable, 2 = directly addressable (pinned)
- **Persistence (P):** 0 = immediately overwritten, 1 = overwritten on next event, 2 = persists until restart

Maps with I=3 were prioritized for Phase 3.

## Phase 3: Attack Primitive Identification

**Objective:** For each high-criticality map, determine the precise modification needed to achieve evasion.

**Process per map:**

1. **Identify the decision point.** Trace from the map lookup to the branch that determines whether an event is processed or dropped.

2. **Determine the poison value.** What value, when read from the map, causes the BPF program to drop/skip the event?

3. **Identify cache invalidation requirements.** Some tools cache map values in per-CPU storage. Poisoning the map alone may be insufficient if cached values are not invalidated.

4. **Calculate minimal modification.** What is the smallest number of bytes that must be changed to achieve total evasion?

5. **Construct the update command.** Translate the required modification into `bpf(BPF_MAP_UPDATE_ELEM)` calls with exact key and value parameters.

**Results:**

- **Tracee:** 10 bytes modified (8 bytes for `enabled_policies` at offset 216, 2 bytes for `policies_version` at offset 14). The version bump is critical -- without it, per-CPU cached config values remain active and events continue to be processed.

- **Tetragon:** Two operations: (a) delete 2 entries from `execve_calls` PROG_ARRAY, breaking the tail call chain for exec events; (b) delete all entries from `execve_map` HASH, removing process context for all sensors. Either operation alone causes significant blindness; together they achieve total blindness.

- **Falco:** 512 bytes modified (one byte per syscall entry in `interesting_syscalls`). Each entry zeroed causes the corresponding syscall's BPF probe to return without processing.

## Phase 4: Dynamic Verification

**Objective:** Confirm each attack primitive works against live tool instances and measure the effect quantitatively.

**Experimental protocol per tool:**

1. **Deploy tool** in Docker container with standard configuration (privileged mode, host PID namespace, required volume mounts).

2. **Wait for initialization** (15 seconds after container start, verified by checking BPF program/map presence).

3. **Establish baseline.** Generate a fixed set of detectable activities (file access to `/etc/shadow`, process execution via `/bin/bash`, `whoami`, `id`, `cat /etc/passwd`, `ps aux`, `find /tmp`). Count events/alerts produced by the tool over a fixed time window (3-5 seconds post-activity).

4. **Verify baseline non-zero.** If the tool produces zero events during baseline, abort (indicates tool malfunction, not a valid test).

5. **Execute poison.** Apply the attack primitive identified in Phase 3 using `bpftool map update` / `bpftool map delete`.

6. **Verify poison applied.** Read back the modified map values to confirm the write succeeded.

7. **Test blindness.** Repeat the identical activity set from step 3. Count events/alerts over an extended window (4-5 seconds) to account for any pipeline lag.

8. **Measure effect.** Compare post-poison event count against baseline. Classify: total blindness (0 events), near-total (<= 2 events, attributed to pipeline flush), partial (> 2 events).

9. **Test reversibility.** For Tracee: restore original map values via `bpftool map update`. For Tetragon/Falco: restart the container (map values are re-initialized on startup). Re-run the activity set and confirm events resume.

**Controls:**
- Same activity generator function used for all phases (baseline, poison, restore)
- Fixed sleep intervals between activity generation and event counting
- Event counting via tool-native interfaces (docker logs for Tracee/Falco, `tetra getevents` for Tetragon)

## Phase 5: Cross-Tool Generalization

**Objective:** Determine whether BPF map poisoning is a systemic vulnerability class rather than a tool-specific bug.

**Analysis dimensions:**

1. **Root cause commonality.** All three tools share the same root cause: BPF maps are writable by any process with `CAP_BPF`, but the tools assume exclusive map ownership.

2. **Capability requirement consistency.** Confirmed that `CAP_BPF` (not `CAP_SYS_ADMIN`) is sufficient for all three attacks. Verified on kernel 6.8.0 with `unprivileged_bpf_disabled=2`.

3. **Protection mechanism absence.** Checked all three tools for:
   - `bpf_map_freeze()` usage: none
   - `BPF_F_RDONLY_PROG` flag: none
   - Runtime map integrity checks (periodic re-read and verify): none
   - BPF LSM self-protection (hooking `bpf()` syscall to deny external map writes): none

4. **Attack pattern abstraction.** Generalized the attack into a three-step pattern applicable to any BPF-based security tool:
   - Enumerate maps (via `BPF_MAP_GET_NEXT_ID` or pinned paths)
   - Identify control-plane maps (by name, type, or behavioral analysis)
   - Modify control values to suppress event generation

5. **Mitigation analysis.** Evaluated whether existing kernel mechanisms could prevent the attack and why they are not deployed.
