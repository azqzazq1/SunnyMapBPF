# Evaluation Plan

## 1. Evaluation Objectives

The evaluation answers three questions:

1. **Effectiveness:** Does BPF map poisoning achieve complete evasion (zero events/alerts) for each tool?
2. **Reversibility:** Can the attack be undone, restoring normal tool operation?
3. **Generality:** Does the attack class apply across tools with different architectures and map designs?

---

## 2. Metrics

### 2.1 Primary Metric: Event Count

The fundamental measure is the number of security events (or alerts) produced by the tool when a fixed set of detectable activities is performed.

| Metric                 | Definition                                                    |
|------------------------|---------------------------------------------------------------|
| `E_baseline`           | Events detected during baseline activity window               |
| `E_poison`             | Events detected during identical activity after map poisoning |
| `E_restore`            | Events detected after restoration of original map state       |
| `Evasion_rate`         | `1 - (E_poison / E_baseline)`, expressed as percentage        |

An evasion rate of 100% (E_poison = 0) indicates total blindness.

### 2.2 Secondary Metrics

| Metric                 | Definition                                                    |
|------------------------|---------------------------------------------------------------|
| `Bytes_modified`       | Number of bytes changed in the target map                     |
| `Maps_modified`        | Number of distinct maps modified                              |
| `Time_to_blind`        | Wall-clock time from first bpftool command to confirmed blind |
| `Time_to_restore`      | Wall-clock time from restore action to confirmed recovery     |
| `Capabilities_required`| Minimum Linux capabilities needed for the attack              |

### 2.3 Per-Tool Event Categories

**Tracee:**
- Total event count (all event types)
- No sub-categorization needed (config_map disables ALL policies globally)

**Tetragon:**
- `process_exec` events (directly affected by execve_calls deletion)
- `process_exit` events (may or may not be affected, depending on separate exit pipeline)
- Total event count across all sensors

**Falco:**
- Alert count by severity (Warning, Notice, Error, Critical, Alert)
- Total alert count

---

## 3. Experimental Protocol

### 3.1 Per-Tool Test Procedure

Each tool is tested independently using the following protocol:

```
PHASE 0: SETUP
    Deploy tool in Docker container with standard configuration
    Wait for initialization (15s)
    Verify BPF programs loaded and target maps present

PHASE 1: BASELINE MEASUREMENT
    Record event count: count_before
    Wait 1 second
    Execute activity generator
    Wait 3-5 seconds (tool-specific)
    Record event count: count_after
    E_baseline = count_after - count_before
    ASSERT: E_baseline > 0 (tool is functional)

PHASE 2: POISON APPLICATION
    Execute map poisoning command(s)
    Read back modified map to verify write succeeded
    ASSERT: Map values match intended poison state

PHASE 3: BLINDNESS MEASUREMENT
    Record event count: count_before
    Wait 1 second
    Execute SAME activity generator as Phase 1
    Wait 4-5 seconds (extended to catch delayed events)
    Record event count: count_after
    E_poison = count_after - count_before
    Calculate: evasion_rate = 1 - (E_poison / E_baseline)

PHASE 4: RESTORATION
    Tracee: Write original values back to config_map
    Tetragon/Falco: Restart container (docker restart)
    Wait for re-initialization
    Record event count: count_before
    Execute SAME activity generator
    Wait 3-4 seconds
    Record event count: count_after
    E_restore = count_after - count_before
    ASSERT: E_restore > 0 (tool has recovered)

PHASE 5: CLEANUP
    Remove container
    Report results
```

### 3.2 Controlled Variables

| Variable                | Control Method                                    |
|-------------------------|---------------------------------------------------|
| Activity set            | Same generate_activity() function for all phases  |
| Activity timing         | Fixed sleep intervals between commands             |
| Tool configuration      | Default configuration for all tools                |
| Kernel version          | Same host for all tests (6.8.0-111-generic)        |
| Measurement window      | Fixed per-tool (documented in EXPERIMENTAL_SETUP)  |
| Tool initialization     | 15s wait; presence of target maps verified         |

### 3.3 Confound Mitigation

**False positives (detecting events not from our activity):**
Differential measurement (count_after - count_before) isolates events generated during the activity window from background system events. The 1-second pre-activity wait allows any in-flight events from prior activity to drain.

**False negatives (missing events from our activity):**
Post-activity wait windows (3-5 seconds) are conservatively long relative to expected pipeline latency (< 100ms). Extended post-poison windows (4-5 seconds) provide additional margin.

**Tool startup variability:**
15-second initialization wait is empirically sufficient for all three tools. Baseline phase confirms tool is operational before proceeding.

---

## 4. Cross-Tool Comparison

### 4.1 Comparison Dimensions

| Dimension               | Tracee                      | Tetragon                     | Falco                        |
|--------------------------|-----------------------------|------------------------------|------------------------------|
| Attack target            | Configuration map           | Prog array + state map       | Syscall filter map           |
| Map access method        | ID enumeration              | Pinned path (deterministic)  | ID enumeration               |
| Modification type        | Value overwrite (2 fields)  | Entry deletion               | Value overwrite (512 entries)|
| Bytes modified           | 10                          | N/A (deletion, not overwrite)| 512                          |
| Cache invalidation req.  | Yes (version bump)          | No                           | No                           |
| Recovery method          | Map restore (no restart)    | Container restart             | Container restart            |
| Self-detection possible  | No                          | No                           | No                           |

### 4.2 Root Cause Analysis

For each tool, confirm that the root cause matches the generalized vulnerability pattern:

1. **No map ownership enforcement** -- the kernel permits writes from any `CAP_BPF` process
2. **No use of `bpf_map_freeze()`** -- maps remain writable after initialization
3. **No use of `BPF_F_RDONLY_PROG`** -- this flag is not set on any security-critical map
4. **No runtime integrity checking** -- tools do not periodically re-validate their own map contents
5. **No BPF LSM self-protection** -- tools do not hook `bpf()` to detect external map modifications

### 4.3 Generalization Criteria

The attack class is considered "generalizable" if:
- All three tools are independently vulnerable (different codebases, different organizations)
- The root cause is shared (BPF subsystem design, not tool-specific bugs)
- The same attacker capability (`CAP_BPF`) is sufficient for all three
- No tool-specific preconditions are required beyond map identification

---

## 5. Reversibility Assessment

Reversibility is evaluated on two dimensions:

### 5.1 Operational Reversibility

Can the tool be restored to full functionality after poisoning?

| Tool     | Restore Method              | Events Resume? | State Fully Recovered? |
|----------|-----------------------------|----------------|------------------------|
| Tracee   | Map value restore           | Yes (immediate)| Yes                    |
| Tetragon | Container restart           | Yes            | Yes (maps re-created)  |
| Falco    | Container restart           | Yes            | Yes (maps re-populated)|

### 5.2 Forensic Reversibility

Can the poisoning be detected after the fact?

| Artifact                    | Available? | Notes                                      |
|-----------------------------|------------|---------------------------------------------|
| Map modification logs       | No         | Kernel does not log BPF map writes          |
| Audit trail (auditd)       | Possible   | If auditd monitors `bpf()` syscall          |
| Tool-side logs              | No         | Tools do not log their own config state     |
| Event gap in timeline       | Yes        | Absence of events during poison window      |

The primary forensic indicator is a *gap* in the event timeline -- a period where no events were generated despite system activity. However, this requires an external monitoring system that independently tracks the tool's output rate.

---

## 6. Threat Model Validation

The evaluation validates the following threat model assumptions:

| Assumption                                    | Validation Method                             |
|-----------------------------------------------|-----------------------------------------------|
| Attacker has CAP_BPF                          | Tests run with CAP_BPF (not CAP_SYS_ADMIN)   |
| Attacker can enumerate maps                    | bpftool map list succeeds from external process|
| Attacker can identify target maps by name     | Map names are unique and descriptive           |
| Map writes take immediate effect              | Post-write map read confirms values            |
| BPF programs read poisoned values             | Event count drops to zero                      |
| Tool does not detect the modification         | No alerts generated about self-tampering       |

---

## 7. Limitations

1. **Single-host evaluation.** All tests run on one kernel version (6.8.0-111-generic). Different kernel versions may have different BPF subsystem behavior, though the core map access APIs are stable since kernel 5.8.

2. **Default configurations only.** Tools may have non-default hardening options (e.g., Tetragon's runtime enforcement policies). These were not tested.

3. **Docker deployment only.** Kubernetes deployments with additional pod security policies, seccomp profiles, or AppArmor confinement may restrict BPF access. The fundamental vulnerability remains, but exploitation may be harder.

4. **Timing sensitivity.** Event counts depend on fixed-duration measurement windows. Very slow systems may produce different counts. The baseline validation step mitigates this.

5. **Version specificity.** Struct layouts, map names, and offsets are version-specific. The Tracee attack in particular depends on the `config_entry_t` layout, which may change between versions. The methodology (Phase 1 static analysis) would need to be re-applied for new versions.
