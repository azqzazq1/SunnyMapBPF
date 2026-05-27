# Experimental Setup

## 1. Host Environment

| Component       | Value                                          |
|-----------------|------------------------------------------------|
| OS              | Ubuntu 24.04 LTS                               |
| Kernel          | 6.8.0-111-generic                              |
| Architecture    | x86_64                                         |
| BPF subsystem   | BTF enabled, CO-RE supported                   |
| bpftool         | v7.4.0                                         |
| Docker          | Docker Engine (Community), latest stable        |
| Python          | 3.12.x (for JSON parsing in PoC scripts)       |
| `unprivileged_bpf_disabled` | 2 (default for Ubuntu 24.04)       |

### Kernel Configuration (BPF-relevant)

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_JIT_ALWAYS_ON=y
CONFIG_BPF_LSM=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_BPF_UNPRIV_DEFAULT_OFF=y
```

Verified via:
```bash
cat /boot/config-$(uname -r) | grep BPF
```

### Capability Verification

```bash
# Confirm CAP_BPF is sufficient (not CAP_SYS_ADMIN)
# Test process runs with only CAP_BPF:
capsh --caps="cap_bpf+eip" -- -c "bpftool map list"
```

## 2. Tool Deployments

### 2.1 Tracee v0.24.1

**Container image:** `aquasec/tracee:latest` (pulled tag resolving to v0.24.1 at time of testing)

**Docker run command:**
```bash
docker run -d --name tracee-poc-test \
    --privileged \
    --pid=host \
    -v /etc/os-release:/etc/os-release-host:ro \
    -v /boot:/boot:ro \
    -v /lib/modules:/lib/modules:ro \
    -v /sys/kernel/debug:/sys/kernel/debug:rw \
    aquasec/tracee:latest
```

**Initialization wait:** 15 seconds (allows BPF program compilation, loading, and attachment)

**Verification:** After initialization, `bpftool map list` shows `config_map` (ARRAY, 1 entry, 256B value) and `bpftool prog list` shows multiple Tracee BPF programs attached to tracepoints.

**Event output:** JSON to stdout, captured via `docker logs tracee-poc-test`

**Default configuration:** All default policies enabled (1 policy active, `enabled_policies = 0x0000000000000001`)

### 2.2 Tetragon v1.4.0

**Container image:** `quay.io/cilium/tetragon:v1.4.0`

**Docker run command:**
```bash
docker run -d --name tetragon-poc-test \
    --privileged \
    --pid=host \
    -v /sys/kernel/btf:/sys/kernel/btf:ro \
    -v /sys/kernel/debug:/sys/kernel/debug \
    -v /sys/fs/bpf:/sys/fs/bpf \
    -v /lib/modules:/lib/modules:ro \
    quay.io/cilium/tetragon:v1.4.0
```

**Critical mount:** `-v /sys/fs/bpf:/sys/fs/bpf` is required for map pinning. This also makes pinned maps accessible from the host, which is the intended deployment model but also enables the attack.

**Initialization wait:** 15 seconds

**Verification:**
```bash
# Confirm pinned maps exist
ls /sys/fs/bpf/tetragon/execve_map
ls /sys/fs/bpf/tetragon/__base__/event_execve/execve_calls

# Confirm execve_map is populated
bpftool map dump pinned /sys/fs/bpf/tetragon/execve_map -j | python3 -c \
    "import json,sys; print(len(json.load(sys.stdin)), 'entries')"
```

**Event output:** JSON via `tetra getevents -o json` (executed inside the container via `docker exec`)

### 2.3 Falco (Latest)

**Container image:** `falcosecurity/falco:latest`

**Docker run command:**
```bash
docker run -d --name falco-poc-test \
    --privileged \
    --pid=host \
    -v /etc/os-release:/etc/os-release-host:ro \
    -v /boot:/boot:ro \
    -v /lib/modules:/lib/modules:ro \
    -v /sys/kernel/debug:/sys/kernel/debug \
    -v /dev:/host/dev \
    -v /proc:/host/proc:ro \
    falcosecurity/falco:latest
```

**Initialization wait:** 15 seconds (Falco compiles BPF programs at startup if not using pre-built driver)

**Verification:**
```bash
# Confirm interesting_syscalls map exists
bpftool map list -j | python3 -c "
import json,sys
for m in json.load(sys.stdin):
    if 'interesting_sys' in m.get('name',''):
        print(f\"ID={m['id']} entries={m['max_entries']}\")
"

# Verify key syscalls are marked interesting
MAP_ID=<discovered_id>
bpftool map lookup id $MAP_ID key hex 3b 00 00 00  # execve (NR 59)
# Should show value 01
```

**Event output:** Alerts to stdout, captured via `docker logs falco-poc-test`. Alerts contain severity levels (Warning, Notice, Error, Critical, Alert).

**Default ruleset:** Falco ships with a comprehensive default ruleset that monitors file access, process execution, network activity, and privilege escalation. This ensures a non-trivial set of `interesting_syscalls` entries.

## 3. Activity Generator

A consistent set of activities is used across all tools to produce detectable events. The generator is designed to trigger multiple rule categories:

```bash
generate_activity() {
    /bin/ls /etc/shadow > /dev/null 2>&1 || true       # Sensitive file access
    /bin/cat /etc/passwd > /dev/null 2>&1               # Sensitive file read
    /usr/bin/whoami > /dev/null 2>&1                    # Process execution
    /usr/bin/id > /dev/null 2>&1                        # Process execution
    /bin/uname -a > /dev/null 2>&1                      # Process execution
    /bin/ps aux > /dev/null 2>&1                        # Process listing
    /usr/bin/find /tmp -maxdepth 1 > /dev/null 2>&1     # Directory enumeration
    /bin/bash -c "echo invisible" > /dev/null 2>&1      # Shell execution
}
```

**Design rationale:**
- Each command uses absolute paths to avoid shell built-in ambiguity
- `/etc/shadow` access triggers file sensitivity rules in all three tools
- Multiple `execve` calls provide a reliable baseline count
- Output redirected to `/dev/null` to avoid terminal noise
- `|| true` on shadow access prevents script failure on permission deny

**Falco-specific additions:**
```bash
cp /etc/passwd /tmp/falco-test-copy 2>/dev/null || true  # File copy to /tmp
rm /tmp/falco-test-copy 2>/dev/null || true              # File deletion
```

These trigger additional Falco rules around file modification in `/tmp`.

## 4. Measurement Methodology

### 4.1 Event Counting

**Tracee:** Event count measured via line count of `docker logs` output.
```bash
count_events() {
    docker logs tracee-poc-test 2>&1 | wc -l
}
```
Differential measurement: `count_after - count_before` gives the number of new events in the measurement window.

**Tetragon:** Events captured via `tetra getevents` streamed to a file for a fixed duration.
```bash
capture_events() {
    docker exec tetragon-poc-test tetra getevents -o json > /tmp/events.json &
    local pid=$!
    sleep 1
    generate_activity
    sleep $duration
    kill $pid
}
```
Process execution events counted via `grep -c "process_exec"`. Total events counted via `wc -l`.

**Falco:** Alert count measured via pattern matching on `docker logs` output.
```bash
count_alerts() {
    docker logs falco-poc-test 2>&1 | grep -c "Warning\|Notice\|Error\|Critical\|Alert"
}
```

### 4.2 Timing

| Phase            | Wait Before Activity | Wait After Activity | Rationale                        |
|------------------|---------------------|---------------------|----------------------------------|
| Baseline         | 1s                  | 3-4s                | Allow pipeline to process events |
| Post-poison      | 1s                  | 4-5s                | Extended window to catch delayed events |
| Post-restore     | 2s                  | 3-4s                | Allow map re-read / restart      |

Extended post-poison windows are intentionally longer than baseline to provide a conservative measurement -- any events that leak through delayed processing are captured.

### 4.3 Success Criteria

| Classification     | Condition                          |
|--------------------|-------------------------------------|
| Total blindness    | Post-poison events = 0             |
| Near-total         | Post-poison events <= 2 (pipeline flush) |
| Partial            | Post-poison events > 2             |
| Failed             | Post-poison events >= baseline      |

### 4.4 Controls

1. **Baseline validation:** If baseline produces 0 events, the test is aborted (indicates tool malfunction, not a valid test environment).

2. **Map write verification:** After each poison write, the map is read back to confirm the intended values were written.

3. **Restoration verification:** After restoring original values (or restarting the container), activity is re-generated to confirm the tool resumes normal operation. This proves the tool was functional before and after, and that the observed blindness was caused by the map modification.

## 5. Reproducibility

All PoC scripts are self-contained and automated:
- `poc/poc-tracee-blindness.sh` -- Tracee attack
- `poc/poc-tetragon-blindness.sh` -- Tetragon attack
- `poc/poc-falco-blindness.sh` -- Falco attack

Each script handles container lifecycle (start, test, cleanup), produces structured output with event counts, and exits cleanly regardless of success or failure.

**Prerequisites for reproduction:**
1. Root access or `CAP_BPF` + `CAP_PERFMON`
2. Docker installed and running
3. `bpftool` v7.0+ installed
4. `python3` with `json` module (stdlib)
5. Internet access for pulling container images (first run only)
6. Kernel 5.8+ with BTF support
