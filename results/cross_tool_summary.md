# Cross-Tool Verification Summary

## Test Matrix

| | Tracee v0.24.1 | Tetragon v1.4.0 | Falco latest |
|---|---|---|---|
| **Attack Vector** | config_map: enabled_policies=0 | execve_calls + execve_map | interesting_syscalls=0 |
| **Map Type** | ARRAY (unpinned) | PROG_ARRAY + HASH (pinned) | ARRAY (unpinned) |
| **Discovery Method** | BPF_MAP_GET_NEXT_ID | Filesystem path | BPF_MAP_GET_NEXT_ID |
| **Fields Modified** | 2 (10 bytes) | 2 entries + 192 entries | 512 entries (512 bytes) |
| **Baseline Events** | 16 | 14 exec + exits | 1+ alerts |
| **Post-Poison Events** | **0** | **0** | **0** |
| **Post-Restore Events** | 7 | 11 | 1+ |
| **Blindness Level** | TOTAL | TOTAL | TOTAL |
| **bpf_map_freeze()** | NOT USED | NOT USED | NOT USED |
| **BPF_F_RDONLY_PROG** | NOT USED | NOT USED | NOT USED |
| **Runtime Integrity Check** | NONE | NONE | NONE |
| **Map Modification Alert** | Partial* | NONE | NONE |

*Tracee hooks `security_bpf_map` but the attacker can disable this event first.

## Environment

- Kernel: Linux 6.8.0-111-generic (Ubuntu 24.04)
- bpftool: v7.4.0
- Docker: containerized tool instances with `--privileged --pid=host`
- Required capability: CAP_BPF
