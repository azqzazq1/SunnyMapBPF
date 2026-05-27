# Figures

Diagrams and visualizations for the SunnyMapBPF research.

## Planned Figures

- `fig1_attack_overview.png` — High-level attack flow diagram
- `fig2_tracee_architecture.png` — Tracee BPF map data flow
- `fig3_tetragon_architecture.png` — Tetragon pinned map layout
- `fig4_falco_architecture.png` — Falco syscall processing pipeline
- `fig5_cross_tool_comparison.png` — Results comparison chart
- `fig6_defense_layers.png` — Proposed defense-in-depth model

## Text-Based Architecture Diagrams

### BPF Map Poisoning Attack Flow

```
 Attacker Process                    Kernel BPF Subsystem
 (CAP_BPF)                         
                                    +------------------+
  bpf(BPF_MAP_GET_NEXT_ID) ------> | Map Enumeration  |
                                    +------------------+
  bpf(BPF_MAP_GET_FD_BY_ID) -----> | Map FD Lookup    |
                                    +------------------+
  bpf(BPF_MAP_UPDATE_ELEM) ------> | Map Write        | ---> Security Tool
  bpf(BPF_MAP_DELETE_ELEM) ------> | (NO ACL CHECK)   |      BPF Programs
                                    +------------------+      read poisoned
                                                              state
                                                              
                                                              Events DROPPED
                                                              at kernel level
```

### Tool-Specific Attack Paths

```
TRACEE:
  config_map[0].enabled_policies = 0  --->  match_scope_filters() = 0
  config_map[0].policies_version++    --->  per-CPU cache invalidated
                                            ALL events silently dropped

TETRAGON:
  execve_calls[0] = DELETE            --->  bpf_tail_call() fails silently
  execve_calls[1] = DELETE            --->  exec events never processed
  execve_map[*] = DELETE              --->  all PIDs unknown
                                            ALL events silently dropped

FALCO:
  interesting_syscalls[0..511] = 0    --->  BPF probe returns immediately
                                            for every syscall
                                            ALL events silently dropped
```
