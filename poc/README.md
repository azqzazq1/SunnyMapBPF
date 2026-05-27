# Proof-of-Concept Scripts

Automated PoC scripts demonstrating BPF Map Poisoning against each tool.

## Scripts

| Script | Target | Attack Vector | Expected Result |
|--------|--------|--------------|-----------------|
| `poc-tracee-blindness.sh` | Tracee v0.24.x | `config_map` enabled_policies=0 | Total blindness (0 events) |
| `poc-tetragon-blindness.sh` | Tetragon v1.4.x | `execve_calls` + `execve_map` clear | Total blindness (0 events) |
| `poc-falco-blindness.sh` | Falco (modern BPF) | `interesting_syscalls` zeroed | Total blindness (0 alerts) |

## Prerequisites

- Linux kernel 5.8+ with BPF support
- `CAP_BPF` or `CAP_SYS_ADMIN`
- `bpftool` (v7.0+)
- `python3` with `json` module
- Docker

## Usage

```bash
# Test against Tracee
sudo ./poc-tracee-blindness.sh

# Test against Tetragon
sudo ./poc-tetragon-blindness.sh

# Test against Falco
sudo ./poc-falco-blindness.sh
```

Each script performs the full cycle:
1. Start the target tool in a Docker container
2. Establish baseline (measure normal event detection)
3. Poison the BPF map(s)
4. Verify blindness (generate activity, measure zero detection)
5. Restore the tool
6. Verify recovery

## Safety

These scripts run in isolated Docker containers and clean up after themselves. No production systems are affected. All map modifications are reversed (via tool restart) at the end of each test.
