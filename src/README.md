# Source Code

## Tools

| File | Description |
|------|------------|
| `map_enumerator.py` | Enumerates BPF maps and identifies security-critical ones per tool |
| `map_poisoner.py` | Implements attack primitives for controlled testing |
| `integrity_checker.py` | Defensive tool: monitors BPF map integrity via periodic hashing |

## Usage

All tools require `CAP_BPF` or `CAP_SYS_ADMIN`.

```bash
# Enumerate maps
sudo python3 map_enumerator.py --tool tracee --critical-only

# Execute attack (research only)
sudo python3 map_poisoner.py --tool tracee --attack blindness

# Monitor integrity (defensive)
sudo python3 integrity_checker.py --tool tracee --interval 5
```
