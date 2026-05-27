# Experiment: Tracee v0.24.1 Total Blindness

## Objective

Verify that zeroing `enabled_policies` in Tracee's `config_map` causes complete event blindness.

## Setup

```bash
docker run -d --name tracee-test \
  --privileged --pid=host \
  -v /etc/os-release:/etc/os-release-host:ro \
  -v /boot:/boot:ro \
  -v /lib/modules:/lib/modules:ro \
  -v /sys/kernel/debug:/sys/kernel/debug:rw \
  aquasec/tracee:latest
```

## Variables

- **Independent variable:** `enabled_policies` value in `config_map` (1 vs 0)
- **Dependent variable:** Number of events detected by Tracee
- **Control:** Same set of commands executed before and after modification
- **Confound mitigation:** `policies_version` bump to invalidate per-CPU cache

## Procedure

1. Wait 15s for Tracee initialization
2. Locate `config_map` (ARRAY type, name="config_map")
3. Record baseline: execute test commands, count events over 5s window
4. Poison: set `enabled_policies`=0 at offset 216, bump `policies_version` at offset 14
5. Record post-poison: execute same test commands, count events over 5s window
6. Restore: set `enabled_policies`=1, set `policies_version`=1
7. Record post-restore: execute same test commands, count events

## Test Commands

```bash
ls /etc/shadow
cat /etc/passwd
whoami
id
uname -a
ps aux
find /tmp -maxdepth 1
curl --version
bash -c "echo test"
```

## Results

| Phase | enabled_policies | policies_version | Events Detected |
|-------|-----------------|-----------------|-----------------|
| Baseline | 1 | 1 | **16** |
| Post-poison | 0 | 2 | **0** |
| Post-restore | 1 | 1 | **7** |

## Observations

- Total blindness achieved with 2-field modification
- Per-CPU caching requires version bump for immediate effect
- Restore via version reset successfully recovers monitoring
- No error messages or alerts generated during poisoning
- Tracee userspace daemon continues running normally (no crash)

## Conclusion

Confirmed: `enabled_policies=0` causes `match_scope_filters()` to return 0 for all events, resulting in complete monitoring blindness.
