# Evaluation Metrics

## Primary Metrics

### M1: Event Detection Rate (EDR)

```
EDR = (events_detected / events_expected) * 100%
```

- **Baseline EDR:** 100% (tool detects all generated test events)
- **Post-poison EDR:** 0% (total blindness)
- **Post-restore EDR:** ~100% (tool recovers after fix/restart)

### M2: Alert Generation Rate (AGR)

Falco-specific metric measuring security alerts per sensitive operation.

```
AGR = alerts_generated / sensitive_operations_performed
```

### M3: Attack Complexity (AC)

| Dimension | Tracee | Tetragon | Falco |
|-----------|--------|----------|-------|
| Maps to modify | 1 | 2 | 1 |
| Fields to change | 2 | N/A (deletions) | 512 |
| Bytes modified | ~10 | ~770 (192 * 4B keys) | 512 |
| Commands needed | 1 | ~194 | ~512 |
| Time to execute | <1s | ~3s | ~2s |
| Enumeration needed | Yes (by ID) | No (pinned paths) | Yes (by ID) |

### M4: Stealth

| Indicator | Tracee | Tetragon | Falco |
|-----------|--------|----------|-------|
| Error in tool logs | No | No | No |
| Tool daemon crash | No | No | No |
| Health check failure | No | No | No |
| Kernel log entry | No | No | No |
| Audit trail | Only if audit enabled for bpf() syscall | Same | Same |

### M5: Reversibility

| Method | Tracee | Tetragon | Falco |
|--------|--------|----------|-------|
| Map value restore | Yes (write back original) | Partial (need PID repopulation) | Yes (write back 1s) |
| Tool restart | Full recovery | Full recovery | Full recovery |
| Automatic recovery | No (no integrity check) | No | No |
