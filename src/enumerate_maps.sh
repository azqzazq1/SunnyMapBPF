#!/bin/bash
# SunnyMapBPF — Quick Map Enumeration
# Lists all BPF maps and highlights security-critical ones

set -euo pipefail

echo "============================================================"
echo "  SunnyMapBPF — BPF Map Enumeration"
echo "============================================================"
echo ""

echo "=== All BPF Maps ==="
bpftool map list 2>/dev/null || { echo "ERROR: bpftool failed. Need CAP_BPF."; exit 1; }

echo ""
echo "=== Security-Critical Maps (by name pattern) ==="
bpftool map list -j 2>/dev/null | python3 -c "
import json, sys

critical_patterns = [
    'config_map', 'policies_config', 'enabled_policies',
    'interesting_sys', 'sc_set',
    'execve_map', 'tg_conf_map', 'policy_conf', 'policy_filter',
    'enforcer_data', 'execve_calls',
    'sys_enter_tails', 'sys_exit_tails',
    'syscall_exit_ta', 'syscall_enter_ta',
    'events_map', 'containers_map', 'task_info_map', 'proc_info_map',
]

maps = json.load(sys.stdin)
found = []
for m in maps:
    name = m.get('name', '')
    for pat in critical_patterns:
        if pat in name:
            found.append(m)
            break

if not found:
    print('  No security-critical maps detected (tools may not be running)')
else:
    for m in found:
        frozen = 'FROZEN' if m.get('frozen', False) else 'WRITABLE'
        print(f'  ID:{m[\"id\"]:>5} {m.get(\"name\",\"?\"):<25} {m[\"type\"]:<18} [{frozen}]')
    print(f'\n  Total: {len(found)} security-critical maps, all WRITABLE')
"

echo ""
echo "=== Tetragon Pinned Maps ==="
if [ -d /sys/fs/bpf/tetragon ]; then
    find /sys/fs/bpf/tetragon -type f 2>/dev/null | while read f; do
        echo "  $f"
    done
else
    echo "  Tetragon not running (no pinned maps)"
fi

echo ""
echo "=== Protection Summary ==="
bpftool map list -j 2>/dev/null | python3 -c "
import json, sys
maps = json.load(sys.stdin)
total = len(maps)
# Check if any map has frozen flag
frozen = sum(1 for m in maps if m.get('frozen', False))
print(f'  Total maps: {total}')
print(f'  Frozen (bpf_map_freeze): {frozen}')
print(f'  Unprotected: {total - frozen}')
if frozen == 0:
    print('  WARNING: Zero maps are frozen. All maps are writable by CAP_BPF.')
"
