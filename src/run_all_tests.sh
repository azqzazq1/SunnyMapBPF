#!/bin/bash
# SunnyMapBPF — Run All PoC Tests
# Executes all three tool-specific PoC scripts sequentially

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
POC_DIR="$SCRIPT_DIR/../poc"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo "============================================================"
echo "  SunnyMapBPF — Full Test Suite"
echo "  BPF Map Poisoning Cross-Tool Verification"
echo "============================================================"
echo ""

PASS=0
FAIL=0

for poc in tracee tetragon falco; do
    SCRIPT="$POC_DIR/poc-${poc}-blindness.sh"
    if [ ! -f "$SCRIPT" ]; then
        echo -e "${RED}[-] Missing: $SCRIPT${NC}"
        FAIL=$((FAIL + 1))
        continue
    fi

    echo -e "${CYAN}[*] Testing $poc...${NC}"
    echo "------------------------------------------------------------"

    if bash "$SCRIPT"; then
        echo -e "${GREEN}[+] $poc: PASSED${NC}"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}[-] $poc: FAILED${NC}"
        FAIL=$((FAIL + 1))
    fi

    echo ""
done

echo "============================================================"
echo "  Results: $PASS passed, $FAIL failed (of 3)"
echo "============================================================"

exit $FAIL
