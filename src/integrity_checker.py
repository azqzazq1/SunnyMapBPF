#!/usr/bin/env python3
"""
SunnyMapBPF — BPF Map Integrity Checker

Demonstrates a defensive tool that periodically verifies the integrity
of security-critical BPF maps. This is one of the mitigations proposed
in the SunnyMapBPF research.

Monitors maps for unexpected modifications and alerts on detected tampering.

Requires: CAP_BPF or CAP_SYS_ADMIN
Usage: sudo python3 integrity_checker.py --tool tracee --interval 5
"""

import subprocess
import json
import sys
import argparse
import hashlib
import time
import signal

running = True


def handle_signal(sig, frame):
    global running
    running = False


signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)


def run_bpftool(*args):
    cmd = ["bpftool"] + list(args) + ["-j"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return None
    return json.loads(result.stdout)


def snapshot_map(map_id):
    data = run_bpftool("map", "dump", "id", str(map_id))
    if data is None:
        return None
    raw = json.dumps(data, sort_keys=True).encode()
    return hashlib.sha256(raw).hexdigest()


def snapshot_pinned_map(path):
    data = run_bpftool("map", "dump", "pinned", path)
    if data is None:
        return None
    raw = json.dumps(data, sort_keys=True).encode()
    return hashlib.sha256(raw).hexdigest()


def find_map_id(name, map_type=None):
    maps = run_bpftool("map", "list")
    if not maps:
        return None
    for m in maps:
        if name in m.get("name", ""):
            if map_type is None or m.get("type") == map_type:
                return m["id"]
    return None


WATCHLIST = {
    "tracee": [
        {"name": "config_map", "type": "array", "description": "Main configuration (enabled_policies)"},
        {"name": "sys_enter_tails", "type": "prog_array", "description": "Syscall enter tail calls"},
        {"name": "sys_exit_tails", "type": "prog_array", "description": "Syscall exit tail calls"},
    ],
    "tetragon": [
        {"name": "execve_calls", "pinned": "/sys/fs/bpf/tetragon/__base__/event_execve/execve_calls",
         "description": "Exec tail call prog_array"},
        {"name": "tg_conf_map", "pinned": "/sys/fs/bpf/tetragon/tg_conf_map",
         "description": "Global agent configuration"},
    ],
    "falco": [
        {"name": "interesting_sys", "type": "array", "description": "Syscall interest flags"},
    ],
}


def monitor(tool, interval):
    watchlist = WATCHLIST.get(tool)
    if not watchlist:
        print(f"No watchlist for tool: {tool}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] SunnyMapBPF Integrity Checker — monitoring {tool}")
    print(f"[*] Check interval: {interval}s")
    print()

    # Take initial snapshots
    snapshots = {}
    for entry in watchlist:
        name = entry["name"]
        if "pinned" in entry:
            snap = snapshot_pinned_map(entry["pinned"])
        else:
            map_id = find_map_id(name, entry.get("type"))
            if map_id is None:
                print(f"[!] Map not found: {name}")
                continue
            entry["id"] = map_id
            snap = snapshot_map(map_id)

        if snap:
            snapshots[name] = snap
            print(f"[+] Baseline: {name} = {snap[:16]}...")
        else:
            print(f"[!] Failed to snapshot: {name}")

    print()
    print("[*] Monitoring started. Press Ctrl+C to stop.")
    print()

    alert_count = 0
    check_count = 0

    while running:
        time.sleep(interval)
        check_count += 1

        for entry in watchlist:
            name = entry["name"]
            if name not in snapshots:
                continue

            if "pinned" in entry:
                current = snapshot_pinned_map(entry["pinned"])
            elif "id" in entry:
                current = snapshot_map(entry["id"])
            else:
                continue

            if current is None:
                print(f"[!] Check #{check_count}: Failed to read {name}")
                continue

            if current != snapshots[name]:
                alert_count += 1
                print(f"[ALERT #{alert_count}] Map TAMPERED: {name}")
                print(f"  Expected: {snapshots[name][:16]}...")
                print(f"  Current:  {current[:16]}...")
                print(f"  Description: {entry['description']}")
                print()
                snapshots[name] = current

    print()
    print(f"[*] Stopped. Checks: {check_count}, Alerts: {alert_count}")


def main():
    parser = argparse.ArgumentParser(description="SunnyMapBPF — BPF Map Integrity Checker")
    parser.add_argument("--tool", required=True, choices=["tracee", "tetragon", "falco"])
    parser.add_argument("--interval", type=int, default=5, help="Check interval in seconds (default: 5)")
    args = parser.parse_args()

    monitor(args.tool, args.interval)


if __name__ == "__main__":
    main()
