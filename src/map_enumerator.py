#!/usr/bin/env python3
"""
SunnyMapBPF — BPF Map Enumerator

Enumerates all BPF maps on the system and identifies security-critical maps
belonging to known eBPF security tools (Falco, Tracee, Tetragon).

Requires: CAP_BPF or CAP_SYS_ADMIN
Usage: sudo python3 map_enumerator.py [--json] [--tool tracee|tetragon|falco]
"""

import subprocess
import json
import sys
import argparse

TOOL_SIGNATURES = {
    "tracee": {
        "map_names": [
            "config_map", "policies_config", "sys_enter_tails", "sys_exit_tails",
            "events_map", "task_info_map", "proc_info_map", "containers_map",
            "sys_enter_init_tail", "sys_exit_init_tail", "sys_enter_submit_tail",
            "sys_exit_submit_tail", "events_map_version", "policies_config_version",
        ],
        "critical_maps": {
            "config_map": "Contains tracee_pid (self-exclusion) and enabled_policies (policy control)",
            "policies_config": "Versioned policy configuration — controls all scope filtering",
            "sys_enter_tails": "PROG_ARRAY for syscall enter handlers — delete = disable syscall monitoring",
            "sys_exit_tails": "PROG_ARRAY for syscall exit handlers",
            "events_map": "Per-event configuration — controls which events are submitted",
            "containers_map": "Container state tracking — delete = remove container awareness",
            "task_info_map": "Per-thread info — poisoning breaks process attribution",
            "proc_info_map": "Per-process info — poisoning breaks process tree",
        }
    },
    "tetragon": {
        "map_names": [
            "execve_map", "tg_conf_map", "tcpmon_map", "tg_stats_map",
            "execve_calls", "tg_execve_joined_info_map", "execve_map_stats",
            "tg_mbset_map", "tg_errmetrics_map",
        ],
        "critical_maps": {
            "execve_map": "Process tracking (PID->info) — clear = all processes invisible",
            "execve_calls": "PROG_ARRAY for exec tail calls — delete = break exec pipeline",
            "tg_conf_map": "Global config including agent PID — modify = confuse agent identity",
            "tcpmon_map": "Perf/ring buffer for event delivery — corrupt = break event delivery",
        },
        "pinned_path": "/sys/fs/bpf/tetragon/"
    },
    "falco": {
        "map_names": [
            "interesting_sys", "syscall_exit_ta", "syscall_exit_ex",
            "auxiliary_maps", "counter_maps", "ringbuf_maps",
            "capture_setting", "extra_sched_pro",
        ],
        "critical_maps": {
            "interesting_sys": "ARRAY controlling which syscalls are monitored — zero = skip all",
            "syscall_exit_ta": "PROG_ARRAY for syscall exit handlers — delete = disable processing",
            "syscall_exit_ex": "PROG_ARRAY for extra syscall handlers",
            "capture_setting": "Capture configuration — modify = disable event capture",
        }
    }
}


def run_bpftool(*args):
    cmd = ["bpftool"] + list(args) + ["-j"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return None
    return json.loads(result.stdout)


def enumerate_maps():
    maps = run_bpftool("map", "list")
    if maps is None:
        print("ERROR: Failed to enumerate BPF maps. Do you have CAP_BPF?", file=sys.stderr)
        sys.exit(1)
    return maps


def identify_tool(map_entry):
    name = map_entry.get("name", "")
    for tool, sig in TOOL_SIGNATURES.items():
        for known_name in sig["map_names"]:
            if known_name in name or name in known_name:
                return tool
    return None


def classify_map(map_entry, tool):
    name = map_entry.get("name", "")
    if tool and tool in TOOL_SIGNATURES:
        for crit_name, desc in TOOL_SIGNATURES[tool]["critical_maps"].items():
            if crit_name in name or name in crit_name:
                return {"critical": True, "description": desc}
    return {"critical": False, "description": ""}


def check_protection(map_entry):
    flags = map_entry.get("flags", 0)
    frozen = bool(flags & 0x10)  # BPF_F_RDONLY_PROG in map flags
    return {
        "frozen": frozen,
        "rdonly_prog": bool(flags & 0x80),
        "wronly_prog": bool(flags & 0x100),
        "any_protection": frozen or bool(flags & 0x80) or bool(flags & 0x100)
    }


def main():
    parser = argparse.ArgumentParser(description="SunnyMapBPF — BPF Map Enumerator")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--tool", choices=["tracee", "tetragon", "falco"], help="Filter by tool")
    parser.add_argument("--critical-only", action="store_true", help="Show only security-critical maps")
    args = parser.parse_args()

    maps = enumerate_maps()
    results = []

    for m in maps:
        tool = identify_tool(m)
        if args.tool and tool != args.tool:
            continue

        classification = classify_map(m, tool)
        if args.critical_only and not classification["critical"]:
            continue

        protection = check_protection(m)

        entry = {
            "id": m.get("id"),
            "name": m.get("name", ""),
            "type": m.get("type", ""),
            "key_size": m.get("bytes_key", m.get("key_size", 0)),
            "value_size": m.get("bytes_value", m.get("value_size", 0)),
            "max_entries": m.get("max_entries", 0),
            "tool": tool,
            "critical": classification["critical"],
            "description": classification["description"],
            "protection": protection,
        }
        results.append(entry)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"{'ID':>6} {'Name':<25} {'Type':<18} {'Tool':<10} {'Critical':<9} {'Protected':<10}")
        print("-" * 90)
        for r in results:
            crit = "YES" if r["critical"] else ""
            prot = "YES" if r["protection"]["any_protection"] else "NO"
            tool = r["tool"] or ""
            print(f"{r['id']:>6} {r['name']:<25} {r['type']:<18} {tool:<10} {crit:<9} {prot:<10}")
            if r["critical"]:
                print(f"       -> {r['description']}")

        # Summary
        total = len(results)
        critical = sum(1 for r in results if r["critical"])
        protected = sum(1 for r in results if r["protection"]["any_protection"])
        tools_found = set(r["tool"] for r in results if r["tool"])

        print(f"\nSummary: {total} maps found, {critical} security-critical, {protected} protected")
        print(f"Tools detected: {', '.join(tools_found) if tools_found else 'none'}")
        if critical > 0 and protected == 0:
            print("WARNING: All security-critical maps are UNPROTECTED")


if __name__ == "__main__":
    main()
