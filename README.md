```
  ____                          __  __             ____  ____  _____ 
 / ___| _   _ _ __  _ __  _   _|  \/  | __ _ _ __ | __ )|  _ \|  ___|
 \___ \| | | | '_ \| '_ \| | | | |\/| |/ _` | '_ \|  _ \| |_) | |_   
  ___) | |_| | | | | | | | |_| | |  | | (_| | |_) | |_) |  __/|  _|  
 |____/ \__,_|_| |_|_| |_|\__, |_|  |_|\__,_| .__/|____/|_|   |_|    
                           |___/             |_|                       
  BPF Map State Poisoning Against eBPF Runtime Security Monitors
```

> **Research artifact, not a production offensive tool.** This repository contains empirical research into a telemetry trust boundary weakness in eBPF-based security monitors. It is published to help tool maintainers harden their BPF map state and to inform the community about a class of same-privilege tampering that, to our knowledge, has not been systematically explored before.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Research: Active](https://img.shields.io/badge/Research-Active-brightgreen.svg)]()
[![Status: Published](https://img.shields.io/badge/Status-Published-blue.svg)]()

---

## Abstract

eBPF-based security monitoring tools rely on BPF maps to store runtime state: policy configurations, process tracking tables, syscall interest sets, and event routing logic. These maps reside in kernel memory but are writable by any process holding `CAP_BPF` — a capability that is privileged but realistically available in post-exploitation scenarios including container escape, kernel privilege escalation, and misconfigured Kubernetes workloads.

This research demonstrates that, to our knowledge, **none of the three major eBPF security monitors** (Falco, Tracee, Tetragon) employ `bpf_map_freeze()`, `BPF_F_RDONLY_PROG`, or runtime map integrity verification on their security-critical maps. A same-privilege process can modify these maps to silently suppress all telemetry, creating a gap in the trust boundary between the monitoring tool and the kernel BPF subsystem.

We empirically validate this across all three tools with reproducible experiments showing that map state poisoning reduces event detection from baseline levels to zero.

## Empirical Results

| Tool | Version | Map Target | Primitive | Baseline | Post-Modification |
|------|---------|------------|-----------|----------|-------------------|
| **Tracee** | v0.24.1 | `config_map` | `enabled_policies=0` + version invalidation | 16 events | **0 events** |
| **Tetragon** | v1.4.0 | `execve_calls` + `execve_map` | prog_array entry deletion + process table clear | 14+ events | **0 events** |
| **Falco** | latest | `interesting_syscalls` | 512-entry array zeroed | 1+ alerts | **0 alerts** |

Observations across all three tools:

- **Silent**: no error logs, no health check failures, no daemon crashes
- **Immediate**: takes effect within the next BPF program invocation
- **Reversible**: the tool resumes normal operation after map state is restored or the tool is restarted
- **Same-privilege**: requires `CAP_BPF`, which is privileged but realistically obtainable in misconfigured or compromised environments

## Mitigation Summary

The underlying issue is architectural: the Linux BPF subsystem does not provide per-map access control. However, several defense-in-depth measures can significantly raise the bar:

| Mitigation | Layer | Feasibility | Notes |
|-----------|-------|-------------|-------|
| `bpf_map_freeze()` on config maps after initialization | Tool | **High** | Prevents all userspace writes; permanent (no unfreeze), so only suitable for maps that don't change at runtime |
| `BPF_F_RDONLY_PROG` / `BPF_F_WRONLY_PROG` flags | Tool | **Medium** | Prevents BPF-side writes, but does **not** prevent userspace writes via `bpf()` syscall |
| Periodic map integrity verification (hash-based canaries) | Tool | **High** | Detects tampering with TOCTOU caveat; attacker can restore between checks |
| Heartbeat / liveness canary in BPF maps | Tool | **Medium** | BPF program writes a rotating value; userspace validates. Adds overhead but detects pipeline breakage |
| Restrict `CAP_BPF` distribution | Operator | **High** | Minimize processes with BPF access; use seccomp to block `bpf()` for non-monitoring workloads |
| External `bpf()` syscall auditing | Operator | **Medium** | Monitor `bpf(BPF_MAP_UPDATE_ELEM)` / `BPF_MAP_DELETE_ELEM` calls via auditd or a separate tracing layer |
| Kernel-level per-map owner binding | Kernel | **Low** | Does not exist today; would require kernel patches to restrict map writes to the loading process |
| BPF token scoping (kernel 6.9+) | Kernel | **Low** | Scopes BPF operations to a delegation context; too new for broad adoption |

See [DEFENSIVE_CONSIDERATIONS.md](docs/DEFENSIVE_CONSIDERATIONS.md) for detailed analysis of each mitigation.

## Quick Start

### Research Tool

**`sunnymapbpf.py`** automates the map discovery and state modification workflow described in the paper. It is intended for controlled testing in lab environments:

```bash
# Scan: enumerate security-critical BPF maps (read-only, no modifications)
sudo python3 sunnymapbpf.py --scan

# Reproduce the findings against a specific tool (in a test environment)
sudo python3 sunnymapbpf.py --target tracee

# Run against all detected tools
sudo python3 sunnymapbpf.py
```

### Prerequisites

- Linux kernel 5.8+ with BPF support
- `bpftool` (v7.0+)
- `python3`
- `CAP_BPF` or `CAP_SYS_ADMIN`
- Docker (for PoC scripts that deploy target tools)

### Reproducible PoC Scripts

Each PoC deploys the target tool, establishes a baseline, applies the map modification, verifies the result, and restores normal operation:

```bash
git clone https://github.com/azqzazq1/SunnyMapBPF.git
cd SunnyMapBPF

sudo bash poc/poc-tracee-blindness.sh      # Tracee
sudo bash poc/poc-tetragon-blindness.sh    # Tetragon
sudo bash poc/poc-falco-blindness.sh       # Falco
```

See [REPRODUCIBILITY.md](docs/REPRODUCIBILITY.md) for detailed reproduction instructions and troubleshooting.

## Repository Structure

```
SunnyMapBPF/
├── sunnymapbpf.py              # Research tool: auto-detect + map state modification
├── README.md
├── LICENSE
├── docs/                       # Research documentation
│   ├── ABSTRACT.md             # Academic abstract
│   ├── PROBLEM_STATEMENT.md    # Formal problem statement
│   ├── THREAT_MODEL.md         # Attacker model and scope
│   ├── BACKGROUND.md           # eBPF subsystem, BPF maps, tool architectures
│   ├── METHODOLOGY.md          # Research methodology
│   ├── RESULTS.md              # Empirical results
│   ├── DISCUSSION.md           # Analysis and implications
│   ├── DEFENSIVE_CONSIDERATIONS.md
│   ├── RESPONSIBLE_DISCLOSURE.md
│   └── ...                     # + ETHICS, LIMITATIONS, REFERENCES, etc.
├── poc/                        # Reproducible PoC scripts
│   ├── poc-tracee-blindness.sh
│   ├── poc-tetragon-blindness.sh
│   └── poc-falco-blindness.sh
├── src/                        # Supporting tools (enumerator, integrity checker)
├── paper/                      # Academic paper sections (00–10)
├── related-work/               # Literature survey (11 topic areas)
├── experiments/                # Raw experimental logs
├── results/                    # Cross-tool comparison data
├── evaluation/                 # Evaluation metrics
└── figures/                    # Diagrams and visualizations
```

## Documentation

| Document | Description |
|----------|-------------|
| [ABSTRACT.md](docs/ABSTRACT.md) | Formal academic abstract |
| [PROBLEM_STATEMENT.md](docs/PROBLEM_STATEMENT.md) | The map state integrity gap in eBPF monitoring |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | Attacker capabilities and realistic scenarios |
| [BACKGROUND.md](docs/BACKGROUND.md) | eBPF subsystem, BPF maps, and tool architectures |
| [METHODOLOGY.md](docs/METHODOLOGY.md) | Five-phase research methodology |
| [RESULTS.md](docs/RESULTS.md) | Per-tool and cross-tool empirical results |
| [DISCUSSION.md](docs/DISCUSSION.md) | Architectural root cause and ecosystem implications |
| [DEFENSIVE_CONSIDERATIONS.md](docs/DEFENSIVE_CONSIDERATIONS.md) | Mitigation recommendations for maintainers and operators |
| [SECURITY_IMPLICATIONS.md](docs/SECURITY_IMPLICATIONS.md) | Compliance and trust model implications |
| [LIMITATIONS.md](docs/LIMITATIONS.md) | Scope limitations and future work |
| [RESPONSIBLE_DISCLOSURE.md](docs/RESPONSIBLE_DISCLOSURE.md) | Disclosure timeline |
| [ETHICS.md](docs/ETHICS.md) | Research ethics statement |

## Responsible Disclosure

This research was conducted under responsible disclosure principles. The techniques described require `CAP_BPF`, a capability that already grants significant kernel-level access. The contribution of this work is demonstrating that current eBPF security tools do not defend their own runtime state against same-privilege tampering — a gap that, to our knowledge, has not been systematically documented.

Disclosure contacts:
- **Tracee**: security@aquasec.com
- **Tetragon**: security@cilium.io
- **Falco**: cncf-falco-maintainers@lists.cncf.io
- **Linux kernel BPF**: bpf@vger.kernel.org

## Citation

```bibtex
@misc{dastan2026sunnymapbpf,
  title     = {SunnyMapBPF: BPF Map State Poisoning Against eBPF Runtime Security Monitors},
  author    = {Da\c{s}tan, Azizcan},
  year      = {2026},
  url       = {https://github.com/azqzazq1/SunnyMapBPF},
  note      = {Empirical analysis of writable BPF map state as a telemetry trust
               boundary weakness in Falco, Tracee, and Tetragon}
}
```

## Author

**Azizcan Dastan**
- [LinkedIn](https://www.linkedin.com/in/azqzazq/)
- [GitHub](https://github.com/azqzazq1)

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
