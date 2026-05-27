# Responsible Disclosure

## 1. Nature of the Finding

BPF Map Poisoning is an **architectural weakness** in the eBPF subsystem's access model, not a specific software vulnerability in any individual tool. There is no CVE to assign because the behavior is by design: the kernel permits any process with `CAP_BPF` to modify any BPF map on the host, and no tool has implemented countermeasures.

This distinction affects the disclosure approach. Traditional vulnerability disclosure targets a specific vendor with a specific patch. Architectural weaknesses require coordinated engagement with multiple stakeholders: tool maintainers, kernel developers, and the broader security community.

## 2. Disclosure Channels

### 2.1 Tool Maintainers

| Tool | Maintainer Organization | Security Contact | Disclosure Method |
|------|------------------------|-------------------|-------------------|
| Tracee | Aqua Security | security@aquasec.com | Email with encrypted report |
| Tetragon | Cilium / Isovalent | security@cilium.io | Email with encrypted report |
| Falco | Falco Authors (CNCF) | cncf-falco-maintainers@lists.cncf.io | Email via CNCF security process |

Each disclosure includes:
- Description of the attack class
- Specific attack instance for the recipient's tool
- Proof-of-concept script
- Recommended mitigations
- Link to this repository (shared under embargo until public release)

### 2.2 Linux Kernel BPF Subsystem

| Channel | Contact | Purpose |
|---------|---------|---------|
| BPF mailing list | bpf@vger.kernel.org | Public discussion of BPF map access model improvements |
| Kernel security team | security@kernel.org | If kernel-level mitigations are proposed that require security review |

The kernel disclosure focuses on the architectural gap (lack of per-map access control) rather than the tool-specific attacks, as the kernel behavior is intentional and documented.

### 2.3 CNCF Security

As both Falco (graduated) and Tetragon (incubating) are CNCF projects, a consolidated disclosure to the CNCF security team provides coordination across projects:

| Channel | Contact |
|---------|---------|
| CNCF Security TAG | security@cncf.io |

## 3. Disclosure Timeline

| Date | Action | Status |
|------|--------|--------|
| 2026-05-27 | Initial disclosure to Tracee, Tetragon, and Falco security contacts | Planned |
| 2026-05-27 | Notification to CNCF Security TAG | Planned |
| +7 days | Follow-up if no acknowledgment received | -- |
| +30 days | Request status update from all parties | -- |
| +90 days | Public release (this repository) regardless of patch status | -- |
| +90 days | BPF mailing list discussion of architectural improvements | -- |
| Post-release | Conference presentation submission (academic venue) | -- |

The 90-day embargo period follows industry-standard coordinated disclosure practices (consistent with Google Project Zero, CERT/CC, and CNCF vulnerability disclosure policies).

## 4. Embargo Terms

During the embargo period:

- The full repository (including PoC scripts) is shared with tool maintainers under a non-public disclosure agreement.
- Tool maintainers are encouraged to develop and release mitigations before public disclosure.
- If a maintainer requests an extension beyond 90 days with evidence of active mitigation development, a reasonable extension (up to 14 additional days) will be considered.
- If the vulnerability is independently discovered and publicly disclosed by a third party, the embargo is immediately lifted.

## 5. Post-Disclosure

After public release:

- This repository is made public on GitHub.
- A blog post summarizing the findings is published.
- Conference submissions (academic or industry) are pursued.
- The BPF mailing list is engaged for discussion of kernel-level improvements.
- Mitigations implemented by tool maintainers are documented and credited in this repository.

## 6. Scope Clarification

This disclosure explicitly covers:

- The BPF Map Poisoning attack class (modifying another program's BPF maps to alter behavior)
- Three specific attack instances (Tracee config_map, Tetragon execve_calls/execve_map, Falco interesting_syscalls)
- The architectural observation that `CAP_BPF` provides unrestricted map access

This disclosure does **not** cover:

- Kernel vulnerabilities or bugs in the BPF subsystem
- Vulnerabilities in the tools' userspace components
- Other BPF attack surfaces (program loading, ring buffer manipulation, etc.) -- these are noted as future work but not disclosed as specific attacks

## 7. Researcher Contact

| Field | Value |
|-------|-------|
| Researcher | Azizcan Dastan |
| Organization | Milenium Security |
| Email | Available upon request |
| GitHub | [@azqzazq1](https://github.com/azqzazq1) |
| PGP | Available upon request for encrypted communication |

All communication regarding this disclosure should reference "BPF Map Poisoning - SunnyMapBPF" in the subject line.
