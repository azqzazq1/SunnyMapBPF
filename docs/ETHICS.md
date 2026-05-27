# Research Ethics Statement

## 1. Testing Environment

All experiments described in this research were conducted exclusively in controlled laboratory environments:

- **Hardware:** Dedicated research workstation under the sole control of the researcher
- **Software:** Docker containers running target tools on an isolated Linux host
- **Network:** No connection to production systems, customer environments, or third-party infrastructure
- **Data:** No real user data, production credentials, or sensitive information was involved at any stage

No production system, cloud deployment, or third-party infrastructure was accessed, tested, or affected by this research.

## 2. Scope of Testing

The experiments were limited to:

- Deploying open-source security tools (Falco, Tracee, Tetragon) in their documented Docker configurations on local hardware
- Modifying BPF maps belonging to these self-deployed instances
- Observing the effect on event generation and detection capabilities
- Restoring original state after each experiment

At no point did the research involve:

- Accessing or modifying BPF maps belonging to tools deployed by other users or organizations
- Testing against production security monitoring infrastructure
- Attempting to evade detection in any environment where the monitoring is relied upon for actual security
- Exfiltrating data, establishing persistence, or performing any post-exploitation action beyond observing the blind spot

## 3. Responsible Disclosure Commitment

This research follows responsible disclosure principles as documented in RESPONSIBLE_DISCLOSURE.md:

- All affected tool maintainers are notified before public release
- A 90-day embargo period provides time for mitigation development
- The disclosure includes specific, actionable mitigation recommendations
- The researcher is available to assist maintainers in understanding and addressing the findings

The goal of disclosure is to improve the security posture of the eBPF monitoring ecosystem, not to enable attacks against deployed systems.

## 4. Dual-Use Awareness

We acknowledge that this research has dual-use potential:

**Defensive value:**
- Identifies a previously undocumented weakness in widely deployed security tools
- Provides tool maintainers with specific information needed to develop mitigations
- Raises awareness of BPF map integrity as a security-relevant property
- Contributes to the maturation of the eBPF security ecosystem

**Offensive potential:**
- The techniques described could be used by adversaries to evade detection in real environments
- The PoC scripts lower the barrier to executing these attacks
- The cross-tool applicability means the findings affect a large portion of the eBPF security ecosystem

We believe the defensive value outweighs the offensive risk for the following reasons:

1. **The underlying capability is not novel.** `bpftool map update` and the `bpf()` syscall are documented kernel interfaces. Any attacker with `CAP_BPF` already has access to these interfaces. This research identifies specific high-value targets (which maps to modify) but does not introduce new exploitation primitives.

2. **The vulnerability is architectural, not secret.** Security through obscurity (hoping attackers do not realize they can modify BPF maps) is not a viable long-term strategy. Public disclosure enables defenders to act.

3. **Mitigations exist.** The defensive considerations outlined in this research are implementable by tool maintainers without kernel changes. The research provides both the problem and concrete steps toward solutions.

4. **Precedent.** Similar disclosure of security tool evasion techniques (EDR unhooking, ETW patching, antivirus bypass) has consistently led to improved defenses in those domains. The eBPF security ecosystem benefits from the same adversarial pressure.

## 5. Research Motivation

This research was motivated by a genuine interest in improving the security of the Linux eBPF ecosystem. The researcher's goals are:

- **Advance understanding** of the eBPF security model's limitations
- **Improve tool resilience** by identifying and reporting weaknesses before adversaries exploit them
- **Contribute to kernel development** by providing empirical evidence for BPF map access control improvements
- **Inform the security community** about the gap between eBPF security promises and current implementation reality

This research is not motivated by commercial interest, competitive advantage against the tested tools, or any intent to harm users of these tools.

## 6. Commitment to Ongoing Responsibility

The researcher commits to:

- **Monitoring for misuse.** If the published techniques are observed being used in malicious attacks, the researcher will cooperate with affected parties and law enforcement as appropriate.
- **Updating mitigations.** As tool maintainers implement defenses, this repository will be updated to document the effectiveness of those defenses and any remaining gaps.
- **Responsible amplification.** Public presentations and publications of this research will emphasize the defensive aspects and mitigations alongside the attack techniques.
- **Community engagement.** The researcher will engage constructively with tool maintainers, kernel developers, and the security community to promote adoption of mitigations.

## 7. Compliance with Research Norms

This research adheres to:

- **The Menlo Report** principles for ethical ICT research: beneficence, respect for persons, justice, and respect for law and public interest
- **ACM Code of Ethics** guidelines on vulnerability research and disclosure
- **FIRST** (Forum of Incident Response and Security Teams) guidelines on coordinated vulnerability disclosure
- The spirit of open-source contribution: improving shared infrastructure for the benefit of all users
