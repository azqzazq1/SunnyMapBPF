# 10. Conclusion

This paper has identified, formalized, and empirically demonstrated BPF map poisoning as a novel evasion technique against eBPF-based security monitoring tools. By modifying the BPF maps that store runtime configuration and state for Falco, Tracee, and Tetragon, an attacker with `CAP_BPF` can achieve complete suppression of security event generation using only the legitimate `bpf(2)` syscall interface.

The attack requires no BPF program loading, no verifier bypass, and no kernel exploit. It operates entirely within the documented BPF API, exploiting the absence of map-level access control in the kernel and the failure of security tools to apply available protection mechanisms such as `bpf_map_freeze()`. Each attack executes via a single command (or a small number of commands), takes effect within one BPF program invocation cycle, and produces no alerts or log entries from the targeted tool.

Our evaluation against production releases demonstrated complete event suppression across all three tools: Tracee v0.24.1 (16 to 0 events), Tetragon v1.4.0 (14+ to 0 events), and Falco (1+ to 0 alerts). All attacks are reversible, confirming that the mechanism is data-plane manipulation rather than code corruption.

These findings reveal a structural gap in the eBPF security ecosystem's threat model. The implicit assumption that kernel-resident BPF map contents are protected from external tampering is incorrect: the `bpf(2)` syscall provides any `CAP_BPF` process with unrestricted read/write access to all maps on the system. Until security tools adopt map freezing, runtime integrity verification, and capability-scoped access control, BPF map poisoning remains a viable single-command technique for rendering eBPF-based security monitoring completely ineffective.
