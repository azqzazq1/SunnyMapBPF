# References

## eBPF Foundation and Architecture

1. **Vieira, M. A., Castanho, M. S., Pac&iacute;fico, R. D., Santos, E. R., J&uacute;nior, E. P., & Vieira, L. F.** (2020). "Fast Packet Processing with eBPF and XDP: Concepts, Code, Challenges, and Applications." *ACM Computing Surveys*, 53(1), 1-36. https://doi.org/10.1145/3371038

2. **Gregg, B.** (2019). "BPF Performance Tools: Linux System and Application Observability." Addison-Wesley Professional. ISBN: 978-0136554820.

3. **Scholz, D., Raumer, D., Emmerich, P., Kurber, A., Lesiak, K., & Carle, G.** (2018). "Performance Implications of Packet Filtering with Linux eBPF." *IEEE Conference on Network Protocols (ICNP)*. https://doi.org/10.1109/LCN.2018.8638234

4. **Calavera, D., & Fontana, L.** (2020). "Linux Observability with BPF." O'Reilly Media. ISBN: 978-1492050209.

5. **Cilium Authors.** "BPF and XDP Reference Guide." Cilium Documentation. https://docs.cilium.io/en/latest/bpf/

## BPF Maps and Kernel Internals

6. **Linux Kernel Documentation.** "BPF Design Q&A." https://www.kernel.org/doc/html/latest/bpf/bpf_design_QA.html

7. **Linux Kernel Documentation.** "BPF Map Types." https://www.kernel.org/doc/html/latest/bpf/maps.html

8. **Starovoitov, A.** (2019). "bpf: add bpf_map_freeze() helper." Linux kernel commit 87df15de441b ("bpf: add bpf_map_freeze() helper"). https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=87df15de441b

9. **Starovoitov, A.** (2019). "bpf: introduce BPF token object." Linux kernel patch series. https://lore.kernel.org/bpf/

10. **Linux Kernel Documentation.** "CAP_BPF and unprivileged BPF." https://www.kernel.org/doc/html/latest/bpf/bpf_licensing.html

11. **Song, Y.** (2019). "bpf: add BPF_F_RDONLY_PROG and BPF_F_WRONLY_PROG." Linux kernel commit 591fe9888d78. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=591fe9888d78

## Security Monitoring Tools

### Falco

12. **Falco Authors.** "The Falco Project - Cloud Native Runtime Security." https://falco.org/

13. **Falco Authors.** "Falco Drivers: kernel module, eBPF probe, and modern BPF." https://falco.org/docs/event-sources/drivers/

14. **Grasso, L., & Dalzotto, L.** (2022). "Falco: Practical Runtime Threat Detection for Cloud-Native." *CNCF Blog*. https://www.cncf.io/blog/

15. **Sysdig, Inc.** "Falco libs: BPF probe source code." https://github.com/falcosecurity/libs/tree/master/driver/bpf

### Tracee

16. **Aqua Security.** "Tracee: Linux Runtime Security and Forensics using eBPF." https://github.com/aquasecurity/tracee

17. **Aqua Security.** "Tracee Documentation: Architecture." https://aquasecurity.github.io/tracee/latest/docs/architecture/

18. **Fishbein, I., & Schendel, P.** (2021). "Tracee: Runtime Security and Forensics using eBPF." *Aqua Security Blog*. https://blog.aquasec.com/

### Tetragon

19. **Cilium Authors.** "Tetragon: eBPF-based Security Observability and Runtime Enforcement." https://github.com/cilium/tetragon

20. **Cilium Authors.** "Tetragon Documentation: Concepts." https://tetragon.io/docs/concepts/

21. **Borkmann, D., & Graf, T.** (2022). "Tetragon: Real-time, eBPF-based Security Observability and Runtime Enforcement." *Isovalent Blog*. https://isovalent.com/blog/

## Linux Capabilities and Access Control

22. **Linux man-pages.** "capabilities(7) -- overview of Linux capabilities." https://man7.org/linux/man-pages/man7/capabilities.7.html

23. **Hallyn, S.** (2020). "CAP_BPF and CAP_PERFMON." Linux kernel commit 2c78ee898d8f. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=2c78ee898d8f

24. **Linux Kernel Documentation.** "BPF token and BPF FS-based delegation." https://www.kernel.org/doc/html/latest/bpf/bpf_token.html

## Related Attack Research

25. **Falcone, R., & Lancaster, T.** (2023). "Bring Your Own Vulnerable Driver (BYOVD) Attacks." *Palo Alto Networks Unit 42*. https://unit42.paloaltonetworks.com/

26. **Patel, A.** (2022). "Blinding EDR on Windows." *MDSec Research*. https://www.mdsec.co.uk/

27. **Palantir Technologies.** (2022). "Tampering with Windows Event Tracing: Background, Offense, and Defense." https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63

28. **Leibowitz, J.** (2023). "Evil eBPF: Practical Abuses of an In-Kernel Bytecode Runtime." *DEF CON 31*. https://defcon.org/

29. **Guillaume, F.** (2021). "With Friends Like eBPF, Who Needs Enemies?" *BlackHat USA 2021*. https://www.blackhat.com/us-21/briefings/schedule/

30. **Fournier, G., & Afchain, S.** (2021). "eBPF, I thought we were friends!" *DEF CON 29*. https://defcon.org/

## MITRE ATT&CK

31. **MITRE Corporation.** "T1562.001 - Impair Defenses: Disable or Modify Tools." MITRE ATT&CK. https://attack.mitre.org/techniques/T1562/001/

32. **MITRE Corporation.** "T1562.006 - Impair Defenses: Indicator Blocking." MITRE ATT&CK. https://attack.mitre.org/techniques/T1562/006/

33. **MITRE Corporation.** "T1014 - Rootkit." MITRE ATT&CK. https://attack.mitre.org/techniques/T1014/

34. **MITRE Corporation.** "T1070 - Indicator Removal." MITRE ATT&CK. https://attack.mitre.org/techniques/T1070/

## Compliance and Standards

35. **AICPA.** "SOC 2 - SOC for Service Organizations: Trust Services Criteria." https://www.aicpa.org/

36. **PCI Security Standards Council.** "PCI DSS v4.0." https://www.pcisecuritystandards.org/

37. **NIST.** "SP 800-53 Rev. 5: Security and Privacy Controls for Information Systems and Organizations." https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final

## eBPF Security Analysis

38. **He, D., Ahmad, S., Wang, S., & Song, D.** (2023). "On the Verifier Complexity of eBPF Programs." *USENIX Security Symposium*. https://www.usenix.org/conference/

39. **Nelson, L., Van Geffen, J., Torlak, E., & Wang, X.** (2020). "Specification and Verification in the Field: Applying Formal Methods to BPF Just-in-Time Compilers in the Linux Kernel." *OSDI 2020*. https://www.usenix.org/conference/osdi20

40. **Jia, J., Zhu, Y., Williams, D., Arcangeli, A., Canella, C., Gruss, D., & Xu, T.** (2023). "Kernel Extension Verification is Untenable." *HotOS 2023*. https://dl.acm.org/

## General Systems Security

41. **Anderson, R.** (2020). "Security Engineering: A Guide to Building Dependable Distributed Systems." 3rd Edition. Wiley. ISBN: 978-1119642787.

42. **Saltzer, J. H., & Schroeder, M. D.** (1975). "The Protection of Information in Computer Systems." *Proceedings of the IEEE*, 63(9), 1278-1308. https://doi.org/10.1109/PROC.1975.9939
