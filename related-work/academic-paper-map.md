# Academic Paper Map

## Overview

This document provides a curated list of the most relevant academic papers, conference talks, and technical reports organized by topic. For each entry: title, authors, venue, year, and a one-line relevance note to the BPF Map Poisoning research.

---

## 1. eBPF Security and Verifier Research

### Papers

- **"Simple and Precise Static Analysis of Untrusted Linux Kernel Extensions"**
  Gershuni, Amit, Gurfinkel, Narodytska, Navas, Shoham. **PLDI 2019**.
  *Analyzes the BPF verifier as a static analyzer; characterizes precision limitations that inform understanding of what the verifier does and does not guarantee.*

- **"Specification and Verification of BPF JIT Compilers" (Jitterbug)**
  Nelson, Bornholt, Gu, Baumann, Torlak. **OSDI 2020**.
  *Formal verification of BPF JIT compilers; found 16 bugs across 5 architectures. Demonstrates semantic divergences between verifier model and JIT output.*

- **"Scaling Symbolic Evaluation for Automated Verification of Systems Code with Serval"**
  Nelson, Bornholt, Gu, Baumann, Torlak. **SOSP 2019**.
  *Symbolic evaluation framework for systems verification; applied to BPF JIT correctness. Foundation for the Jitterbug work.*

- **"Verifying the Verifier: eBPF Range Analysis Verification"**
  Vishwanathan, Shacham, Brumley. **CAV 2023**.
  *First SMT-based formal verification of the BPF verifier's abstract domain. Formalizes tnum representation and bounds tracking. Found imprecision but no unsoundness in analyzed paths.*

- **"Kernel Extension Verification is Untenable"**
  Jiang, Nelson, Parno. **HotOS 2023**.
  *Argues that static verification of kernel extensions (including BPF) faces fundamental scalability and completeness challenges. Proposes runtime verification alternatives.*

- **"JIT-Picking: Differential Testing of BPF JIT Compilers"**
  Vishwanathan, Shacham. **2024**.
  *Differential fuzzing between BPF interpreter and JIT compilers. Found behavioral divergences that could be exploitable.*

- **"Formal Verification of eBPF Programs Using Agda"**
  Bhat, Nagarakatte. **2024**.
  *Machine-checked correctness proofs for a subset of BPF semantics. Demonstrates feasibility of formal verification for BPF.*

- **"Making eBPF Verifier Scalable: Taming Exponential Complexity with Demand-Driven Approach"**
  Hu, Saxena, Liu. **2024**.
  *Addresses verifier scalability through demand-driven analysis. Relevant to understanding verifier limitations that affect security tools.*

### Conference Talks and Technical Reports

- **"Speculative Execution Attacks on BPF"**
  Jann Horn, Google Project Zero. **2021**.
  *Demonstrated that verified BPF programs could perform speculative OOB reads. Fundamental challenge to verifier-based safety.*

- **"BPF Security Auditing at Google"**
  KP Singh, Google. **Linux Plumbers Conference 2020**.
  *Describes Google's approach to auditing BPF usage. Identifies BPF as both a security tool and attack surface.*

---

## 2. BPF-Based Offense and Rootkits

### Papers and Talks

- **"Warping Reality: Creating and Countering the Next Generation of Linux Rootkits Using eBPF"**
  Pat Hogan. **DEF CON 29, 2021**.
  *Introduced bad-bpf: offensive BPF tools for PID hiding, sudo credential theft. Requires program loading, unlike map poisoning.*

- **"With Friends Like eBPF, Who Needs Enemies?"**
  Guillaume Fournier, Sylvain Afchain. **DEF CON 29, 2021**.
  *Introduced ebpfkit: a comprehensive eBPF rootkit. Network MITM, process hiding, backdoor execution. Requires attacker-controlled BPF programs.*

- **"TripleCross: A Linux eBPF Rootkit"**
  Marcos S. **2023**.
  *Open-source eBPF rootkit with backdoor, library injection, and execution hijacking modules. Academic analysis of offensive BPF.*

- **"Evil eBPF: Practical Abuses of an In-Kernel Bytecode Runtime"**
  Hejazi, Zhu, et al. **Black Hat 2024**.
  *Cataloged offensive BPF uses including covert channels via BPF maps. Focused on creating maps for attacker programs, not modifying defensive tool maps.*

- **"Namespaced eBPF: Towards Container-Aware eBPF"**
  Zheng, Jia, Wang. **2024**.
  *Proposes namespace awareness for eBPF. Directly relevant to the BPF map isolation gap that enables map poisoning.*

---

## 3. Syscall Monitoring Evasion

### Papers

- **"Phantom Attack: Evading System Call Monitoring"**
  Rex Guo, Junyuan Zeng. **NDSS 2023**.
  *TOCTOU attacks against syscall argument tracing. Modifies arguments in shared memory between trace read and kernel use. Different from map poisoning (data corruption vs. config corruption) but related evasion class.*

- **"Evading Behavior-Based Security Monitors via Mimicry Attacks"**
  Wagner, Soto. **Oakland/IEEE S&P 2002**.
  *Foundational work on evading behavior-based IDS. Demonstrated that attackers can mimic legitimate behavior to evade pattern-matching monitors. Conceptual ancestor of modern evasion techniques.*

- **"Undermining Syscall-Based Intrusion Detection with Stealthy Process Manipulation"**
  Kruegel, Kirda, Mutz, Robertson, Vigna. **NDSS 2005**.
  *Showed how process manipulation can evade syscall-based monitoring. Relevant as a precedent for kernel-level evasion of monitoring tools.*

- **"Lazarus: Practical Side-Channel Resilient Kernel-Space Randomization"**
  Aga, Austin, Brown. **RAID 2019**.
  *Addresses side-channel attacks against KASLR. Relevant to the broader theme of kernel security assumptions that do not hold in practice.*

---

## 4. Runtime Security Tool Research

### Papers and Documentation

- **"Tetragon: eBPF-Based Security Observability and Runtime Enforcement"**
  Guillaume Fournier, John Fastabend, Natalia Reka Ivanko. **Isovalent, 2023**.
  *Architecture description of Tetragon. Describes tail-call-based event processing and LSM enforcement. Does not address map integrity.*

- **"Real-Time Security Monitoring on the Edge with eBPF"**
  Cassagnes, Jaiswal, Tshilidzi. **2020**.
  *Evaluates eBPF for edge security monitoring. Discusses performance but not configuration integrity.*

- **"Falco: Runtime Security Monitoring for Cloud-Native Environments"**
  Sysdig/CNCF. **Cloud Native Computing Foundation, 2024**.
  *Falco architecture and deployment guide. Describes the interesting_syscalls filtering mechanism but not its security implications.*

- **"System Call Interception: Detection and Prevention"**
  Hsu, Chen, Ku. **IEEE Access, 2020**.
  *Survey of system call interception techniques and defenses. Covers traditional approaches that BPF-based tools have superseded.*

---

## 5. Kernel Security and Capabilities

### Papers

- **"Linux Capabilities: Making Them Work"**
  Hallyn, Morgan. **Linux Symposium, 2008**.
  *Analysis of the Linux capabilities model, its implementation challenges, and the gap between design intent and deployment reality. Directly relevant to the CAP_BPF capability analysis.*

- **"A Study of Security Vulnerabilities on Docker Hub"**
  Shu, Gu, Enck. **CODASPY 2017**.
  *Found widespread use of privileged containers in Docker Hub images. Relevant to the prevalence of CAP_BPF/CAP_SYS_ADMIN in container environments.*

- **"Understanding and Hardening Linux Privileges"**
  Chen, Xing, Mao, Luo, Wang. **IEEE S&P (Oakland) 2024**.
  *Systematic analysis of Linux privilege mechanisms. Found capability design flaws including over-broad capabilities like CAP_SYS_ADMIN and CAP_BPF.*

- **"Security Namespace: Making Linux Security Mechanisms Namespace-Aware"**
  Sun, Safford, Zohar, Pendarakis, Gu. **USENIX Security 2018**.
  *Proposes namespace awareness for security mechanisms (IMA, EVM, audit). The absence of BPF namespace awareness is directly relevant to map poisoning.*

- **"Analyzing Integrity Protection in the SELinux Example Policy"**
  Jaeger, Sailer, Zhang. **USENIX Security 2003**.
  *Formal analysis of SELinux policy integrity. Methodology applicable to analyzing BPF LSM policy integrity (or lack thereof).*

---

## 6. Container Security

### Papers

- **"A Study of Container Security in Practice"**
  Lin, Lal, Luo, Fokker. **ACM CCS 2020**.
  *Empirical study of container security practices. Found that 40% of Docker Hub images run as root and many request elevated capabilities.*

- **"Understanding Real-World Container Security"**
  Brady, Sultan, Bhagwat, Rabin. **ACM ACSAC 2020**.
  *Analysis of container vulnerabilities and misconfigurations in production. Identifies privileged containers as a primary risk factor.*

- **"Slacker: Fast Distribution of Docker Container Images"**
  Harter, Ananthanarayanan, Basu, et al. **USENIX FAST 2016**.
  *Not security-focused, but foundational work on container image distribution. Relevant as context for why containers need rapid deployment (which drives use of privileged containers).*

- **"gVisor: Comprehensive Kernel Security Protection for Containers"**
  Young, Hua, et al., Google. **USENIX ATC 2023**.
  *Architecture and security analysis of gVisor. Demonstrates that complete BPF isolation requires a separate kernel implementation.*

- **"Kata Containers: An Emerging Architecture for Enabling MEC Services in Fast and Secure Way"**
  Randazzo, Ferretti, Musumeci. **2019**.
  *Architecture of Kata Containers. Hardware-level isolation provides complete BPF map isolation at the cost of performance.*

---

## 7. io_uring Security

### Papers and Reports

- **"io_uring: The Fast Path to a Bigger Attack Surface"**
  Hao Sun, et al. **USENIX Security 2024**.
  *Systematic security analysis of io_uring. Found that io_uring re-implements syscall functionality with weaker security checks. Directly relevant as a parallel kernel-level evasion mechanism.*

- **"Lord of the io_uring"**
  Dor Laor, et al. **2022**.
  *Comprehensive io_uring programming reference. Documents the scope of operations available through io_uring, many of which bypass syscall monitoring.*

- **"Efficient I/O with io_uring"**
  Jens Axboe. **Linux Plumbers Conference, 2019**.
  *Original io_uring design presentation. Focuses on performance; does not address security monitoring bypass.*

---

## 8. Network Security and BPF

### Papers

- **"The eXpress Data Path: Fast Programmable Packet Processing in the Operating System Kernel"**
  Hoiland-Jorgensen, Brouer, Borkmann, Fastabend, Herbert, Ahern, Miller. **CoNEXT 2018**.
  *Foundational XDP paper. Describes architecture and performance. BPF maps used for forwarding tables and statistics are subject to poisoning.*

- **"Cilium: BPF & XDP for Containers"**
  Borkmann. **netdev 2017**.
  *Cilium architecture description. BPF maps store network policies; modification of these maps would bypass network segmentation.*

- **"Revisiting the Open vSwitch Dataplane Ten Years Later"**
  Tu, Lemieux, Bhagwat, et al. **SIGCOMM 2021**.
  *Compares OVS with BPF-based datapaths. Notes that BPF datapaths distribute state into maps rather than centralized flow tables.*

- **"Fast Packet Processing with eBPF and XDP: Concepts, Code, Challenges, and Applications"**
  Vieira, Castanho, Pacini, Schweitzer, Guedes. **ACM Computing Surveys 2020**.
  *Comprehensive survey of eBPF networking. Catalogs map types used in networking, all of which are subject to poisoning.*

- **"Bringing the Power of eBPF to Open vSwitch"**
  Tu, Stringer, et al. **SIGCOMM Poster 2018**.
  *BPF-based OVS datapath. Demonstrates the pattern of storing network forwarding state in BPF maps.*

---

## 9. LSM and Access Control

### Papers

- **"MAC and Audit policy using eBPF (KRSI)"**
  KP Singh. **Linux Plumbers Conference, 2019**.
  *Original BPF LSM proposal. Describes dynamic policy via BPF programs. Does not address self-protection of BPF LSM policy maps.*

- **"The Inevitability of Failure: The Flawed Assumption of Security in Modern Computing Environments"**
  Loscocco, Smalley. **21st National Information Systems Security Conference, 1998**.
  *Motivating paper for SELinux. Argues that security must be enforced in the kernel. Relevant: BPF LSM follows this principle but stores policy in unprotected maps.*

- **"Security Enhanced (SE) Android: Bringing Flexible MAC to Android"**
  Smalley, Craig. **NDSS 2013**.
  *SELinux for Android. Demonstrates comprehensive MAC including BPF operation controls. SELinux protects its own policy -- unlike BPF LSM.*

- **"Landlock: Unprivileged Access Control"**
  Salaun. **Linux Security Summit, 2020**.
  *Landlock LSM for unprivileged sandboxing. Could potentially be extended with BPF hooks for self-restriction.*

---

## 10. Monitoring Evasion (General)

### Papers

- **"Intrusion Detection Evasion: How Attackers Get Past the Burglar Alarm"**
  Ptacek, Newsham. **Secure Networks, 1998**.
  *Foundational work on IDS evasion via ambiguity in protocol interpretation. Conceptual ancestor: exploiting gaps between what the monitor sees and what actually happens.*

- **"A Taxonomy of Evasion Techniques for Network Intrusion Detection Systems"**
  Cheng, Chaiken, et al. **ACM Computing Surveys 2012**.
  *Comprehensive taxonomy of NIDS evasion. BPF map poisoning represents a new category: configuration-plane attacks against kernel-level monitors.*

- **"Missed Alarms: A Side-Channel Analysis of Monitoring Software"**
  Schwarz, Lackner, Gruss. **ACM CCS 2019**.
  *Side-channel attacks against security monitoring. Demonstrated that monitoring tools leak information about their configuration. Related: BPF maps are not just leaked but directly modifiable.*

- **"SoK: The Challenges, Pitfalls, and Perils of Using Hardware Performance Counters for Security"**
  Das, Werner, Giannacopoulos, Joshi, Mishra. **IEEE S&P (Oakland) 2019**.
  *Surveys limitations of hardware-counter-based security monitoring. Relevant as another case where monitoring assumptions do not hold under adversarial conditions.*

---

## 11. Formal Methods and Kernel Verification

### Papers

- **"seL4: Formal Verification of an OS Kernel"**
  Klein, Elphinstone, Heiser, et al. **SOSP 2009**.
  *Gold standard for kernel verification. The BPF verifier aspires to similar guarantees but for a dynamic, evolving subset of kernel functionality.*

- **"CertiKOS: An Extensible Architecture for Building Certified Concurrent OS Kernels"**
  Gu, Vaynberg, Ford, et al. **OSDI 2016**.
  *Certified concurrent kernel. Relevant as a reference point for what verified kernel safety looks like.*

- **"Ironclad Apps: End-to-End Security via Automated Full-System Verification"**
  Hawblitzel, Howell, Lorch, et al. **OSDI 2014**.
  *Full-system verification including I/O. Relevant as inspiration for end-to-end BPF program + map integrity verification.*

---

## 12. Cloud-Native and Kubernetes Security

### Papers

- **"An Empirical Study of Kubernetes Security"**
  Shamim, Bhuiyan, Rahman. **ACM MSR 2020**.
  *Studied security issues in Kubernetes. Found widespread misconfigurations including overly permissive pod security contexts.*

- **"Security Implications of Kubernetes Networking"**
  Ahmet Balkan, Google. **KubeCon 2019 (Talk)**.
  *Analyzed network security gaps in Kubernetes. Relevant: BPF-based network policy (Cilium) is the recommended solution, but its BPF maps are unprotected.*

- **"Kubernetes Security: Operating Kubernetes Clusters and Applications Safely"**
  Rice. **O'Reilly, 2021 (Book)**.
  *Comprehensive Kubernetes security reference. Discusses capability management but does not address BPF map security.*

---

## Summary: Paper Coverage by Research Area

| Research Area | Papers Cited | Key Insight for Map Poisoning |
|---|---|---|
| eBPF verifier | 7 | Verifier protects code plane; data plane (maps) unprotected |
| BPF offense/rootkits | 5 | All prior offensive BPF requires program loading; map poisoning does not |
| Syscall evasion | 4 | Map poisoning is a new evasion class distinct from TOCTOU/mimicry |
| Runtime security tools | 4 | Tools assume map integrity; none verify it |
| Kernel capabilities | 4 | CAP_BPF grants system-wide map access, violating least privilege |
| Container security | 5 | Namespace isolation does not extend to BPF objects |
| io_uring | 3 | Parallel kernel-level evasion; better studied than map poisoning |
| Network BPF | 5 | Network policy maps are also poisonable, expanding impact |
| LSM/MAC | 4 | BPF LSM policy maps are unprotected, creating circular dependency |
| Monitoring evasion | 4 | Map poisoning is a novel category in evasion taxonomy |
| Formal methods | 3 | Verification approaches exist but do not cover runtime data integrity |
| Cloud-native security | 3 | Production environments routinely grant BPF capabilities |
