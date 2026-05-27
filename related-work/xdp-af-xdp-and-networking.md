# XDP, AF_XDP, and Networking BPF

## Overview

eBPF has become the dominant technology for programmable network processing in the Linux kernel. XDP (eXpress Data Path), TC (Traffic Control) BPF programs, and AF_XDP (Address Family XDP) sockets enable high-performance, programmable packet processing at various points in the network stack. Cilium uses these mechanisms to implement Kubernetes network policy, load balancing, and service mesh functionality. This survey covers the networking BPF landscape, how network BPF maps store policy and state, and the implications of BPF map poisoning for network security.

---

## 1. XDP (eXpress Data Path)

### Architecture

XDP (introduced in kernel 4.8, 2016) provides a programmable hook at the earliest point in the network receive path, before the kernel allocates an `sk_buff` (socket buffer). XDP programs process raw Ethernet frames and return one of five verdicts:

| Verdict | Action |
|---|---|
| `XDP_PASS` | Pass packet to normal network stack |
| `XDP_DROP` | Drop packet immediately |
| `XDP_TX` | Retransmit packet on the same interface |
| `XDP_REDIRECT` | Redirect to another interface, CPU, or AF_XDP socket |
| `XDP_ABORTED` | Drop with error tracepoint |

### Performance

XDP achieves near-line-rate packet processing (14.88 Mpps on 10 GbE) by processing packets before the kernel's network stack overhead:

- No `sk_buff` allocation
- No GRO/GSO processing
- No routing table lookup (unless the program chooses to `XDP_PASS`)
- JIT-compiled BPF execution

### XDP and BPF Maps

XDP programs use BPF maps for:

- **Forwarding tables**: Hash maps mapping destination addresses to output interfaces
- **Statistics counters**: Per-CPU arrays for packet counts, byte counts
- **Configuration**: Array maps for program behavior settings
- **Redirect targets**: `BPF_MAP_TYPE_DEVMAP` (device redirect) and `BPF_MAP_TYPE_CPUMAP` (CPU redirect)
- **AF_XDP routing**: `BPF_MAP_TYPE_XSKMAP` mapping queue indices to AF_XDP sockets

### XDP Security Use Cases

- **DDoS mitigation**: Drop malicious packets at the earliest possible point (Cloudflare, Facebook)
- **Firewall**: Programmable packet filtering before the kernel's netfilter
- **Network monitoring**: Mirror or sample traffic for analysis

---

## 2. TC BPF Programs

### Architecture

TC (Traffic Control) BPF programs attach to the Linux traffic control layer, processing packets after `sk_buff` allocation but before routing/forwarding decisions. TC supports both ingress and egress hooks:

- **TC ingress**: After packet reception, before routing
- **TC egress**: After routing, before transmission

TC BPF programs have access to the full `sk_buff` structure, providing richer context than XDP (which only sees raw frames).

### TC and Cilium

Cilium uses TC BPF programs as its primary datapath for network policy enforcement:

```
Packet → NIC → XDP (optional) → TC ingress → Cilium BPF → Routing → TC egress → Cilium BPF → NIC
```

At both ingress and egress, Cilium's BPF programs consult BPF maps to determine whether to allow, deny, or redirect packets based on Kubernetes network policies.

### TC BPF Maps for Network Policy

Cilium's TC BPF programs use maps including:

- **`cilium_policy`**: Hash map storing network policies per endpoint identity
- **`cilium_ipcache`**: Hash map mapping IP addresses to security identities
- **`cilium_ct4_global` / `cilium_ct6_global`**: Connection tracking tables (IPv4/IPv6)
- **`cilium_lb4_services_v2`**: Load balancer service table
- **`cilium_lb4_backends_v3`**: Load balancer backend table
- **`cilium_endpoints`**: Endpoint metadata (pod IDs, security labels)
- **`cilium_tunnel_map`**: VXLAN/Geneve tunnel endpoint mappings

---

## 3. AF_XDP (Address Family XDP)

### Architecture

AF_XDP (kernel 4.18, 2018) provides a zero-copy path from network hardware to user-space applications, bypassing the kernel's network stack entirely. An XDP program redirects packets to an AF_XDP socket using `XDP_REDIRECT` and `BPF_MAP_TYPE_XSKMAP`.

### Components

- **UMEM**: Shared memory region between kernel and user space for packet buffers
- **FILL ring**: User space provides empty buffers for the kernel to fill
- **COMPLETION ring**: Kernel returns buffers after transmission
- **RX ring**: Received packets (references to UMEM buffers)
- **TX ring**: Packets to transmit (references to UMEM buffers)
- **XSKMAP**: BPF map routing packets to AF_XDP sockets

### Security Implications

AF_XDP creates a direct path from the NIC to user space that bypasses:

- The kernel's network stack (netfilter, conntrack, routing)
- TC BPF programs (unless the XDP program is configured to also run TC)
- Network-level security tools that operate above XDP

An attacker who can redirect packets to an AF_XDP socket via XDP map modification can:

1. Exfiltrate network traffic without it passing through Cilium's policy enforcement
2. Inject packets into the network without TC-level monitoring
3. Create a covert network channel invisible to network security tools

### AF_XDP and TC Bypass

Research has demonstrated that AF_XDP can bypass TC-level security policies:

- Packets redirected to AF_XDP at the XDP layer never reach the TC layer
- Cilium's TC-based network policies are not evaluated for AF_XDP-redirected traffic
- This was verified in the context of the LID-005/LID-009 AF_XDP tc bypass research, which confirmed that tc egress rules can be bypassed via AF_XDP on plain Docker containers (though Cilium-managed networking was not fully bypassed due to additional enforcement points)

---

## 4. Cilium's Use of BPF for Network Policy

### Architecture

Cilium (Isovalent/Cisco) is the most widely deployed BPF-based networking solution for Kubernetes. It replaces kube-proxy and implements:

- **Network policy enforcement** (Kubernetes NetworkPolicy, CiliumNetworkPolicy)
- **Load balancing** (ClusterIP, NodePort, LoadBalancer services)
- **Service mesh** (L7 policy, mTLS via Envoy integration)
- **Observability** (Hubble flow logs, metrics)
- **Encryption** (WireGuard, IPsec)

### BPF Map-Based Policy Enforcement

Cilium's policy enforcement is entirely BPF map-driven:

1. Kubernetes NetworkPolicy resources are compiled into BPF map entries
2. The Cilium agent writes policy entries to `cilium_policy` maps
3. TC BPF programs look up the packet's source and destination identities in `cilium_ipcache`
4. Policy is evaluated by looking up the identity pair in `cilium_policy`
5. The verdict (allow, deny) is returned based on the map lookup result

### Network Policy Map Poisoning Scenarios

Poisoning Cilium's network policy maps could achieve:

1. **Policy bypass**: Modifying `cilium_policy` to add `ALLOW` entries for all identity pairs would effectively disable network policy enforcement. All pods could communicate freely regardless of Kubernetes NetworkPolicy restrictions.

2. **Identity confusion**: Modifying `cilium_ipcache` to assign incorrect security identities to IP addresses would cause policy to be evaluated against wrong identities, potentially allowing unauthorized traffic.

3. **Load balancer manipulation**: Modifying `cilium_lb4_backends_v3` could redirect service traffic to attacker-controlled backends.

4. **Connection tracking poisoning**: Modifying `cilium_ct4_global` could inject fake connection tracking entries, causing the datapath to treat malicious connections as established.

5. **Tunnel endpoint redirection**: Modifying `cilium_tunnel_map` could redirect pod-to-pod traffic through attacker-controlled VXLAN endpoints for man-in-the-middle attacks.

### Cilium Map Protection

Cilium does not currently use `bpf_map_freeze()` on its policy maps because policies must be dynamically updated as Kubernetes resources change. The Cilium agent continuously reconciles map state with the Kubernetes API server, which provides some detection capability (if a map is modified, the next reconciliation would overwrite the change). However:

- Reconciliation intervals create a window of vulnerability
- An attacker who also suppresses the Cilium agent (via container manipulation or its own BPF map poisoning) can persist the modification
- The Cilium agent does not cryptographically verify map contents

---

## 5. BPF-Based Firewalling

### Cloudflare's XDP-Based DDoS Mitigation

Cloudflare uses XDP programs for DDoS mitigation at their network edge. XDP programs consult BPF maps containing:

- IP address blocklists (hash maps)
- Rate limiting counters (per-CPU arrays)
- Protocol-specific filter rules

While Cloudflare's infrastructure is not directly comparable to Kubernetes deployments, the pattern is identical: firewall rules stored in BPF maps that are writable by any `CAP_BPF` process on the same host.

### Facebook (Meta) Katran

Katran is Meta's XDP-based L4 load balancer. It uses BPF maps for:
- Virtual IP to backend mapping
- Backend health status
- Connection tracking (consistent hashing)

Poisoning Katran's VIP map could redirect production traffic to arbitrary backends.

### nftables and BPF

The kernel's nftables framework supports BPF as an expression type, allowing BPF programs within nftables rules. BPF maps used in nftables expressions are subject to the same poisoning risks.

---

## 6. Network Observability Maps

### Cilium/Hubble Flow Maps

Hubble's network flow visibility depends on Cilium's BPF datapath generating flow events. These events are written to BPF ring buffers and annotated with data from BPF maps (identities, service names, policy verdicts). Poisoning the annotation maps would corrupt flow visibility without affecting the actual packet forwarding.

### Network Performance Monitoring

Tools like BCC's `tcpconnect`, `tcpaccept`, `tcplife`, and `tcpretrans` use BPF maps to track network connections and performance metrics. Poisoning these maps corrupts network performance data, potentially masking network anomalies indicative of data exfiltration or lateral movement.

---

## 7. Key Research and Projects

- **Hoiland-Jorgensen et al., "The eXpress Data Path: Fast Programmable Packet Processing in the Operating System Kernel" (CoNEXT 2018)**. Foundational XDP paper. Described the architecture, performance characteristics, and use cases. Did not address XDP map security.

- **Miano et al., "Creating Complex Network Services with eBPF: Experience and Lessons Learned" (IEEE HPSR 2018)**. Demonstrated complex network service chaining using eBPF. Identified map management as a key operational challenge.

- **Cilium documentation, "BPF and XDP Reference Guide"**. Comprehensive reference for Cilium's BPF datapath. Describes map types, program attachment, and policy enforcement. Does not address map integrity threats.

- **Tu et al., "Revisiting the Open vSwitch Dataplane Ten Years Later" (SIGCOMM 2021)**. Compared OVS (Open vSwitch) with BPF-based datapaths. Noted that BPF-based approaches trade OVS's centralized flow table management for distributed BPF maps.

- **Vieira et al., "Fast Packet Processing with eBPF and XDP" (ACM Computing Surveys 2020)**. Survey of eBPF networking capabilities. Cataloged map types used in networking applications.

---

## 8. Map Types in Networking

### Network-Specific Map Types

| Map Type | Purpose | Example Use |
|---|---|---|
| `BPF_MAP_TYPE_DEVMAP` | Redirect packets between interfaces | XDP forwarding |
| `BPF_MAP_TYPE_CPUMAP` | Redirect packets to other CPUs | Load distribution |
| `BPF_MAP_TYPE_XSKMAP` | Redirect to AF_XDP sockets | User-space networking |
| `BPF_MAP_TYPE_SOCKMAP` | Redirect between sockets | Socket-level load balancing |
| `BPF_MAP_TYPE_SK_STORAGE` | Per-socket storage | Connection metadata |
| `BPF_MAP_TYPE_LPM_TRIE` | Longest prefix match | IP routing, CIDR matching |
| `BPF_MAP_TYPE_LRU_HASH` | LRU eviction hash | Connection tracking |

All of these map types are accessible to any `CAP_BPF` process. Poisoning a `DEVMAP` could redirect network traffic; poisoning an `XSKMAP` could route packets to attacker-controlled AF_XDP sockets; poisoning an `LPM_TRIE` could alter routing decisions.

---

## 9. Relevance to BPF Map Poisoning

The networking BPF landscape significantly expands the BPF map poisoning attack surface beyond security monitoring:

1. **Network policy enforcement** (Cilium, Calico eBPF mode) stores Kubernetes network policies in BPF maps. Poisoning these maps bypasses network segmentation, one of the fundamental security controls in multi-tenant Kubernetes environments.

2. **Load balancer manipulation**: BPF-based load balancers (Cilium, Katran) store backend mappings in BPF maps. Poisoning enables traffic redirection to attacker-controlled endpoints.

3. **Network observability corruption**: Hubble flow data depends on BPF map annotations. Poisoning corrupts network visibility without affecting actual forwarding, creating a gap between observed and actual network behavior.

4. **Cross-domain impact**: A single BPF map poisoning campaign can simultaneously disable security monitoring (Tetragon/Falco), bypass network policy (Cilium), and corrupt observability (Hubble), because all three share the same unprotected BPF map architecture.

The networking domain demonstrates that BPF map poisoning is not limited to security tool evasion -- it extends to the entire BPF-based infrastructure stack, including network policy, load balancing, and observability.
