# BPF Verifier Research

## Overview

The BPF verifier is the kernel component responsible for ensuring that all eBPF programs loaded into the kernel are safe: they must terminate, they must not access out-of-bounds memory, and they must not violate type safety. The verifier performs abstract interpretation over the program's control flow graph, tracking register states, pointer types, and value ranges. This survey covers the verifier's architecture, known bypass classes, and academic analysis of its correctness, with emphasis on how verifier research relates to the BPF map poisoning attack surface.

---

## 1. Verifier Architecture

### Abstract Interpretation Model

The BPF verifier operates as a static analyzer that walks every possible execution path through a BPF program. For each instruction, it maintains an abstract state consisting of:

- **Register state**: For each of the 11 BPF registers (R0-R10), the verifier tracks the register type (`SCALAR_VALUE`, `PTR_TO_MAP_VALUE`, `PTR_TO_CTX`, `PTR_TO_STACK`, etc.), a `tnum` (tristate number representing known bits), signed and unsigned minimum/maximum bounds, and reference count.

- **Stack state**: The 512-byte BPF stack is tracked slot by slot. Each slot records what type of value was stored (scalar, pointer, uninitialized).

- **Reference tracking**: The verifier tracks acquired references (e.g., from `bpf_map_lookup_elem()`) and ensures they are released before program exit.

- **Precision tracking** (kernel 5.5+): Marks which registers require exact bounds tracking vs. those that can be safely approximated. Reduces verification complexity.

### Path Exploration and Pruning

The verifier explores all paths through the program. At branch points (conditional jumps), it forks the abstract state and explores both true and false branches. To prevent exponential blowup, the verifier employs **state pruning**: at each program point, it compares the current state against previously verified states. If the current state is a "subset" of a previously verified state (every register has equal or tighter bounds), the path is pruned as redundant.

The instruction complexity limit (currently 1 million verified instructions for privileged programs) bounds verification time. Programs exceeding this limit are rejected.

### Type System

The verifier's type system distinguishes:

| Type | Description | Access Rules |
|---|---|---|
| `SCALAR_VALUE` | Integer, no pointer semantics | Arithmetic allowed, no dereference |
| `PTR_TO_MAP_VALUE` | Pointer into a BPF map value | Dereference within map value size |
| `PTR_TO_MAP_KEY` | Pointer to map key on stack | Read-only |
| `PTR_TO_CTX` | Pointer to program context | Field access per program type |
| `PTR_TO_STACK` | Pointer to BPF stack frame | Within 512-byte stack |
| `PTR_TO_BTF_ID` | Kernel pointer with BTF type | Read-only, offset-bounded |
| `PTR_TO_PACKET` | Network packet data pointer | Bounded by packet length |
| `CONST_PTR_TO_MAP` | Constant pointer to map descriptor | Used in helper calls |

---

## 2. Known Bypass Classes

### 2.1 ALU Bounds Tracking Errors

The most exploited class of verifier bugs. The verifier must update register bounds after every arithmetic operation. Errors in bounds propagation create situations where the verifier believes a register has a narrower range than it actually does at runtime.

- **32-bit/64-bit mismatch (CVE-2020-8835, CVE-2021-3490)**. The verifier maintains separate 32-bit and 64-bit bounds for each register (since BPF supports both ALU32 and ALU64 operations). Bugs in synchronizing these bounds -- particularly after 32-bit operations that the verifier incorrectly applies to 64-bit state or vice versa -- have been the single most fruitful exploit class. CVE-2021-3490 specifically exploited incorrect `tnum` propagation for `BPF_AND` and `BPF_OR` on 32-bit sub-registers: the `tnum_and()` result was correct for the 32-bit operation but the verifier failed to intersect the resulting `var_off` with `[smin32, smax32]` bounds.

- **Shift operation errors (CVE-2020-27194)**. Right-shift operations on bounded scalars must correctly narrow the bounds. An error in `scalar_min_max_rsh()` allowed the verifier to compute overly permissive bounds for `BPF_RSH`, enabling OOB access at runtime.

- **Sign extension errors**. When a 32-bit value is sign-extended to 64 bits, the verifier must correctly propagate the sign bit into the 64-bit bounds. Errors here have created exploitable mismatches between the verifier's model and actual register values.

### 2.2 Type Confusion

Type confusion occurs when the verifier assigns the wrong type to a register, typically allowing a scalar to be treated as a pointer (or vice versa), enabling arbitrary memory access.

- **CVE-2022-23222**. The verifier failed to properly handle `PTR_TO_MEM` after certain arithmetic operations, allowing an attacker to craft a sequence of instructions that caused the verifier to lose track of a pointer's type, effectively turning it into an untyped value that could be dereferenced at arbitrary offsets.

- **BTF type confusion (CVE-2023-39191)**. Maliciously crafted BTF (BPF Type Format) data could cause the verifier to misinterpret kernel data structure types, enabling type-confused access to kernel memory through `PTR_TO_BTF_ID` registers.

- **Map value type confusion**. When the verifier processes `bpf_map_lookup_elem()`, it types the return value as `PTR_TO_MAP_VALUE | PTR_NULL`. Bugs in handling the null check branch -- or in propagating the map value type through subsequent operations -- can create type-confused states.

### 2.3 State Pruning Bugs

The verifier's pruning optimization is a correctness-critical component: if it incorrectly prunes a path, that path's safety is never verified.

- **CVE-2023-2163**. The pruning comparator determined that two states were equivalent when they were not, specifically failing to compare certain register attributes that were relevant to safety. This allowed an attacker to craft a program where the pruned path performed out-of-bounds map access that the verifier never checked.

- **Precision tracking and pruning interaction**. Kernel 5.5 introduced precision tracking to reduce verification complexity. Registers marked as "imprecise" have relaxed pruning requirements. Bugs in precision propagation -- marking a register as imprecise when it is actually used in a bounds-sensitive context -- can create pruning-exploitable states.

### 2.4 Reference Tracking Bugs

The verifier tracks references (pointers obtained from helpers like `bpf_map_lookup_elem()`, `bpf_sk_lookup_tcp()`) and requires they be released before program exit. Bugs in reference tracking can lead to resource leaks or use-after-free.

- **Spin lock / reference count interaction**. The verifier must track `bpf_spin_lock` / `bpf_spin_unlock` pairing and their interaction with reference-counted resources. Complex control flow paths involving both locks and references have exposed tracking bugs.

- **Exception path reference leaks**. When a helper call fails (returning NULL or an error), the verifier must account for any references that should have been released in the error path. Missing error-path reference tracking has led to kernel resource leaks.

### 2.5 Callback and Tail Call Verification

- **Callback verification complexity**. BPF supports callbacks via `bpf_for_each_map_elem()`, `bpf_timer_set_callback()`, and `bpf_loop()`. The verifier must verify the callback function in the context of the calling function's state. Incorrect state propagation across callback boundaries has been a source of bugs.

- **Tail call chain verification**. Tail calls (`bpf_tail_call()`) transfer execution to another BPF program. The verifier checks each program independently but must account for shared state (maps, register conventions) across tail call boundaries. The verifier limits tail call depth to 33 to bound execution, but does not verify the *composition* of tail-called programs for safety.

---

## 3. Academic Analysis of Verifier Correctness

### Formal Verification Efforts

- **Nelson et al., "Scaling Symbolic Evaluation for Automated Verification of Systems Code with Serval" (SOSP 2019)**. Developed the Serval framework for verifying systems code using symbolic evaluation. Applied to BPF JIT compilers, finding bugs in ARM32, RISC-V, and x86-32 JITs. The methodology was later extended to the Jitterbug framework (OSDI 2020) for comprehensive JIT verification.

- **Nelson et al., "Specification and Verification with the Jitterbug Framework" (OSDI 2020)**. Formalized BPF JIT correctness as a refinement relation between the BPF instruction semantics and the generated native code. Verified the Arm32 JIT and discovered 16 bugs across 5 JIT backends. The key insight: JIT bugs are *semantic* divergences between the verifier's instruction model and the JIT's code generation.

- **Vishwanathan et al., "Verifying the Verifier: eBPF Range Analysis Verification" (CAV 2023)**. Applied SMT-based verification to the BPF verifier's abstract domain for scalar values. Formalized the `tnum` representation and bounds tracking algorithms. Found multiple cases where the verifier's abstract operations were imprecise (overly conservative) but did not find *unsound* operations in the analyzed code paths. This work is notable for being the first to apply formal methods directly to the verifier's abstract interpretation core.

- **Gershuni et al., "Simple and Precise Static Analysis of Untrusted Linux Kernel Extensions" (PLDI 2019)**. Analyzed the BPF verifier as a static analyzer and characterized its precision limitations. Proposed improvements to the abstract domain that could reduce false rejections without compromising soundness.

- **Bhat et al., "Formal Verification of eBPF Programs Using Agda" (2024)**. Formalized a subset of BPF semantics in the Agda proof assistant and verified basic safety properties. Demonstrated the feasibility of machine-checked correctness proofs for BPF program verification but covered only a limited instruction subset.

### Empirical Analysis

- **Systematic fuzzing**. Google's syzbot (Dmitry Vyukov) continuously fuzzes the BPF subsystem. As of 2024, syzbot has reported over 200 BPF-related kernel bugs, many in the verifier. The BPF subsystem is among the most fuzzed kernel components.

- **BPF conformance test suite**. The BPF community maintains a growing conformance test suite that validates verifier behavior against expected outcomes. However, the test suite focuses on *correctness of rejection* (ensuring unsafe programs are rejected) rather than *soundness of acceptance* (ensuring accepted programs are truly safe).

- **Differential testing**. Comparing verifier analysis results against concrete execution (interpreter or JIT) on random programs. This approach has found cases where the verifier's abstract state diverges from concrete state, indicating potential soundness issues.

---

## 4. Verifier and BPF Maps

### Map Access Verification

The verifier enforces strict rules for map access within BPF programs:

1. `bpf_map_lookup_elem()` returns `PTR_TO_MAP_VALUE | PTR_NULL`. The program must check for NULL before dereferencing.
2. Access to map values is bounded: the verifier tracks the register's offset within the map value and ensures all reads/writes are within `[0, value_size)`.
3. Map type compatibility is checked: the helper call must match the map's key and value sizes.

### What the Verifier Does NOT Check

The verifier's scope is limited to **program-side safety**. It does not:

- Verify that map contents are semantically valid for the program's logic
- Enforce any access control on which programs can access which maps
- Detect or prevent userspace modification of map contents after program load
- Validate the integrity of map data between BPF program invocations

This last point is the foundation of BPF map poisoning: the verifier ensures that a BPF program accesses map memory safely (within bounds, correct type), but it provides no guarantee that the *values* in the map are what the program's author intended. An externally modified map value is accessed just as safely as a legitimate one -- the program simply operates on poisoned data.

---

## 5. Relevance to BPF Map Poisoning

The extensive research on verifier correctness reflects a fundamental assumption in the BPF security model: **safety is enforced at program load time**. The verifier ensures that approved programs cannot violate memory safety, regardless of the input data they process. This model was designed to protect the kernel from BPF programs, not to protect BPF programs from each other or from external interference.

BPF map poisoning exploits the gap between load-time verification and runtime data integrity. The verifier ensures that a security tool's BPF program will safely read from `config_map[0]` -- but it provides no mechanism to ensure that `config_map[0]` still contains the value the tool wrote during initialization. The verifier's correctness guarantees are orthogonal to the data-plane integrity that BPF map poisoning violates.

The verifier hardening trajectory (unprivileged BPF disabled, CAP_BPF separation, complexity limits, speculative load hardening) has made program-level attacks increasingly difficult. This asymmetry -- hardened code plane, unhardened data plane -- makes map poisoning an increasingly attractive attack vector relative to verifier exploitation.
