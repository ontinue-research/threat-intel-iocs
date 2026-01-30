# VoidLink Indicators of Compromise (IOCs)

**Last Updated:** 2026-01-29  
**Malware Family:** VoidLink Linux C2 Implant  
**Threat Type:** Command & Control Framework
**Target Platform:** Linux (x86-64)

---

## File Hashes

### Primary Sample
```
Filename:     implant.bin
File Type:    ELF 64-bit LSB executable
Architecture: x86-64

MD5:          [Calculate from sample]
SHA1:         9cdbc16912dcf188a0f0765ac21777b23b4b2bea
SHA256:       05eac3663d47a29da0d32f67e10d161f831138e10958dcd88b9dc97038948f69
SHA512:       [Calculate from sample]

Entropy:      7.24/8.0 (High - indicates packing/encryption)
Size:         ~1.4 MB
Functions:    1,422 identified
```

### Embedded Rootkit Modules
```
vl_stealth.ko
  - Kernel loadable module for syscall hooking
  - Hides processes, files, network connections
  
stealth_netstat.ko
  - Network connection hiding module
  
hide_ss.bpf.o
  - eBPF program for modern kernel stealth (≥5.5)
```

---

## Network Indicators

### Command & Control Infrastructure

#### Primary C2 Server
```
IP Address:    8.149.128.10
Protocol:      HTTPS (TLS 1.2/1.3)
Ports:         443 (primary), 80 (fallback)
Encryption:    AES-256-GCM
```

#### C2 Communication Patterns
```
User-Agents:
  Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
  Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
  Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36

HTTP Endpoints (Camouflage):
  /api/poll
  /api/v1/sessions/{uuid}
  /api/v2/heartbeat
  /api/metrics/collect
  /api/v1/analytics/events
  /api/v2/notifications
  /api/graphql
  /api/health/check
  
HTTP Headers:
  Cookie: session=<random>
  X-CSRF-Token: <random>
  Referer: https://example.com/
  Accept: application/json
  Accept-Encoding: gzip, deflate, br
  Accept-Language: en-US,en;q=0.9
```

#### ICMP Covert Channel
```
Magic Identifier: 0xC0DE
XOR Key:          0x42
Description:      Custom ICMP tunnel for covert C2 communication
```

#### Test/Connectivity Checks
```
DNS:  8.8.8.8 (Google DNS)
Test: 127.0.0.1 (loopback tests)
Test: https://example.com
Test: api.example.com
```

---

## File System Indicators

### Temporary Files & Storage
```bash
# Credential Storage
/var/tmp/.vl_creds                    # Harvested credentials cache
/dev/shm/.vl_creds                    # Memory-backed credential storage

# Command Execution
/tmp/.vl_cmd.sh                       # Shell command execution script
/tmp/.vl_data                         # Data exfiltration staging
/var/tmp/.vl_data                     # Alternative data staging

# Rootkit Configuration
/tmp/.vl_hide_cfg                     # Hiding configuration file
/tmp/.vl_ss_ports                     # Hidden port list

# Kernel Modules (Temporary)
/tmp/.vl_k3.ko                        # Kernel 3.x rootkit
/tmp/.vl_k4.ko                        # Kernel 4.x rootkit
/tmp/.vl_k5.ko                        # Kernel 5.x rootkit
/tmp/.vl_k6.ko                        # Kernel 6.x rootkit

# Rootkit Modules (Deployed)
vl_stealth.ko                         # Main stealth module
stealth_netstat.ko                    # Network hiding module
hide_ss.bpf.o                         # eBPF stealth program
```

### Targeted Configuration Files
```bash
# Cloud Credentials
~/.aws/*                              # AWS credentials
~/.config/gcloud/*                    # GCP credentials
~/.azure/*                            # Azure credentials
/var/run/secrets/kubernetes.io/       # Kubernetes service account

# SSH & Keys
~/.ssh/config
~/.ssh/id_rsa
~/.ssh/id_ecdsa
~/.ssh/id_ed25519
~/.ssh/known_hosts
~/.ssh/authorized_keys

# Git Credentials
~/.git-credentials

# Kubernetes
~/.kube/config

# Browser Data
~/.mozilla/firefox/*/cookies.sqlite
~/.config/google-chrome/Default/Cookies
```

### Persistence Locations
```bash
# Systemd
/etc/systemd/system/*                 # Service persistence
~/.config/systemd/user/*              # User-level services

# Init Scripts
/etc/rc.local                         # Legacy init persistence

# Cron
/etc/cron.d/*                         # Cron-based persistence
/var/spool/cron/crontabs/*            # User crontabs

# LD_PRELOAD
/etc/ld.so.preload                    # Userland hooking (kernel <4.0)
```

### Log Manipulation
```bash
# Targeted Logs (for clearing)
/var/log/wtmp                         # Login records
/var/log/utmp                         # Current logins
/var/log/btmp                         # Failed login attempts
/var/log/lastlog                      # Last login times
/var/log/faillog                      # Failed login log
/var/log/auth.log                     # Authentication log (Debian)
/var/log/secure                       # Authentication log (RHEL)
/var/log/syslog                       # System log
/var/log/messages                     # General messages
/var/log/audit/audit.log              # Audit subsystem
```

---

## Process Indicators

### Process Names (Rootkit Hidden)
```bash
# Process hiding patterns
[kworker/0:0]                         # Masquerades as kernel worker
[kworker/1:0]
[kworker/*:*]                         # Pattern match kernel workers

# Service masquerading
systemd-resolved                      # DNS service masquerade
nscd                                  # Name service cache daemon
```

### Command-Line Patterns
```bash
# Cloud metadata queries
curl http://169.254.169.254/*
wget http://169.254.169.254/*
curl http://metadata.google.internal/*
curl http://100.100.100.200/*

# Credential harvesting
cat ~/.aws/credentials
cat ~/.ssh/id_rsa
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Rootkit loading
insmod /tmp/.vl_k*.ko
modprobe vl_stealth
```

### Network Connections (Hidden by Rootkit)
```bash
# Outbound connections to C2
tcp 8.149.128.10:443 ESTABLISHED

# ICMP covert channel
icmp type 8 (echo request) with magic 0xC0DE

# Local testing
tcp 127.0.0.1:* LISTEN
```

---

## Kernel Module Indicators

### Loaded Kernel Modules
```bash
# Check for VoidLink modules
lsmod | grep -E "vl_stealth|stealth_netstat"

# Module file locations
/lib/modules/$(uname -r)/kernel/drivers/vl_stealth.ko
/lib/modules/$(uname -r)/kernel/net/stealth_netstat.ko
```

### eBPF Programs
```bash
# Check for loaded eBPF programs
bpftool prog list | grep -i hide

# Program names
hide_ss.bpf.o                         # Socket hiding program
sd_nl_in                              # Netlink message interceptor
```

### Module Signatures
```bash
# Unsigned kernel modules (suspicious on secure boot systems)
mokutil --sb-state                    # Check secure boot status
modinfo vl_stealth.ko | grep sig      # Check module signature
```
---

## Behavioral Indicators

### Cloud Metadata API Access
```bash
# Unusual access patterns to metadata services
GET http://169.254.169.254/latest/meta-data/
GET http://metadata.google.internal/computeMetadata/v1/
GET http://100.100.100.200/latest/meta-data/

# Kubernetes service account token access
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

### Environment Variable Enumeration
```bash
# Searches for credentials in environment
echo $AWS_ACCESS_KEY_ID
echo $AWS_SECRET_ACCESS_KEY
echo $GOOGLE_CLOUD_PROJECT
echo $AZURE_SUBSCRIPTION_ID
echo $KUBERNETES_SERVICE_HOST
```

### Container Detection
```bash
# Files checked for container environment
/.dockerenv
/run/.containerenv
/proc/1/cgroup (contains "docker" or "kubepods")
/var/run/secrets/kubernetes.io/
```

### Anti-Forensics Behaviors
```bash
# History clearing
export HISTFILE=/dev/null
export HISTSIZE=0
export HISTFILESIZE=0
unset HISTFILE

# Log clearing patterns
> /var/log/wtmp
> /var/log/btmp
> /var/log/auth.log
shred -u /var/log/auth.log

# Timestomping
touch -r <reference_file> <target_file>
```

### Virtualization Detection
```bash
# Checks for VM/sandbox environment
cat /sys/class/dmi/id/sys_vendor       # VMware, QEMU, VirtualBox
cat /sys/class/dmi/id/product_name     # Virtual Machine
cat /sys/hypervisor/type               # xen, kvm, hyperv
cat /proc/cpuinfo | grep hypervisor
```
---

---

**⚠️ CRITICAL REMINDER:** The primary IOC is C2 server `8.149.128.10`. Block this IP immediately at network perimeter and endpoint firewalls.
