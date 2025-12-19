# Nezha Monitoring Tool Abuse - Indicators of Compromise

## 2025-12-18: Post-Exploitation Tool Abuse
**Author:** Rhys Downing

**References:**
- https://www.ontinue.com/resources/?resource_type[]=blog

---

# Indicators of Compromise

## Network Indicators

### C2 Infrastructure
Note: Domain and IP are from the real-world discovery.
```
nz.632313373[.]xyz:8008
47.79.42[.]91
```

### Default Ports
```
8008 - Default Nezha dashboard port
443 - Common alternative (46% of deployments)
80 - Common alternative (28% of deployments)
8888 - Alternative port
18008 - Alternative port
```

### Infrastructure Details
```
ASN: AS45102 - Alibaba (US) Technology Co., Ltd.
IP Range: 47.79.40.0/21
Hosting: Alibaba Cloud LLC
Geolocation: Japan
```

---

## File System Indicators

### Windows Paths
```
C:\nezha\nezha-agent.exe
C:\nezha\config.yml
C:\temp\nezha-agent.exe
C:\nezha.zip
```

### Linux Paths
```
/opt/nezha/agent/nezha-agent
/opt/nezha/agent/config.yml
```

### Configuration File Structure
```yaml
client_secret: [32-character alphanumeric string]
server: [C2_address]:8008
tls: false
disable_command_execute: false
disable_force_update: false
```

---

## Process Indicators

### Process Names
```
nezha-agent.exe
nezha-agent
nezha_agent
```

### Parent-Child Relationships
```
services.exe → nezha-agent.exe
powershell.exe → nezha-agent.exe
nezha-agent.exe → powershell.exe
nezha-agent.exe → cmd.exe
nezha-agent.exe → whoami.exe
nezha-agent.exe → systeminfo.exe
nezha-agent.exe → net.exe
```

### Command Line Indicators
```
nezha-agent.exe -c C:\nezha\config.yml
client_secret
NZ_SERVER
NZ_CLIENT_SECRET
NZ_TLS
nezhahq
```

---

## File Hashes

### Agent Binary (Version Dependent)
```
056304fc1f7a81f08e957edff4207d5cf9c1934e52e23775da4483ecfad3bbf2 (SHA256)
```
Note: Hashes vary by version. The agent is legitimate software; focus detection on configuration and behaviour rather than file hashes alone.

---

## Deployment Script Indicators

### Environment Variables
```
NZ_SERVER
NZ_TLS
NZ_CLIENT_SECRET
```
---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell execution via agent |
| Indirect Command Execution | T1202 | Command execution through legitimate tool |
| Windows Management Instrumentation | T1047 | WMI queries for system enumeration |
| Query Registry | T1012 | Registry enumeration |
| Remote Access Software | T1219 | Legitimate RMM tool abuse |
| System Services: Service Execution | T1569.002 | Agent installed as Windows service |

---