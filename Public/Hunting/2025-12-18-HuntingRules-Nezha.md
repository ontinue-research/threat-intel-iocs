# Nezha Monitoring Tool Abuse - Hunting Queries

## Overview

Nezha is a legitimate open-source server monitoring tool that can be abused as a post-exploitation RAT. These queries help identify unauthorised Nezha agent deployments within Microsoft Defender for Endpoint environments.

**Related Research:** [Nezha: The Monitoring Tool That's Also a Perfect RAT](https://www.ontinue.com/resources/?resource_type[]=blog)

---

## Queries

### Process Execution and File Paths

Detects Nezha agent process execution, installation paths, and command line parameters associated with deployment.

```kql
// Hunt for Nezha agent process execution and file paths
DeviceProcessEvents
| where TimeGenerated > ago(90d)
| where FileName has_any ("nezha-agent", "nezha_agent") 
    or FolderPath has_any ("\\nezha\\", "/nezha/", "/opt/nezha/") 
    or ProcessCommandLine has_any ("client_secret", "nezhahq", "NZ_SERVER", "NZ_CLIENT_SECRET")
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by TimeGenerated desc
```

---

### Network Connections

Identifies connections to Nezha default dashboard ports and known infrastructure patterns.

```kql
// Hunt for network connections to Nezha default ports and known infrastructure
DeviceNetworkEvents
| where TimeGenerated > ago(90d)
| where RemotePort in (8008, 8888, 18008) 
    or RemoteUrl has_any ("nezha", "nezhahq")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl, ActionType
| order by TimeGenerated desc
```

---

### File Artefacts

Locates Nezha agent binaries and configuration files on disk.

```kql
// Hunt for Nezha configuration files and agent binaries on disk
DeviceFileEvents
| where TimeGenerated > ago(90d)
| where FileName has_any ("nezha-agent", "config.yml") 
    or FolderPath has_any ("\\nezha\\", "/opt/nezha/", "C:\\nezha")
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Remote Access Software | T1219 | Legitimate RMM tool abuse |
| Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell execution via agent |
| System Services: Service Execution | T1569.002 | Agent installed as Windows service |

---