# TWINLOOT - Indicators of Compromise

| | |
|---|---|
| **Last Updated** | 2026-08-17 |
| **Target Platform** | Windows 10/11 (x64) |
| **Reference** | [Living Off the Cloud: A Python Implant Hiding Its Entire C2 Inside Microsoft 365 & Azure](https://www.ontinue.com/resource/python-implant-hiding-its-entire-c2-inside-microsoft-365-azure/) |

---

## Hashes

```
Stage-0 loader (bootstrap-fat.pyc)
2f1aa13fbdd8f5cdfe0838ecd4801a5881239ea096dd80f0af6ad1990c11418e

Embedded vendor ZIP
dc12b303b6374e0e1e1b2583d5e60e7d1e6e5207e6254627c7069b3049198f82

pyarmor_runtime.pyd
0ca8367e52c0c64bd75b994a4dfe4b29a1d2eb1307932c91b50576b1e19d6fd9

.pyarmor.ikey
16189a81eb537350cb5a3fff6cfa0b18444dbba6cdbe19e555c523b3a9fba191
```

---

## Domains and IPs

```
sharepointx.th2ch[.]com              # Primary C2 (:443, WS /user-authentication)
lpi-web[.]com                        # Failover edge
193.24.211[.]221                     # Failover edge (SNI sharepointx.th2ch.com)
kerteransens.sharepoint[.]com        # SharePoint C2 site (/sites/sanatrra)
034e10fbc291f2ce.blob.core.windows[.]net  # Config dead-drop (/034e10fbc291f2ce/cfg.json)
```

---

## Azure Identity

```
App (client) ID:      90d19ef9-23e6-4152-bb82-d46d16615796
Malicious Tenant ID:  d5e50217-99da-403d-a317-5bbce8855475
SharePoint site:      kerteransens.sharepoint[.]com/sites/sanatrra
Drive folder:         /TwinLoot
```

---

## File System Artifacts

```
Implant files
bootstrap-fat.pyc
.agent.lock
.vendor.ok
.vendor.stamp
.upgrade.prev_pid
.reobf.manifest
client_id.txt
lib\
lib.__staging
python-tk-runtime.zip
certs\ca.pem
certs\isrgrootx1.pem
python312._pth

Deploy directories
C:\ProgramData\PackageCache\
C:\ProgramData\CloudSync\
C:\ProgramData\Python\
C:\ProgramData\p\

Persistence files
C:\ProgramData\PackageCache\Config.sct
%USERPROFILE%\NTUSER.MAN

Credential phisher artifacts
%TEMP%\launcher_w10lss_cache
%TEMP%\launcher_tk_*

Headless Edge profile directories
launcher-edge-*
```

---

## Registry Indicators

```
Run key
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UserExperienceSync

TypeLib COM hijack
HKCU\Software\Classes\TypeLib\{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}\1.1
HKCU\...\1.1\0\win32 = script:C:\ProgramData\PackageCache\Config.sct
HKCU\...\1.1\0\win64 = script:C:\ProgramData\PackageCache\Config.sct

GhostTask (TaskCache, missing SD value)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\UserExperienceSyncTask
HKLM\...\Schedule\TaskCache\Tasks\<GUID>
HKLM\...\Schedule\TaskCache\Plain\<GUID>
```

---

## Process Indicators

```
Implant process
pythonw.exe executing .pyc from user-writable paths (%APPDATA%, %LOCALAPPDATA%, %TEMP%, C:\ProgramData\)
Environment variable: LAUNCHER_BG_CHILD=1

msedge.exe --headless=new
           --remote-debugging-port=<free>
           --user-data-dir=<tmp "launcher-edge-*">
           --window-position=-32000,-32000
           --window-size=1,1
           --disable-background-networking
```

---

## Network Signatures

```
User-Agents
LAUNCHER-cfg/1.0
LAUNCHER-reobf/1.0
LAUNCHER-bc-cfg/1.0
LAUNCHER-tk-runtime/1.0

TLS
ALPN: launcher/1

Teams TURN credential theft (from non-Teams processes)
POST teams.microsoft[.]com/api/authsvc/v1.0/authz/visitor
GET  teams.microsoft[.]com/trap-exp/tokens
Header: Ms-Teams-Auth-Type: ExplicitLogin
Header: X-Skypetoken: <token>

TURN relay (from non-Teams processes)
worldaz-msit.relay.teams.microsoft[.]com:443

Lateral movement (pythonw.exe to internal IPs)
445 / 3389 / 5985 / 5986 / 22 / 1433 / 135 / 389

Phishing asset hot-links
github[.]com/PrPunk/WEBFILES/raw/refs/heads/main/VidSmall.webm
i.postimg[.]cc/G2WpwMHH/windows-loandig-cargando.gif
```
---

## MITRE ATT&CK

```
T1566.004    Phishing: Spearphishing Voice (Teams social engineering)
T1546.015    Event Triggered Execution: COM hijack (TypeLib scriptlet)
T1053.005    Scheduled Task (GhostTask TaskCache manipulation)
T1547.001    Boot/Logon Autostart: Registry Run key
T1547.001    Boot/Logon Autostart: NTUSER.MAN mandatory profile hive
T1071.001    Application Layer Protocol: Web (SharePoint/Graph HTTPS)
T1071        Application Layer Protocol: WebRTC/Teams TURN
T1090        Proxy: Internal SOCKS via implant
T1090.003    Multi-hop Proxy: M365 relay infrastructure
T1102.001    Dead Drop Resolver: SharePoint files, Azure Blob, blockchain
T1102        Web Service: SharePoint Online, Microsoft Teams
T1056.002    Input Capture: GUI Input Capture (fake lock screen)
T1082        System Information Discovery (env + NetAPI recon)
T1027        Obfuscated Files: PyArmor encrypted bytecode
T1140        Deobfuscate/Decode: AES-256-GCM config decryption
T1036        Masquerading: task name, ProgramData paths
T1105        Ingress Tool Transfer: Tk runtime download
T1573.002    Encrypted Channel: AES-256-GCM
T1218.010    Signed Binary Proxy Execution: scrobj.dll (scriptlet)
```
