## PowerShell + Native ABE Stealer (Fake Claude Code Installer Lure)

**Author:** Rhys Downing
**Date:** 2026-04-29 
**References:**
- https://www.ontinue.com/resources/?resource_type[]=blog

---

# Indicators of Compromise

## Network Indicators
### Hardcoded URLs
```
https://install-claude.com/                                  - Lure / fake Claude Code installer page
https://events.msft23.com/                                   - Stage-1 redirector (irm target)
https://mt7263.com/gate/start/c09d19a0                       - Stage-2 PowerShell loader delivery
https://mt7263.com/gate/init/c09d19a0/<SID>                  - Victim check-in and exfiltration sink
https://mt7263.com/gate/auto/c09d19a0/<UUID>                 - Tasking and follow-up channel
```
- URI regex (campaign-agnostic): ```/gate/(init|auto)/[0-9a-f]{8}/```
- Campaign ID embedded in C2 paths: ```c09d19a0```
- Apex domains: ```msft23.com```, ```mt7263.com```, ```install-claude.com```
- Default User-Agent (no override): ```Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.<build>``` (the loader uses Invoke-RestMethod without a UA override, so requests carry the default WindowsPowerShell user-agent)
---

### HTTP Headers (exfiltration)
```
Method: PUT
Content-Type: multipart/form-data; boundary=<random>
Host: mt7263.com
Path: /gate/init/c09d19a0/<SID>
Body: secure_prefs.zip (loot archive)
```
Tasking response headers (from `/gate/auto/`):
```
x-filename: <task-router-controlled name>
x-task:     <task-router-controlled directive>
```
---

## File System Indicators
### Target Directories - Browser Data (App-Bound Encryption targets)
```
%LOCALAPPDATA%\Google\Chrome\User Data\
%LOCALAPPDATA%\Microsoft\Edge\User Data\
%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\
%LOCALAPPDATA%\Vivaldi\User Data\
%LOCALAPPDATA%\Perplexity\Comet\User Data\
%LOCALAPPDATA%\imput\Helium\User Data\
%LOCALAPPDATA%\Packages\TheBrowserCompany.Arc_ttt1ap7aakyb4\LocalCache\Local\Arc\User Data\
%APPDATA%\Opera Software\Opera Stable\
%APPDATA%\Opera Software\Opera GX Stable\
```
- #### Target Files
```
Login Data                  - Chromium credential store (SQLite)
Cookies / Network\Cookies   - Session cookies (SQLite)
Web Data                    - Autofill and payment methods (SQLite)
Local State                 - Holds app_bound_encrypted_key (DPAPI-wrapped ABE master key)
History                     - Browsing history
secure_prefs.zip            - In-memory loot archive prior to exfiltration
<Browser>/v20key.bin        - Decrypted 32-byte ABE master key per browser
<Browser>/v10key.bin        - Pre-ABE DPAPI-derived key (legacy fall-back)
<Browser>/extension.zip     - Server-delivered per-browser follow-on bundle
```

### Host-Based Artefacts
```
\\.\pipe\mojo.<pid>.<tid>.<filename_hash>      - Helper-created IPC pipe (Mojo camouflage); third field is a deterministic hash of the host browser executable name (not random)
\\.\pipe\ArchPipe_\d{10}                       - Cross-architecture PowerShell-to-helper bridge
APPB (0x42505041)                              - 4-byte handshake magic on pipe input
conhost --headless powershell -ep bypass -file <...>   - Scheduled-task command line (PT1M repetition)
```

### Pipe-name third-field hash values (per browser)
```
chrome.exe        -> 0x03EE0040 (x64)  /  0x03EE0000 (x86)
msedge.exe        -> 0x03E50040 (x64)  /  0x03E50000 (x86)
msedge_proxy.exe  -> 0x06860040 (x64)  /  0x06860000 (x86)
brave.exe         -> 0x03800040 (x64)  /  0x03800000 (x86)
brave_proxy.exe   -> 0x06210040 (x64)  /  0x06210000 (x86)
AvastBrowser.exe  -> 0x06930040 (x64)  /  0x06930000 (x86)
```

### Locale Guardrail
```
Loader exits early if Win32_OperatingSystem TwoLetterISORegionName is one of:
AZ, AM, BY, GE, KZ, KG, MD, RU, TJ, TM, UZ, UA, IR
```

## File Hashes

### Native App-Bound Encryption helper (PE, ~4.6 KB)
```
54ab86b72423832e1d821e19486844375e1428079e1622f1c967d5a66bdc0b48  payload_x64.bin
4563483704a8190d3ed69005fb2f593e53ca4496399e96afdb48fbde8ccdb51d  payload_x86.bin
```

### PowerShell loader (start.ps1) - per-fetch variant
```
ac5c6d38b45bb429b7f690530c5ffaf329193f606796c602566702450dc9099f  Local incident sample (623,661 bytes)
844c67c405eb7bdd8e61720f542eee7f87ec8470612a1dc19e332c35a174ae22  urlscan 2026-04-18 variant
bdcfccf3e0aa2a524251c0594d3c308a940b23054374f36f2e4b73f4bc11b11d  urlscan 2026-04-20 variant
bcb515be6344720a3b06e6bd56e5eeaa661810eb14456acceb7eab5029704117  urlscan 2026-04-20 variant
```

### Code anchors (binary-level pivots)
```
551c967b0ddbc198545038c596a3c10d                                  Imphash (shared by x64 and x86 helpers)
566cd98ddd48865caa5cd73a060d6df06bade6d481823675c0eb509042fef9f3  Normalised opcode hash, elevator_pipe_client (x64)
677dac2412576267599d058cbc257d32902e53654a4ec0f552be4a26ecb31df7  Normalised opcode hash, elevator_pipe_client (x86)
```
Byte patterns:
```
80 34 ?? 57       XOR-0x57 decode loop body (x64)
80 30 57          XOR-0x57 decode loop body (x86)
c5 30 2c d8       Edge IElevator2 IID Data1 immediate (XOR-encoded LE bytes)
```

### Deobfuscated CLSIDs and IIDs (XOR-0x57 stack-resident)
```
{708860E0-F641-4611-8895-7D867DD3675B}   Chrome Elevation Service CLSID
{1BF5208B-295F-4992-B5F4-3A9BB6494838}   Chromium IElevator2 IID (Chrome and Brave primary)
{463ABECF-410D-407F-8AF5-0DF35A005CC8}   Chrome IElevator legacy IID (fall-back)
{576B31AF-6369-4B6B-8560-E4B203A97A8B}   Brave Elevation Service CLSID
{F396861E-0C8E-4C71-8256-2FAE6D759CE9}   Brave IElevator legacy IID (fall-back)
{1FCBE96C-1697-43AF-9140-2897C7C69767}   Edge Elevation Service CLSID
{8F7B6792-784D-4740-845D-1782EFBEF205}   Edge IElevator2 IID (as embedded; canonical Data3 is 4047, transposed to 4740)
{C9C2B807-7731-4F34-81B7-44FF7779522B}   Edge IElevator legacy IID (fall-back)
{EAD34EE8-8D08-4CA1-ADA3-64754374D811}   Avast Secure Browser Elevation Service CLSID
{7737BB9F-BAC1-4C71-A696-7C82D7994B6F}   Avast Secure Browser IID
```

---
