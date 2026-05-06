/*
 * YARA rule: mt7263 stealer - App-Bound Encryption helper
 *
 * Targets the tiny (~4.6 KB) PE that the mt7263 PowerShell stealer
 * process-hollows into a Chromium-family browser (Chrome / Edge / Brave /
 * Avast Secure Browser) to invoke IElevator::DecryptData on the victim's
 * `app_bound_encrypted_key`. Fires on both 32-bit and 64-bit variants.
 *
 * Distinctive design choices used as signal:
 *   - Browser elevator CLSIDs/IIDs stored XOR-0x57-encoded in .rdata
 *   - Named pipe formatted as `\\.\pipe\mojo.%d.%d.%d` (Mojo IPC camouflage)
 *   - 4-byte "APPB" magic prefix validation on pipe input
 *   - Single shared kernel32+ole32+oleaut32 import surface
 *
 * Cross-validated on:
 *   payload_x64.bin  sha256 54ab86b72423832e1d821e19486844375e1428079e1622f1c967d5a66bdc0b48
 *   payload_x86.bin  sha256 4563483704a8190d3ed69005fb2f593e53ca4496399e96afdb48fbde8ccdb51d
 */

import "pe"

rule mt7263_abe_helper
{
    meta:
        author      = "Rhys Downing"
        Company     = "Ontinue AG"
        date        = "2026-04-20"
        family      = "mt7263-stealer"
        component   = "abe-helper"
        description = "Chromium App-Bound Encryption IElevator abuse helper (XOR-0x57 CLSID obfuscation)"
        reference   = "https://mt7263.com/gate/init/<campaign>/<uid>"
        sha256_x64  = "54ab86b72423832e1d821e19486844375e1428079e1622f1c967d5a66bdc0b48"
        sha256_x86  = "4563483704a8190d3ed69005fb2f593e53ca4496399e96afdb48fbde8ccdb51d"

    strings:
        // Mojo-pipe camouflage - the full format string is very distinctive
        $pipe_fmt   = "\\\\.\\pipe\\mojo.%d.%d.%d" wide

        // 4-byte App-Bound magic - appears as a mov-immediate (0x42505041)
        // so it's embedded in a `mov dword ptr [...], 42505041h` instruction;
        // no `fullword` modifier because the preceding byte is a register/disp.
        $appb       = { 41 50 50 42 }

        // Target-process allowlist (wide)
        $exe_edge   = "msedge.exe"       wide fullword
        $exe_edge2  = "msedge_proxy.exe" wide fullword
        $exe_brave  = "brave.exe"        wide fullword
        $exe_brave2 = "brave_proxy.exe"  wide fullword
        $exe_avast  = "AvastBrowser.exe" wide fullword

        // XOR-0x57-encoded Data1 of each embedded CLSID/IID. Real GUID in comment.
        // These appear as 32-bit `mov` immediates, scattered across .text.
        $clsid_chrome_x57  = { B7 37 DF 27 }   // {708860E0-...} GoogleChromeElevatorClass
        $clsid_edge_x57    = { 3B BE 9C 48 }   // {1FCBE96C-...} MicrosoftEdgeElevatorClass
        $clsid_brave_x57   = { F8 66 3C 00 }   // {576B31AF-...} BraveElevatorClass
        $clsid_avast_x57   = { BF 19 84 BD }   // {EAD34EE8-...} Avast Secure Browser elevator
        $iid_ielevator_x57 = { 98 E9 6D 11 }   // {463ABECF-...} public IElevator
        $iid_ielevator2_x57= { DC 77 A2 4C }   // {1BF5208B-...} IElevatorChrome / IElevatorChromium

        // In-place XOR-decode loop body (8-bit xor 0x57 on ptr advance).
        // x64: `xor byte ptr [...], 57h` ; `inc rdx/rax` ; `dec rcx/r8` ; `jnz`
        // This is a tight and unusual sequence at both compiles.
        $xor57_x64 = { 80 34 ?? 57 }           // xor byte ptr [rXX+rYY], 57h  (x64 form)
        $xor57_x86 = { 80 30 57 }              // xor byte ptr [eax], 57h      (x86 form)

    condition:
        // Small Chromium-helper-sized PE
        uint16(0) == 0x5A4D and
        filesize < 16KB and

        // Mandatory imports (ensures it's the COM+pipe combo, not arbitrary code)
        pe.imports("kernel32.dll", "CreateNamedPipeW") and
        pe.imports("kernel32.dll", "ConnectNamedPipe") and
        pe.imports("kernel32.dll", "GetModuleFileNameW") and
        pe.imports("ole32.dll",    "CoCreateInstance") and
        pe.imports("ole32.dll",    "CoSetProxyBlanket") and
        pe.imports("oleaut32.dll", "SysAllocStringByteLen") and

        // Must include the Mojo camouflage, the APPB magic, and the XOR decoder
        $pipe_fmt and $appb and
        ($xor57_x64 or $xor57_x86) and

        // At least THREE of the browser-specific CLSID Data1s present
        // (all four are embedded, so a genuine hit has all four; three guards
        // against false positives where one signature happens to collide)
        3 of ($clsid_chrome_x57, $clsid_edge_x57, $clsid_brave_x57, $clsid_avast_x57) and

        // Plus at least one of the IElevator IIDs
        ($iid_ielevator_x57 or $iid_ielevator2_x57) and

        // And at least two browser-name allowlist entries
        3 of ($exe_edge, $exe_edge2, $exe_brave, $exe_brave2, $exe_avast)
}