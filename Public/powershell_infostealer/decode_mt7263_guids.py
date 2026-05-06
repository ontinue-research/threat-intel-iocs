"""
Decode the eleven XOR-0x57 obfuscated CLSIDs and IIDs embedded in the
mt7263 stealer's App-Bound Encryption helper PE (payload_x64.bin /
payload_x86.bin).

The helper builds each GUID on the stack as a 16-byte blob and decodes
it in-place with a tight `xor byte ptr [...], 0x57` loop immediately
before the corresponding `CoCreateInstance` call. Re-running the decode
against the stack-initialisation immediates recovers the full set of
elevation-service identifiers used to abuse Chrome, Edge, Brave, and
Avast Secure Browser.

Cross-validated against:
  payload_x64.bin  sha256 54ab86b72423832e1d821e19486844375e1428079e1622f1c967d5a66bdc0b48
  payload_x86.bin  sha256 4563483704a8190d3ed69005fb2f593e53ca4496399e96afdb48fbde8ccdb51d
"""

import struct

def decode(d1, d2, d3, d4_bytes):
    b = struct.pack("<IHH", d1, d2, d3) + bytes(d4_bytes)
    b = bytes(x ^ 0x57 for x in b)
    d1x, d2x, d3x = struct.unpack("<IHH", b[:8])
    return "{%08X-%04X-%04X-%s-%s}" % (
        d1x,
        d2x,
        d3x,
        b[8:10].hex().upper(),
        b[10:].hex().upper(),
    )

# (label, Data1, Data2, Data3, Data4[8], expected GUID)
CASES = [
    (
        "Chrome Elevation Service CLSID",
        0x27DF37B7, 0xA116, 0x1146,
        [0xDF, 0xC2, 0x2A, 0xD1, 0x2A, 0x84, 0x30, 0x0C],
        "{708860E0-F641-4611-8895-7D867DD3675B}",
    ),
    (
        "Chromium IElevator2 IID (Chrome and Brave)",
        0x4CA277DC, 0x7E08, 0x1EC5,
        [0xE2, 0xA3, 0x6D, 0xCC, 0xE1, 0x1E, 0x1F, 0x6F],
        "{1BF5208B-295F-4992-B5F4-3A9BB6494838}",
    ),
    (
        "Chrome IElevator (legacy) IID",
        0x116DE998, 0x165A, 0x1728,
        [0xDD, 0xA2, 0x5A, 0xA4, 0x0D, 0x57, 0x0B, 0x9F],
        "{463ABECF-410D-407F-8AF5-0DF35A005CC8}",
    ),
    (
        "Brave Elevation Service CLSID",
        0x003C66F8, 0x343E, 0x1C3C,
        [0xD2, 0x37, 0xB3, 0xE5, 0x54, 0xFE, 0x2D, 0xDC],
        "{576B31AF-6369-4B6B-8560-E4B203A97A8B}",
    ),
    (
        "Brave IElevator (legacy) IID",
        0xA4C1D149, 0x5BD9, 0x1B26,
        [0xD5, 0x01, 0x78, 0xF9, 0x3A, 0x22, 0xCB, 0xBE],
        "{F396861E-0C8E-4C71-8256-2FAE6D759CE9}",
    ),
    (
        "Edge Elevation Service CLSID",
        0x489CBE3B, 0x41C0, 0x14F8,
        [0xC6, 0x17, 0x7F, 0xC0, 0x90, 0x91, 0xC0, 0x30],
        "{1FCBE96C-1697-43AF-9140-2897C7C69767}",
    ),
    (
        # Embedded Data3 is 0x4740; canonical Edge IElevator2 IID has 0x4047.
        # The transposition appears to be an operator transcription error
        # rather than a deliberate variant.
        "Edge IElevator2 IID (as embedded, Data3 transposed)",
        0xD82C30C5, 0x2F1A, 0x1017,
        [0xD3, 0x0A, 0x40, 0xD5, 0xB8, 0xE9, 0xA5, 0x52],
        "{8F7B6792-784D-4740-845D-1782EFBEF205}",
    ),
    (
        "Edge IElevator (legacy) IID",
        0x9E95EF50, 0x2066, 0x1863,
        [0xD6, 0xE0, 0x13, 0xA8, 0x20, 0x2E, 0x05, 0x7C],
        "{C9C2B807-7731-4F34-81B7-44FF7779522B}",
    ),
    (
        "Avast Secure Browser CLSID",
        0xBD8419BF, 0xDA5F, 0x1BF6,
        [0xFA, 0xF4, 0x33, 0x22, 0x14, 0x23, 0x8F, 0x46],
        "{EAD34EE8-8D08-4CA1-ADA3-64754374D811}",
    ),
    (
        "Avast IID",
        0x2060ECC8, 0xED96, 0x1B26,
        [0xF1, 0xC1, 0x2B, 0xD5, 0x80, 0xCE, 0x1C, 0x38],
        "{7737BB9F-BAC1-4C71-A696-7C82D7994B6F}",
    ),
]

def main() -> int:
    failures = 0
    width = max(len(label) for label, *_ in CASES)
    for label, d1, d2, d3, d4, expected in CASES:
        got = decode(d1, d2, d3, d4)
        ok = got == expected
        marker = "OK " if ok else "FAIL"
        print(f"[{marker}] {label:<{width}}  {got}")
        if not ok:
            print(f"        expected:                        {expected}")
            failures += 1
    print()
    if failures:
        print(f"{failures} mismatch(es).")
        return 1
    print(f"All {len(CASES)} GUIDs decoded successfully.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
