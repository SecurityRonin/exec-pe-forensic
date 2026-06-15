[![Crates.io](https://img.shields.io/crates/v/pe-core.svg)](https://crates.io/crates/pe-core)
[![Docs.rs](https://img.shields.io/docsrs/pe-core)](https://docs.rs/pe-core)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/exec-pe-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/exec-pe-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-pink)](https://github.com/sponsors/h4x0r)

**Parse a Windows PE binary and get MITRE-tagged forensic detections in three lines of Rust.**

```rust
use pe_core::parser::parse_pe_path;
use pe_analysis::detect_all;

let pe = parse_pe_path("suspicious.exe")?;
for hit in detect_all(&pe) {
    println!("[{}] {} — {}", hit.mitre_technique_id, hit.tactic, hit.description);
}
```

```
[T1027.002] defense-evasion — Packed/protected section 'UPX0' (entropy 7.82, known packer name)
[T1055]     defense-evasion — Suspicious API import: 'VirtualAllocEx'
[T1055]     defense-evasion — Suspicious API import: 'WriteProcessMemory'
[T1055]     defense-evasion — Suspicious API import: 'CreateRemoteThread'
[T1486]     impact          — QWCrypt/RedCurl IOC '.qwCrypt' found in PE string table
[T1562.001] defense-evasion — AV exclusion fragment 'Windows Defender\Exclusions' found in PE string table
```

---

## What it detects

| Detection | MITRE ID | Confidence | Signal |
|-----------|----------|------------|--------|
| Suspicious API imports | T1055 / T1134 | High | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `BCryptEncrypt`, `ShellExecuteW`, raw Winsock, 55+ more |
| Packed / protected binary | T1027.002 | High | UPX, MPRESS, Themida, VMProtect, Enigma section names **or** Shannon entropy ≥ 6.8 |
| PE structural anomalies | T1027 | Medium–High | W+X sections, EP outside sections, virtual-only sections, large virtual/raw ratio, absent Rich header |
| Overlay data | T1027.009 | High | Bytes appended after the last section — dropper/second-stage channel |
| TLS callbacks | T1055.005 | High | Callbacks executing before the PE entry point — anti-debug staging area |
| Anti-debug API imports | T1622 | Medium | `IsDebuggerPresent`, `NtQueryInformationProcess`, `QueryPerformanceCounter`, `FindWindowA`, timing checks, 25+ more |
| Process hollowing cluster | T1055.012 | High | ≥ 3 of: `NtUnmapViewOfSection`, `WriteProcessMemory`, `SetThreadContext`, `VirtualAllocEx`, `ResumeThread`, 8 more |
| Network / C2 strings | T1071.001 | Medium | `http://`, `https://`, `.onion`, `User-Agent:`, `/beacon`, `/implant`, `meterpreter`, `reverse_tcp`, 15+ more |
| Persistence strings | T1547.001 | High | `CurrentVersion\Run`, `Winlogon\Userinit`, `schtasks /create`, WMI event filters, `AppInit_DLLs`, COM `InprocServer32` |
| Ransomware strings | T1486 | High | `.wncry`, `.locked`, `HOW_TO_DECRYPT`, `bitcoin`, `monero`, `.onion`, `YOUR_FILES_ARE_ENCRYPTED`, 20+ more |
| Credential / secret strings | T1552.001 | High | `password=`, `api_key=`, `AKIA` (AWS key prefix), `-----BEGIN`, `Authorization: Bearer`, JWT prefix, DB connection strings |
| .NET anomalies | T1027 | Medium | Managed binary with native TLS callbacks or overlay — mixed-mode loader / dropper pattern |
| AV exclusion strings | T1562.001 | Medium | Defender, Kaspersky, McAfee, Sophos, ESET, Bitdefender registry path fragments |
| QWCrypt / RedCurl IOCs | T1486 | High | `.qwCrypt`, `rbcw`, `excludeVM`, `ZAM64`, `zamguard`, `workers.dev` |

Detections are sorted by MITRE technique ID — output is deterministic and diff-friendly across runs.

---

## Install

```toml
[dependencies]
pe-core     = "0.1"
pe-analysis = "0.1"
```

The two crates are intentionally separate. `pe-core` is a zero-IO, medium-agnostic parser: it accepts `&[u8]` or a file path and returns a `PeFile` struct. `pe-analysis` contains the detectors; they are pure functions over `&PeFile` with no I/O of their own. You can use `pe-core` alone if you only need structured PE metadata.

---

## What you get from `PeFile`

```rust
pub struct PeFile {
    pub machine: u16,            // 0x8664 AMD64 | 0x014C x86 | 0xAA64 ARM64
    pub compile_timestamp: u32,  // COFF timestamp — frequently zeroed or faked
    pub is_dll: bool,
    pub is_exe: bool,
    pub imports: Vec<String>,    // all imported symbol names
    pub exports: Vec<String>,    // exported symbol names (DLLs)
    pub sections: Vec<PeSection>,
    pub ascii_strings: Vec<String>,   // printable ASCII runs ≥ 6 chars
    pub utf16_strings: Vec<String>,   // UTF-16LE runs ≥ 6 chars
    pub sha256: String,          // hex-encoded SHA-256 of the full binary
    pub size: usize,
}

pub struct PeSection {
    pub name: String,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub virtual_address: u32,
    pub entropy: f32,            // Shannon entropy 0.0 – 8.0
    pub is_executable: bool,
    pub is_writable: bool,
    pub is_readable: bool,
}
```

---

## Architecture

```
exec-pe-forensic
├── pe-core        PARSER layer — accepts &[u8] or Path, no CONTAINER/FS dependencies
│   ├── parser     goblin::pe::PE → PeFile struct (imports, sections, strings, SHA-256)
│   └── strings    extract_ascii / extract_utf16le / compute_entropy
└── pe-analysis    detectors — pure fn(&PeFile) -> Vec<PeDetection>
    ├── suspicious_imports   SUSPICIOUS_IMPORT_NAMES from forensicnomicon
    ├── packed               PACKED_SECTION_NAMES + entropy threshold
    ├── av_exclusion         AV_EXCLUSION_PATH_FRAGMENTS from forensicnomicon
    └── ioc                  QWCRYPT_PE_STRING_IOCS from forensicnomicon
```

Format constants and IOC lists live in [`forensicnomicon`](https://github.com/SecurityRonin/forensicnomicon) — a zero-dependency, compile-time knowledge crate. Updating an IOC list means bumping `forensicnomicon`, not touching any parsing logic.

---

## 66 tests, strict TDD

Every detector was written test-first (red commit before green). Real corpus validation supplements the unit suite.

```
cargo test
```

---

[Privacy Policy](https://securityronin.github.io/exec-pe-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/exec-pe-forensic/terms/) · © 2026 Security Ronin Ltd
