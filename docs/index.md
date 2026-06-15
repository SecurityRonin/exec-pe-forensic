# exec-pe-forensic

**Parse a Windows PE binary and get MITRE-tagged forensic detections in three lines of Rust.**

```rust
use pe_core::parser::parse_pe_path;
use pe_analysis::detect_all;

let pe = parse_pe_path("suspicious.exe")?;
for hit in detect_all(&pe) {
    println!("[{}] {} — {}", hit.mitre_technique_id, hit.tactic, hit.description);
}
```

```text
[T1027.002] defense-evasion — Packed/protected section 'UPX0' (entropy 7.82, known packer name)
[T1055]     defense-evasion — Suspicious API import: 'VirtualAllocEx'
[T1055]     defense-evasion — Suspicious API import: 'WriteProcessMemory'
[T1055]     defense-evasion — Suspicious API import: 'CreateRemoteThread'
[T1486]     impact          — QWCrypt/RedCurl IOC '.qwCrypt' found in PE string table
[T1562.001] defense-evasion — AV exclusion fragment 'Windows Defender\Exclusions' found in PE string table
```

## Install

```toml
[dependencies]
pe-core     = "0.1"
pe-analysis = "0.1"
```

The two crates are intentionally separate. `pe-core` is a zero-IO, medium-agnostic parser: it accepts `&[u8]` or a file path and returns a `PeFile` struct. `pe-analysis` contains the detectors; they are pure functions over `&PeFile` with no I/O of their own. You can use `pe-core` alone if you only need structured PE metadata.

## What it detects

`pe-analysis` runs pure-function detectors over a parsed `PeFile`, each tagged with its MITRE ATT&CK technique:

- **Suspicious imports** — process-injection and evasion API names (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, …)
- **Packed/protected sections** — known packer section names plus an entropy threshold
- **AV-exclusion fragments** — defender-exclusion path strings embedded in the binary
- **IOC strings** — QWCrypt/RedCurl and related campaign indicators in the PE string table

## Architecture

```text
exec-pe-forensic
├── pe-core        PARSER layer — accepts &[u8] or Path, no CONTAINER/FS dependencies
│   ├── parser     goblin::pe::PE → PeFile struct (imports, sections, strings, SHA-256)
│   └── strings    extract_ascii / extract_utf16le / compute_entropy
└── pe-analysis    detectors — pure fn(&PeFile) -> Vec<PeDetection>
```

Format constants and IOC lists live in [`forensicnomicon`](https://github.com/SecurityRonin/forensicnomicon), a zero-dependency, compile-time knowledge crate. Updating an IOC list means bumping `forensicnomicon`, not touching any parsing logic.

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · [GitHub](https://github.com/SecurityRonin/exec-pe-forensic) · © 2026 Security Ronin Ltd
