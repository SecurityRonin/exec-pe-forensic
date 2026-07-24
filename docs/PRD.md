# exec-pe-forensic — Purpose & Scope

*This is a **library** repo — its crates are linked by other tools, not run by an
examiner. Per the fleet PRD & ADR Standard (`ronin-issen/CLAUDE.md`), a library
carries a lighter `docs/PRD.md` (Purpose & Scope) rather than a full
product-requirements document. The load-bearing decisions live as ADRs under
[`docs/decisions/`](decisions/). Every claim below is grounded in a same-session
read of the repo (2026-07-24).*

## What it is

`exec-pe-forensic` is a two-crate Rust workspace for forensic analysis of Windows
PE (Portable Executable) binaries:

- **`exec-pe-core`** — a zero-I/O, medium-agnostic PE parser. `parse_pe(&[u8])`
  and `parse_pe_path(path)` return a `PeFile`: machine type, compile timestamp,
  entry-point RVA and image base, DLL/EXE and .NET/signed/reloc flags, TLS
  callback count, imports and exports, the section table with per-section
  Shannon entropy and R/W/X flags, embedded PDB path, overlay offset/size, the
  decoded Rich header, extracted ASCII and UTF-16LE strings, and the SHA-256 of
  the full binary. It also computes structural anomalies (`PeAnomaly`) and emits
  them as canonical `forensicnomicon::report::Finding`s
  ([ADR 0005](decisions/0005-canonical-report-finding-observation.md)).
- **`exec-pe-analysis`** — fifteen pure-function detectors over a `PeFile`,
  aggregated by `detect_all`, each tagged with a MITRE ATT&CK technique ID:
  suspicious imports (T1055/T1134), packing (T1027.002), structural anomalies
  (T1027), overlay (T1027.009), TLS callbacks (T1055.005), anti-debug (T1622),
  process-hollowing clusters (T1055.012), network/C2 (T1071.001), persistence
  (T1547.001), ransomware (T1486), ransom-note filenames (T1486), credentials
  (T1552.001), .NET anomalies (T1027), AV exclusions (T1562.001), and
  QWCrypt/RedCurl IOCs (T1486). Output is sorted by technique ID —
  deterministic and diff-friendly.

## Who links it

- **Fleet ORCHESTRATION** (Issen and other analyzers) that need PE metadata and
  MITRE-tagged detections folded into a unified `forensicnomicon::report::Report`.
- **Rust developers and DFIR tooling** wanting structured PE parsing without a
  Python runtime — `exec-pe-core` alone for metadata, plus `exec-pe-analysis`
  for detections.
- **Medium-agnostic callers** — because the parser takes `&[u8]`, the same code
  runs over a disk file, a memory-carved fragment, an AFF4 stream, or a network
  capture ([ADR 0001](decisions/0001-two-crate-reader-detector-split.md)).

## Scope

- Parse the PE/COFF container to a `PeFile` (via `goblin`,
  [ADR 0003](decisions/0003-reuse-goblin-for-pe-parsing.md)), including the
  forensic detail a happy-path reader hides: the raw Rich header and appended
  overlay bytes.
- Compute Shannon entropy per section and extract ASCII/UTF-16LE strings
  (minimum run length 6, `strings(1)`-style;
  `crates/exec-pe-core/src/strings.rs`).
- Run heuristic and IOC detectors whose reference tables live in
  `forensicnomicon`, not in-repo
  ([ADR 0004](decisions/0004-knowledge-as-code-forensicnomicon.md)).
- Emit findings as observations with MITRE references framed as "consistent
  with" — never as verdicts.

## Non-goals

- **No I/O beyond reading input bytes.** Detectors are pure functions; there is
  no container, filesystem, memory-paging, or network layer here (PARSER-layer
  dependency rule, [ADR 0001](decisions/0001-two-crate-reader-detector-split.md)).
- **No runnable binary.** No `<x>4n6` CLI, GUI, or MCP server — the user-facing
  surface lives in ORCHESTRATION (Issen). This is why the repo is library tier
  and this document is Purpose & Scope, not a product PRD.
- **No unpacking, emulation, or dynamic analysis.** Detection is static: header
  fields, section attributes, imports, entropy, and strings. A packed payload is
  flagged, not unpacked.
- **No verdicts.** The crates produce graded observations and MITRE technique
  references; whether conduct is malicious is for the analyst/tribunal.
- **No hand-rolled cryptography or PE decoding** — SHA-256 via `sha2`, PE
  structure via `goblin`.

## Validation approach

Every detector was written test-first (RED commit before GREEN — visible in the
git history, e.g. `test(pe-analysis): RED …` preceding each `feat(...): GREEN
…`); the canonical-finding mapping is covered by
`crates/exec-pe-core/tests/canonical_finding_tests.rs`. The README reports a
66-test unit suite plus real-corpus validation. Because these crates parse
untrusted input, safety and panic-freedom are enforced statically
(`unsafe_code = deny`, `unwrap_used = deny`;
[ADR 0006](decisions/0006-safety-and-panic-posture.md)); a `cargo-fuzz` target
to earn the empirical robustness half is not yet present in the repo.
