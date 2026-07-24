# 1. Two-crate reader/detector split, medium-agnostic PARSER layer

Date: 2026-07-24

Status: Accepted

## Context

PE forensic analysis has two separable concerns: turning raw bytes into a
structured `PeFile` (imports, sections, entropy, strings, Rich header, overlay,
SHA-256), and *interpreting* that structure into MITRE-tagged detections. A
consumer that only needs structured PE metadata (e.g. an indexer computing
section entropy) should not have to compile fifteen malware detectors, and the
detectors should not be coupled to any particular byte source. The fleet layer
model (`ronin-issen/CLAUDE.md`, "Multi-Repo Architecture") places both concerns
in the PARSER layer, which "depends on KNOWLEDGE only; accepts `Path` or `&[u8]`
— never imports CONTAINER, FILESYSTEM, PAGING, OS STRUCTURE, or LOG FORMAT
crates."

## Decision

Ship two crates in one workspace (`Cargo.toml` members
`crates/exec-pe-core`, `crates/exec-pe-analysis`):

- **`exec-pe-core`** — the zero-I/O reader. `parse_pe(&[u8])` and
  `parse_pe_path(path)` return a `PeFile` (`crates/exec-pe-core/src/parser.rs`);
  its doc comment states it is "medium-agnostic: accepts raw `&[u8]` bytes from
  any source — disk file, memory dump page, AFF4 stream, network capture, or
  carved fragment" (`crates/exec-pe-core/src/lib.rs`). It also owns pure
  structural anomaly computation (`anomalies.rs`) and string/entropy extraction
  (`strings.rs`).
- **`exec-pe-analysis`** — the detectors. Every detector is a pure
  `fn(&PeFile) -> Vec<PeDetection>` with no I/O, aggregated by `detect_all`
  (`crates/exec-pe-analysis/src/lib.rs`); it depends on `exec-pe-core`
  (`crates/exec-pe-analysis/Cargo.toml`).

Neither crate depends on any CONTAINER or FILESYSTEM crate; the only downward
dependencies are `forensicnomicon` (KNOWLEDGE) and third-party parsing/hashing
crates.

## Consequences

A downstream tool can link `exec-pe-core` alone for structured metadata, or add
`exec-pe-analysis` for detections — the README documents exactly this ("You can
use `exec-pe-core` alone if you only need structured PE metadata"). Because the
detectors take a `PeFile` and never touch I/O, the same analysis runs over a
disk file, a memory-carved fragment, or a network capture without change. The
split must stay acyclic: shared domain types live in `exec-pe-core`, and the
analysis crate never re-implements parsing.
