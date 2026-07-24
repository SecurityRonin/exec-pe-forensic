# 3. Reuse goblin for PE structure parsing

Date: 2026-07-24

Status: Accepted

## Context

Decoding the PE/COFF container — DOS stub, PE signature, COFF and optional
headers, section table, import/export directories, TLS and CLR data directories,
Authenticode and debug directories — is a large, well-specified, and
error-prone surface. The fleet discipline (`CLAUDE.core.md`, "Research-First"
and the `unsafe` build-vs-reuse law) is to reuse a mature, maintained crate
rather than hand-roll a parser, reserving a reimplementation for a genuine
C-FFI liability or an absent ecosystem. `goblin` is a pure-Rust, widely-used
multi-format binary parser with full PE32/PE32+ coverage.

## Decision

Parse PE structure with `goblin::pe::PE` (`crates/exec-pe-core/src/parser.rs`,
`use goblin::pe::PE`), pinned in the workspace as
`goblin = { version = "0.10", default-features = false, features = ["pe32",
"pe64", "std"] }` (`Cargo.toml`). The reader keeps a fast, dependency-free
front gate: it rejects any input whose first two bytes are not the `MZ` magic
(`forensicnomicon::heuristics::pe::MZ_MAGIC`) before handing the bytes to
goblin, mapping parse failures to `PeError::NotPe` / `PeError::Structure`
(`crates/exec-pe-core/src/error.rs`). The feature selection is additive — it
enables both PE bit-widths plus `std`, the full capability this crate needs —
not a slimming of the parser.

## Consequences

The crate inherits goblin's maintained, broadly-tested PE decoding and its
little-endian field handling instead of carrying a bespoke offset-and-endianness
parser. Forensic detail that goblin abstracts away (the raw Rich header between
the DOS stub and PE signature, the overlay bytes after the last section) is
computed directly by `exec-pe-core` (`rich_header.rs`, overlay logic in
`parser.rs`), because a happy-path reader does not surface it. The crate tracks
goblin's release cadence and API for PE changes.
