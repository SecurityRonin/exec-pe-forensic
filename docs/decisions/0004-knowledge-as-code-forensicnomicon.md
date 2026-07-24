# 4. Heuristics and IOCs as code via forensicnomicon

Date: 2026-07-24

Status: Accepted

## Context

The detectors are driven by reference tables: suspicious import names, packer
section names and the entropy threshold, process-hollowing API clusters,
network/C2 and persistence and ransomware and credential string patterns, AV
exclusion path fragments, ransom-note filenames, and QWCrypt/RedCurl IOCs.
Embedding these tables inside the detector code would fork that knowledge from
the rest of the fleet and let each repo's copy drift. The fleet KNOWLEDGE leaf
`forensicnomicon` exists precisely to hold "compile-time artifact specs, format
constants" and heuristic catalogs as code (`ronin-issen/CLAUDE.md`, layer model
and "The Reporting Model").

## Decision

Consume the heuristic and IOC tables from `forensicnomicon`, not from
in-repo literals. Each detector imports its table from
`forensicnomicon::heuristics::pe` (or `::entropy` / `::ransomware`) — e.g.
`SUSPICIOUS_IMPORT_NAMES` (`suspicious_imports.rs`), `PACKED_SECTION_NAMES` +
`PACKED_SECTION_THRESHOLD` (`packed.rs`), `AV_EXCLUSION_PATH_FRAGMENTS`
(`av_exclusion.rs`), `QWCRYPT_PE_STRING_IOCS` (`ioc.rs`),
`RANSOM_NOTE_FILENAMES` (`ransomware.rs`), and the `MZ_MAGIC` gate in the parser
(`crates/exec-pe-core/src/parser.rs`). The dependency was migrated from a local
path to the published registry crate (commit `af94d0f`,
`build: migrate forensicnomicon to published registry crate`) and pinned as
`forensicnomicon = "1"` (`Cargo.toml`).

## Consequences

An IOC or heuristic list updates once, fleet-wide, in `forensicnomicon`; every
detector picks it up on a version bump with no change to parsing or detection
logic (as the README states: "Updating an IOC list means bumping
`forensicnomicon`, not touching any parsing logic"). Both crates take a
dependency on the catalog crate and its release cadence. Detection code stays
small and reviewable — it holds the matching logic, the catalog holds the facts.
