# 2. Crate naming: `exec-pe-*` prefix, `-analysis` suffix

Date: 2026-07-24

Status: Accepted

## Context

The crates were first published under the bare `pe-core` / `pe-analysis` names
(commit history: `test(pe-core, pe-analysis): RED …` and later
`refactor(naming): pe-core/pe-analysis -> exec-pe-core/exec-pe-analysis`,
commit `220d5d4`). A bare `pe-` prefix is a generic-word namespace on crates.io
— read out of any repo context it does not self-describe and collides with the
broad space of "pe" tooling. The fleet naming grammar
(`ronin-issen/CLAUDE.md`, "Crate naming grammar") requires a suite prefix to be
"self-describing on crates.io" and steers a generic-word prefix to the fuller
`<repo>-*` form. Separately, this repo is a multi-crate PARSER suite whose
second crate performs *semantic analysis* (PE structure → MITRE ATT&CK
technique IDs), which the grammar's suffix table maps to `-analysis`, not the
Pattern-A single-format `-forensic` analyzer slot.

## Decision

Adopt the repo/suite prefix `exec-pe-` and keep the semantic-analysis suffix:

- `exec-pe-core` — the reader (`crates/exec-pe-core/Cargo.toml`,
  `name = "exec-pe-core"`).
- `exec-pe-analysis` — the detector suite (`crates/exec-pe-analysis/Cargo.toml`,
  `name = "exec-pe-analysis"`), named `-analysis` because it maps PE features to
  ATT&CK techniques rather than reading one format's structure.

The repo is `exec-pe-forensic`; there is no `exec-pe-forensic` *crate* (Pattern
B: the umbrella repo name is not itself a crate).

## Consequences

Both crate names self-describe on crates.io and read unambiguously in a
dependency list. The rename happened before the crates accrued external
dependents, so it was clean (the crates.io 72-hour rename window; no orphaned
name). Choosing `-analysis` over `-forensic` signals the semantic-analysis role
and keeps the `-forensic` crate name reserved for the Pattern-A one-reader/
one-analyzer shape it denotes elsewhere in the fleet.
