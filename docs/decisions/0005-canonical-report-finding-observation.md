# 5. Emit canonical `report::Finding` via the `Observation` trait

Date: 2026-07-24

Status: Accepted

## Context

The fleet reporting model (`ronin-issen/CLAUDE.md`, "The Reporting Model —
`forensicnomicon::report`") requires every analyzer to emit its findings as one
normalized model — graded `Severity`, a `Category` lens, a scheme-prefixed
`code` contract, MITRE references framed as "consistent with" — so that
ORCHESTRATION (Issen) and a future GUI render N analyzers uniformly instead of N
bespoke `XxxAnalysis` types. The producer pattern is for each analyzer to keep
its typed domain enum and convert to canonical findings via
`impl forensicnomicon::report::Observation`. This crate initially exposed only
its own `PeAnomaly` enum (commit `test(pe-core): RED — PeAnomaly -> canonical
report::Finding`, `3e3726b`).

## Decision

Keep the domain-typed `PeAnomaly` enum as the structural-anomaly vocabulary and
implement `forensicnomicon::report::Observation` for it
(`crates/exec-pe-core/src/anomalies.rs`), grading each variant
(`EntryPointOutsideSections` → `Severity::High`; W+X / virtual-only / large
v/r-ratio → `Medium`; TLS callbacks / overlay / absent Rich header → `Low`),
assigning a `Category` (`Structure` / `Concealment` / `Residue`), a stable
scheme-prefixed `code` (`PE-WX-SECTION`, `PE-ENTRYPOINT-OOB`,
`PE-VIRTUAL-ONLY-SECTION`, `PE-VSIZE-RATIO`, `PE-TLS-CALLBACKS`, `PE-OVERLAY`,
`PE-RICH-ABSENT`), MITRE technique IDs, and structured `Evidence` with
`Location`. The behavior was landed and gated by a test suite
(`crates/exec-pe-core/tests/canonical_finding_tests.rs`; commit
`feat(pe-core)!: grade PeAnomaly + emit canonical report::Finding`, `4c47752` —
a breaking change, hence the `!`).

## Consequences

`PeAnomaly` output aggregates into a fleet `Report` alongside every other
migrated analyzer with no bespoke adapter. The `code` strings are now a
published contract: they must never change once shipped; new anomaly variants
get new codes. The `exec-pe-analysis` detectors currently return their own
`PeDetection` type (MITRE ID + tactic + evidence) rather than canonical
`Finding`s — a future migration can bring them under the same `Observation`
producer pattern. `exec-pe-core` therefore depends on `forensicnomicon::report`
as well as its heuristic tables.
