# 6. Safety and panic posture: `unsafe_code = deny`, `unwrap_used = deny`

Date: 2026-07-24

Status: Accepted

## Context

Both crates parse untrusted, attacker-controllable input — a PE binary from an
evidence image can be truncated, malformed, or crafted to break a parser. The
fleet Paranoid Gatekeeper standard (`ronin-issen/CLAUDE.md`) and the global
lint recipe (`CLAUDE.core.md`, "Rust Lint Posture") require such crates to never
execute `unsafe`, never panic on bad input, and enforce both statically at the
workspace level.

## Decision

Set workspace lints once, inherited by every member via `[lints] workspace =
true` (`Cargo.toml`):

- `unsafe_code = "deny"` (`[workspace.lints.rust]`).
- `clippy::all` + `clippy::pedantic` at `warn`, and `unwrap_used = "deny"`
  (`[workspace.lints.clippy]`).

The tree contains no `unsafe` blocks (a repo-wide search for `unsafe` in
`crates/` returns nothing), and no per-site `#[allow(unsafe_code)]` exists.
Parsing failures are returned as typed errors (`PeError::NotPe` /
`PeError::Structure`, `crates/exec-pe-core/src/error.rs`), not panics, and
pedantic cast lints are opted out narrowly at each crate's `lib.rs`
(`cast_possible_truncation`, `cast_sign_loss`, `cast_precision_loss`) where
entropy and offset arithmetic makes them noise.

## Consequences

Memory safety is enforced by construction and `unwrap` is barred from production
code, matching the fleet posture for untrusted-input parsers. Because the tree
has zero `unsafe` and zero allow sites, the stricter `unsafe_code = "forbid"`
(the fleet default and stated goal, which a `deny` merely approximates) would
currently hold with no code change; the choice of `deny` over `forbid` here has
no recovered rationale (**rationale reconstructed from structure; original
intent not recovered in available history**) and could be tightened to `forbid`
in a follow-up. The panic-free posture is enforced statically only; there is no
`fuzz.yml` / `cargo-fuzz` target in the repo yet, so the empirical
(fuzzed-execs) half of the fleet robustness claim is not yet earned here.
