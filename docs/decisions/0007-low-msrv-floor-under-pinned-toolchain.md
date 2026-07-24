# 7. Low MSRV floor (1.80) under a pinned dev toolchain

Date: 2026-07-24

Status: Accepted

## Context

Both crates are published libraries — things a third-party developer *links*,
not a binary an examiner runs. The fleet MSRV policy
(`CLAUDE.core.md`, "Rust MSRV & Toolchain Policy"; `CLAUDE.personal.md`, fleet
specifics) separates the *dev toolchain* (one pinned current stable across the
fleet, for build/fmt/clippy consistency) from the *declared MSRV* (a
downstream-facing compatibility promise). Published libraries keep a deliberately
low, CI-verified MSRV; only apps declare MSRV equal to the pinned toolchain.

## Decision

Declare a low library MSRV and pin the dev toolchain separately:

- `rust-version = "1.80"` in `[workspace.package]` (`Cargo.toml`), inherited by
  both crates via `rust-version.workspace = true`.
- `rust-toolchain.toml` pins the dev/CI toolchain to `1.96.0` with `clippy` and
  `rustfmt` components (commit `f454c3d`, `chore: pin toolchain to 1.96.0 (fleet
  toolchain policy)`).

## Consequences

`exec-pe-core` and `exec-pe-analysis` stay consumable by toolchains as old as
1.80, a compatibility feature for downstream reuse, while every contributor and
CI job builds, formats, and lints on one current stable. Raising the declared
MSRV would narrow the crates' crates.io audience, so it is treated as a
near-breaking change requiring a real newer-Rust-feature need; it is not raised
merely to match the dev pin. The `1.80` floor must stay CI-verified (a dedicated
low-MSRV job) to remain a real guarantee rather than an aspirational number.
