//! Compile-tested anchor for the canonical "Three-mode inbound DPoP
//! dispatch" doc.
//!
//! The prose + fences live in `core/docs/three_mode_dpop.md` and are pulled
//! in via `include_str!` below so `cargo test --doc -p authplane-sdk`
//! exercises every `rust` fence in that file. If the live API drifts away
//! from the documented signatures (as it did during the three-mode dispatch
//! refactor), the doctest turns into a CI failure rather than a
//! silently-stale doc.
//!
//! `core/docs/user-guide.md` links to the same markdown file rather than
//! re-stating it, so the user-facing doc and the doctested source can't
//! diverge.
//!
//! This module has no runtime surface — it exists purely so rustdoc has
//! somewhere to attach the markdown.

#![doc = include_str!("../docs/three_mode_dpop.md")]
