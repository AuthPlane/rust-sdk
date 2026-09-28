//! Conformance test harness for the AuthPlane Rust SDK.
//!
//! # Design
//!
//! Tests in this crate trace to cases in `oauth-sdk-conformance-catalog.yaml`.
//! The mapping lives inline in each test, expressed via [`conformance_case`]:
//!
//! ```ignore
//! #[tokio::test]
//! async fn rfc8414_metadata_issuer_must_match_configured_issuer() {
//!     conformance_case!("rfc8414-metadata-issuer-must-match-configured-issuer");
//!     // body with real assertions
//! }
//! ```
//!
//! The `catalog_alignment` integration test parses every `tests/*.rs`
//! file in this crate, extracts the case IDs passed to
//! `conformance_case!`, and diffs them against the catalog. A missing case
//! id fails the build.
//!
//! # Rules (from the `conformance-testing` skill)
//!
//! - The catalog is the **sole source of truth**. Assertions trace to
//!   `expected.result_contains` / `result_shape` / `outcome`.
//! - Never weaken an assertion to make a failing test pass — stop and
//!   escalate to a human.
//! - Never edit the catalog yourself; only humans approve catalog edits.
//!
//! # Catalog location
//!
//! Resolved in this order:
//!   1. `CONFORMANCE_CATALOG_PATH` env var (absolute path to the YAML).
//!   2. `AUTHPLANE_CONFORMANCE_CATALOG` env var (legacy).
//!   3. `<repo>/../conformance/oauth-sdk-conformance-catalog.yaml`
//!      (a sibling checkout, for working against only this repo).
//!
//! CI never relies on (3): `ci.yml`, `release.yml` and the drift workflow all
//! fetch the catalog into the runner temp directory and set
//! `CONFORMANCE_CATALOG_PATH`. The revision they fetch is pinned in the tracked
//! `.conformance-catalog-ref` at the repo root — bump it together with the
//! coverage for any newly adopted cases, so a catalog change alone can never
//! break CI.

use std::path::{Path, PathBuf};

/// Env vars naming the catalog explicitly, in precedence order: the canonical
/// spelling first, the legacy spelling second. Set by every CI job that runs
/// this suite, pointing at the checkout the pinned `.conformance-catalog-ref`
/// fetch produced.
///
/// This list is the single source for both [`catalog_path_is_explicit`] and
/// [`catalog_path`]. The two functions must agree on what counts as an
/// explicit configuration — if they ever diverged, a set-but-missing catalog
/// could take the silent skip path, which is exactly the failure mode the
/// fail-loud guard exists to rule out. Add new sources here, not in either
/// function.
pub const CATALOG_PATH_ENVS: [&str; 2] =
    ["CONFORMANCE_CATALOG_PATH", "AUTHPLANE_CONFORMANCE_CATALOG"];

/// Marker recorded at the top of each conformance test body.
///
/// The value is intentionally bound to an unused local so rustc does not
/// warn, and emitted via `let _: &'static str = ...;` so the string is
/// still a textual literal in the source file — which is what the
/// `catalog_alignment` test scans for.
///
/// Keeping this a `macro_rules!` (rather than a fn) means there is no way
/// to pass a non-literal as the case id — catalog IDs must appear
/// verbatim in test sources.
#[macro_export]
macro_rules! conformance_case {
    ($case_id:literal) => {
        let _: &'static str = $case_id;
    };
}

/// Whether the catalog location was configured explicitly, via either env var,
/// rather than falling back to the sibling-checkout default.
///
/// The distinction decides how a missing catalog is treated. An explicit path
/// is a deliberate act — CI wiring — so a file that is not there is a broken
/// harness and must fail loudly. The fallback path is a convenience for a
/// developer working against only this repo, where a missing sibling checkout
/// is ordinary and skipping is the right answer.
pub fn catalog_path_is_explicit() -> bool {
    CATALOG_PATH_ENVS
        .iter()
        .any(|k| std::env::var_os(k).is_some())
}

/// Resolve the catalog path: first env var in [`CATALOG_PATH_ENVS`] that is
/// set wins; otherwise fall back to the sibling checkout.
///
/// Reads with `var_os`, the same call `catalog_path_is_explicit` uses, so the
/// two functions cannot disagree over a non-UTF-8 value: any value that counts
/// as explicit is also the value that resolves.
pub fn catalog_path() -> PathBuf {
    for key in CATALOG_PATH_ENVS {
        if let Some(path) = std::env::var_os(key) {
            return PathBuf::from(path);
        }
    }
    // <repo>/conformance-tests/src/lib.rs -> <repo>/../conformance/...
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest
        .parent()
        .unwrap_or(&manifest)
        .parent()
        .unwrap_or(&manifest);
    repo_root.join("conformance/oauth-sdk-conformance-catalog.yaml")
}

/// Extract every catalog `id:` value that appears under `cases:` — in
/// document order. A lightweight line scan avoids committing this crate to a
/// full YAML parser, and the catalog's shape is stable by policy — the same
/// scan every harness that reads it uses.
pub fn load_catalog_case_ids(catalog: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(catalog)
        .unwrap_or_else(|e| panic!("cannot read catalog {}: {e}", catalog.display()));
    let cases_section = match text.split_once("cases:") {
        Some((_, rest)) => rest,
        None => panic!("catalog {} has no `cases:` section", catalog.display()),
    };
    let mut ids = Vec::new();
    for line in cases_section.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("- id: \"")
            && let Some(end) = rest.find('"')
        {
            ids.push(rest[..end].to_string());
        }
    }
    ids
}

/// Extract case ids referenced by `conformance_case!("...")` in every
/// `tests/*.rs` source file in this crate. Returns them as a `Vec` so the
/// alignment test can surface duplicates as well as missing coverage.
pub fn load_source_case_ids() -> Vec<(String, PathBuf)> {
    let tests_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut pairs = Vec::new();
    let iter = std::fs::read_dir(&tests_dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", tests_dir.display()));
    for entry in iter {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        // Strip comment lines, collapse into a single string, and
        // normalize runs of whitespace so `conformance_case!(\n  "…")`
        // matches our marker even after rustfmt splits the call.
        let joined: String = text
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join(" ");
        let collapsed: String = joined.split_whitespace().collect::<Vec<_>>().join(" ");
        let prefix = "conformance_case!(";
        let mut cursor = 0;
        while let Some(pos) = collapsed[cursor..].find(prefix) {
            let after = cursor + pos + prefix.len();
            // Skip optional whitespace between `(` and `"`
            let rest = collapsed[after..].trim_start();
            if let Some(rest) = rest.strip_prefix('"')
                && let Some(end) = rest.find('"')
            {
                pairs.push((rest[..end].to_string(), path.clone()));
            }
            cursor = after + 1;
        }
    }
    pairs
}

/// The registered-case report the drift check consumes: one entry per
/// `conformance_case!` marker occurrence, carrying the id and the `tests/`
/// source file it was found in, relative to the crate root.
///
/// Two tests claiming one case — the accept and the reject path of the same
/// requirement — are two entries, and the consumer deduplicates. Collapsing
/// them here would drop the second source file, which is the one piece of
/// provenance this report carries.
///
/// This lives beside the scan rather than in the binary that prints it so the
/// report's shape is asserted by a test instead of agreed by convention. A
/// renamed key would otherwise surface on the next scheduled drift run, a week
/// after the change that broke it, and a `source` that stopped being relative
/// would not surface at all: the reader script checks that it is present and
/// non-empty, not that it points anywhere.
pub fn case_id_report() -> serde_json::Value {
    let crate_root = env!("CARGO_MANIFEST_DIR");
    let cases: Vec<serde_json::Value> = load_source_case_ids()
        .into_iter()
        .map(|(case_id, path)| {
            // Relative to the crate root, so the report does not carry the
            // runner's absolute workspace path into a log. Every path the scan
            // yields is built by joining that root, so a prefix that does not
            // strip means the scan read a tree this function does not know
            // about — say so, rather than emit an absolute path where the
            // consumer documents a relative one.
            let source = path
                .strip_prefix(crate_root)
                .unwrap_or_else(|_| {
                    panic!(
                        "marker source {} is not under the crate root {crate_root}",
                        path.display()
                    )
                })
                .to_string_lossy()
                .into_owned();
            serde_json::json!({ "case_id": case_id, "source": source })
        })
        .collect();
    serde_json::json!({ "cases": cases })
}

#[cfg(test)]
mod tests {
    use super::case_id_report;
    use std::path::Path;

    /// The reader script requires a non-empty `case_id` and a non-empty
    /// `source` on every entry, and nothing else asserts even that much: the
    /// shell controls run the reader against hand-written fixtures, and clippy
    /// only compile-checks the writer. The path assertions go further than the
    /// reader does on purpose — `source` is provenance, so it has to name a
    /// test file that is really there, which the reader cannot tell.
    #[test]
    fn every_report_entry_names_a_case_and_the_test_file_it_came_from() {
        let report = case_id_report();
        let cases = report["cases"]
            .as_array()
            .expect("the report carries a `cases` array");
        assert!(
            !cases.is_empty(),
            "the report is empty, so a drift check restricted to it would be vacuously green"
        );

        let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
        for case in cases {
            let case_id = case["case_id"]
                .as_str()
                .unwrap_or_else(|| panic!("entry {case} has no string case_id"));
            assert!(!case_id.is_empty(), "entry {case} has an empty case_id");

            let source = case["source"]
                .as_str()
                .unwrap_or_else(|| panic!("entry {case} has no string source"));
            let source = Path::new(source);
            assert!(
                source.is_relative(),
                "entry {case} reports an absolute source; the consumer documents it as relative"
            );
            assert_eq!(
                source.extension().and_then(|e| e.to_str()),
                Some("rs"),
                "entry {case} does not name a Rust source file"
            );
            assert!(
                crate_root.join(source).is_file(),
                "entry {case} names a source that is not a file under {}",
                crate_root.display()
            );
        }
    }
}
