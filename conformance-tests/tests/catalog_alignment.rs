//! Ensures every catalog case id is wired to a `conformance_case!` marker
//! in at least one conformance test in this crate.
//!
//! The shared catalog is the sole source of truth — if a case is added to
//! `oauth-sdk-conformance-catalog.yaml` and no Rust test claims it, the
//! workspace build breaks here. That is the intended failure mode: it
//! forces the SDK author to port the new case rather than let the Rust
//! SDK silently fall behind the shared catalog.

use authplane_conformance_tests::{
    catalog_path, catalog_path_is_explicit, load_catalog_case_ids, load_source_case_ids,
};
use std::collections::HashSet;

#[test]
fn catalog_case_ids_are_represented_in_conformance_tests() {
    let catalog = catalog_path();
    if !catalog.exists() {
        // A configured-but-missing catalog is a broken harness, not an absent
        // one: something set the env var and the file still is not there. This
        // used to skip unconditionally, which meant CI could report success
        // having asserted nothing — the one failure mode this test exists to
        // rule out. Fail, and say it is a harness problem so the drift
        // workflow does not misreport it as catalog drift.
        assert!(
            !catalog_path_is_explicit(),
            "harness problem: the conformance catalog was configured explicitly but is not at {} \
             — check the catalog fetch step, not the catalog itself.",
            catalog.display()
        );
        // No env var set: a developer working against only this repo, without
        // the sibling `conformance` checkout. Ordinary, so skip. Every CI job
        // that runs this suite sets CONFORMANCE_CATALOG_PATH and so takes the
        // branch above instead.
        eprintln!(
            "skipping: catalog not found at {} — set CONFORMANCE_CATALOG_PATH or check out AuthPlane/conformance alongside this repo.",
            catalog.display()
        );
        return;
    }

    let catalog_ids = load_catalog_case_ids(&catalog);
    assert!(
        !catalog_ids.is_empty(),
        "catalog at {} yielded zero case ids — parser drift?",
        catalog.display()
    );

    // Multiple tests can claim the same catalog case — "accept" and
    // "reject" paths are often separate test bodies referencing one
    // case id. The check we
    // actually care about is coverage (catalog → source, then
    // source → catalog), not uniqueness.
    let pairs = load_source_case_ids();
    let source_ids: HashSet<String> = pairs.into_iter().map(|(id, _)| id).collect();

    let missing: Vec<&String> = catalog_ids
        .iter()
        .filter(|id| !source_ids.contains(*id))
        .collect();
    assert!(
        missing.is_empty(),
        "catalog cases without a conformance_case! marker in tests/*.rs: {missing:?}"
    );

    let catalog_set: HashSet<&String> = catalog_ids.iter().collect();
    let orphan: Vec<&String> = source_ids
        .iter()
        .filter(|id| !catalog_set.contains(*id))
        .collect();
    assert!(
        orphan.is_empty(),
        "conformance_case! markers with no matching catalog case: {orphan:?}"
    );
}
