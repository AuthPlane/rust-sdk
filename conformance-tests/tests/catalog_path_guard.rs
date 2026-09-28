//! Pins the fail-loud guard's precedence/explicitness contract:
//! `catalog_path_is_explicit` and `catalog_path` must agree on what counts as
//! an explicit catalog configuration. If they diverge, a set-but-missing
//! catalog takes `catalog_alignment`'s silent skip path — the regression the
//! guard exists to rule out — with CI green and nothing failing.
//!
//! Env vars are process-global, so the assertions live in a single `#[test]`
//! in their own integration-test target: this process runs nothing else, so
//! no other test can observe the mutations.

use authplane_conformance_tests::{CATALOG_PATH_ENVS, catalog_path, catalog_path_is_explicit};
use std::path::Path;

fn clear_all() {
    for key in CATALOG_PATH_ENVS {
        // SAFETY: single-test target — no concurrent reader of these vars.
        unsafe { std::env::remove_var(key) };
    }
}

#[test]
fn explicitness_and_resolution_read_the_same_sources() {
    let [canonical, legacy] = CATALOG_PATH_ENVS;

    // Each source alone both counts as explicit and resolves — a source that
    // satisfied one function but not the other is the divergence this test
    // exists to catch.
    for key in CATALOG_PATH_ENVS {
        clear_all();
        // SAFETY: single-test target — no concurrent reader of these vars.
        unsafe { std::env::set_var(key, "/nonexistent/from-guard-test.yaml") };
        assert!(
            catalog_path_is_explicit(),
            "{key} set but catalog_path_is_explicit() is false"
        );
        assert_eq!(
            catalog_path(),
            Path::new("/nonexistent/from-guard-test.yaml"),
            "{key} set but catalog_path() resolved elsewhere"
        );
    }

    // The canonical spelling wins over the legacy one.
    clear_all();
    // SAFETY: single-test target — no concurrent reader of these vars.
    unsafe {
        std::env::set_var(canonical, "/nonexistent/canonical.yaml");
        std::env::set_var(legacy, "/nonexistent/legacy.yaml");
    }
    assert_eq!(catalog_path(), Path::new("/nonexistent/canonical.yaml"));

    // With no source set, resolution falls back to the sibling checkout and
    // must NOT count as explicit — that is the developer convenience path
    // where skipping on a missing catalog is the right answer.
    clear_all();
    assert!(!catalog_path_is_explicit());
    assert!(
        catalog_path().ends_with("conformance/oauth-sdk-conformance-catalog.yaml"),
        "fallback should point at the sibling checkout, got {}",
        catalog_path().display()
    );
}
