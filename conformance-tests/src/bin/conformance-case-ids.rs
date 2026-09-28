//! Write the record of which catalog cases this suite registers, as JSON on
//! stdout.
//!
//! This is the extractor half of the case-body drift check;
//! `.github/scripts/conformance-registered-case-ids.sh` reads what it writes.
//! The split is deliberate: keeping the run separate from the read lets that
//! script's guards be exercised against fixture reports, with no toolchain and
//! no catalog, the way the rest of those controls are.
//!
//! The report is built by [`case_id_report`], which calls
//! [`load_source_case_ids`] — the same function the `catalog_alignment` test
//! uses — rather than re-deriving the ids with a second scanner. A second
//! extractor could disagree with the first, and the direction that hurts is the
//! quiet one: an id it fails to see is a case the drift check silently stops
//! guarding. Sharing the function makes that disagreement impossible, and it is
//! what makes `catalog_alignment` a check on this output too, since that test
//! asserts the same set matches the catalog in both directions.
//!
//! Reporting the source file per marker is not decoration. It is the evidence
//! that an id came from a real marker in a real file, and it is what a
//! maintainer needs first when the drift check names a case.
//!
//! [`load_source_case_ids`]: authplane_conformance_tests::load_source_case_ids

use authplane_conformance_tests::case_id_report;
use std::io::Write;

fn main() {
    let report = case_id_report();
    let cases = report["cases"]
        .as_array()
        .expect("the case-id report carries a cases array");

    // Nothing found means the scan is looking at the wrong tree, or the marker
    // spelling moved and the scan did not follow. Either way the id list
    // downstream would be empty, and an empty id list makes the drift check
    // vacuously green — the one failure it exists to prevent. Refuse here, at
    // the point where the cause is still visible.
    if cases.is_empty() {
        eprintln!(
            "error: no conformance_case! marker was found in conformance-tests/tests/. \
             Either the suite registers nothing or the marker scan no longer matches it; \
             a drift check restricted to this list would be vacuously green."
        );
        std::process::exit(1);
    }

    let mut out = std::io::stdout();
    serde_json::to_writer_pretty(&mut out, &report).expect("write the case-id report");
    writeln!(out).expect("terminate the case-id report");
}
