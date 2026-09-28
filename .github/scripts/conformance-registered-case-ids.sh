#!/usr/bin/env bash
#
# Print the conformance case ids THIS suite registers, one per line.
#
# This is the repo-specific half of the case-body drift check: the id source
# depends on how this repo's harness records registrations, so it lives here and
# conformance-case-body-drift.sh stays generic.
#
# There is no runtime registry to read here. Registration is the
# `conformance_case!` marker at the top of each test body, and the marker is a
# `macro_rules!` taking a `literal` — deliberately, so the id has to appear
# verbatim in the source and can be recovered by scanning it. The scan lives in
# `load_source_case_ids()` in conformance-tests/src/lib.rs, and the
# `conformance-case-ids` binary in the same crate runs it and writes the JSON
# this script reads.
#
# Reusing that function rather than grepping the sources here is the whole point.
# A second extractor can disagree with the first, and the direction that hurts is
# the quiet one: an id it fails to see is a case this check silently stops
# guarding. It is not hypothetical — rustfmt splits ten of the markers in this
# suite across lines, and a line-at-a-time grep finds 100 of the 107 ids while
# `load_source_case_ids()` finds all 107. Sharing the function also means the
# `catalog_alignment` test is a check on this list, since it asserts that exact
# set matches the catalog in both directions.
#
# Requires the report to have been produced from this commit's sources; the
# drift workflow writes it in the step before this one.
#
# Inputs (environment):
#   CONFORMANCE_CASE_IDS  path to the report the binary writes
#                         (default: $GITHUB_WORKSPACE/conformance-case-ids.json)
#
# Exit status:
#   0  ids printed on stdout
#   1  the report is missing, unreadable, or holds no registered case

set -euo pipefail

REPORT="${CONFORMANCE_CASE_IDS:-${GITHUB_WORKSPACE:-.}/conformance-case-ids.json}"

fail() {
  echo "::error::$1" >&2
  exit 1
}

if ! command -v jq > /dev/null 2>&1; then
  fail "registered case ids: jq is not available, so the case-id report cannot be read."
fi

if [[ ! -f "$REPORT" ]]; then
  fail "registered case ids: '$REPORT' does not exist. The conformance-case-ids binary writes it, so either that step did not run or it failed before writing."
fi

if ! jq -e . "$REPORT" > /dev/null 2>&1; then
  fail "registered case ids: '$REPORT' is not valid JSON. A truncated report is what a binary that died mid-write leaves behind; it is not an empty registration list."
fi

if ! jq -e '(.cases | type) == "array" and (.cases | length) > 0' "$REPORT" > /dev/null 2>&1; then
  fail "registered case ids: '$REPORT' has no non-empty .cases array, so no conformance marker registered. Any check restricted to this list would be vacuously green."
fi

# Every entry is a marker the scan actually found, so every entry must carry a
# case id and the file it came from. An entry missing either is not a case that
# happens not to be registered — it is the extractor's contract having changed
# under this script, and the list it produces can no longer be trusted.
if ! jq -e 'all(.cases[]; (.case_id | type) == "string" and (.case_id | length) > 0)' "$REPORT" > /dev/null 2>&1; then
  fail "registered case ids: '$REPORT' holds a case entry with a missing or non-string case_id."
fi

if ! jq -e 'all(.cases[]; (.source | type) == "string" and (.source | length) > 0)' "$REPORT" > /dev/null 2>&1; then
  fail "registered case ids: '$REPORT' holds a case entry with no source file. Every entry comes from a marker found in a file, so an entry without one means the extractor no longer reports what it matched."
fi

ids="$(jq -r '.cases[] | .case_id' "$REPORT" | sort -u)"

if [[ -z "$ids" ]]; then
  fail "registered case ids: '$REPORT' yielded no case id. Any check restricted to this list would be vacuously green."
fi

printf '%s\n' "$ids"
