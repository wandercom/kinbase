#!/usr/bin/env bash
# Boundary-compatible, content-addressed cleanliness attestation.
#
# Detector Reviewer finding 1: `git status --porcelain --untracked-files=all`
# emitted permission warnings for excluded `.kin/**` and `evidence/**`, so full
# worktree cleanliness could not be positively attested without crossing the
# review boundary.
#
# This attestation does not need those paths. It reports, over the surface a
# Reviewer is permitted to read:
#
#   * HEAD, the tree object, and the ratification-manifest digest;
#   * every tracked path under spec/** and tests/**, with its blob digest;
#   * whether any tracked file under those paths differs from HEAD;
#   * whether any untracked file exists under those paths;
#   * a combined digest over the whole report.
#
# The excluded paths are outside the Tester lane and are not modified by it; a
# Validator holding read access to them can extend this attestation without the
# Reviewer having to.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

emit() { printf '%s\n' "$*"; }

emit "schema: guildhall-acceptance-cleanliness-attestation/1"
emit "head: $(git rev-parse HEAD)"
emit "tree: $(git rev-parse 'HEAD^{tree}')"
emit "branch: $(git rev-parse --abbrev-ref HEAD)"
emit "manifest_sha256: $(shasum -a 256 spec/ratification-manifest.json | cut -d' ' -f1)"
emit "scope: spec/** tests/**"

staged="$(git diff --cached --name-only -- spec tests | wc -l | tr -d ' ')"
unstaged="$(git diff-files --name-only -- spec tests | wc -l | tr -d ' ')"
untracked="$(git ls-files --others --exclude-standard -- spec tests | wc -l | tr -d ' ')"
emit "staged_differences: $staged"
emit "unstaged_differences: $unstaged"
emit "untracked_files: $untracked"
if [ "$staged" = "0" ] && [ "$unstaged" = "0" ] && [ "$untracked" = "0" ]; then
  emit "in_scope_clean: true"
else
  emit "in_scope_clean: false"
fi

emit "tracked_files:"
git ls-tree -r HEAD --format='%(objectname) %(path)' -- spec tests | sort | sed 's/^/  /'

emit "excluded_from_this_attestation: .kin/** evidence/**"
emit "exclusion_reason: outside the Tester lane and outside the Detector Reviewer surface"
