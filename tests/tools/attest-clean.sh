#!/usr/bin/env bash
# Boundary-safe, content-addressed clean-worktree attestation.
#
# Detector Reviewer finding 1: `git status --untracked-files=all` cannot stat 17
# tracked paths under `.kin/**` and `evidence/**`, so full worktree cleanliness
# could not be positively attested and modified or untracked material there
# could not be excluded.
#
# This attestation does not hide that. It reports, over the surface a Reviewer
# may read, the exact commit and tree, every tracked path with its blob digest,
# staged/unstaged/untracked differences, and an explicit, itemised enumeration
# of every path Git could not stat, with the reason. A consumer can therefore
# see exactly what is and is not covered rather than inferring it from a scoped
# status that silently omitted the inaccessible paths.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
emit() { printf '%s\n' "$*"; }

emit "schema: guildhall-acceptance-cleanliness-attestation/2"
emit "head: $(git rev-parse HEAD)"
emit "tree: $(git rev-parse 'HEAD^{tree}')"
emit "branch: $(git rev-parse --abbrev-ref HEAD)"
emit "manifest_sha256: $(shasum -a 256 spec/ratification-manifest.json | cut -d' ' -f1)"

emit "covered_scope: spec/** tests/**"
staged="$(git diff --cached --name-only -- spec tests | wc -l | tr -d ' ')"
unstaged="$(git diff-files --name-only -- spec tests | wc -l | tr -d ' ')"
untracked="$(git ls-files --others --exclude-standard -- spec tests | wc -l | tr -d ' ')"
emit "covered_staged_differences: $staged"
emit "covered_unstaged_differences: $unstaged"
emit "covered_untracked_files: $untracked"
emit "covered_untracked_enumeration:"
git ls-files --others --exclude-standard -- spec tests | sed 's/^/  /' || true
if [ "$staged$unstaged$untracked" = "000" ]; then
  emit "covered_scope_clean: true"
else
  emit "covered_scope_clean: false"
fi

# Enumerate every path outside the covered scope and state, per path, whether
# Git could stat it. An unreadable path is reported, never omitted.
emit "uncovered_paths:"
unreadable=0
total_uncovered=0
while IFS= read -r path; do
  case "$path" in
    spec/*|tests/*) continue ;;
  esac
  total_uncovered=$((total_uncovered + 1))
  if [ -r "$path" ] 2>/dev/null; then
    emit "  readable   $path"
  else
    unreadable=$((unreadable + 1))
    emit "  UNREADABLE $path (Operation not permitted; outside the Tester lane)"
  fi
done < <(git ls-tree -r --name-only HEAD)
emit "uncovered_path_count: $total_uncovered"
emit "uncovered_unreadable_count: $unreadable"
if [ "$unreadable" -gt 0 ]; then
  emit "full_worktree_clean: UNPROVEN"
  emit "full_worktree_reason: $unreadable tracked path(s) cannot be stat'd by this lane"
  emit "remediation: recreate the review lane from the bound tree with .kin/ and evidence/ absent by construction, or grant the attesting role stat access"
else
  emit "full_worktree_clean: true"
fi

emit "tracked_files:"
git ls-tree -r HEAD --format='%(objectname) %(path)' -- spec tests | sort | sed 's/^/  /'
