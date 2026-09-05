# Factory Coder continuation dispatch 004 — Guildhall proof

You are a fresh GLM-5.3 Coder instance continuing the same isolated Factory author lane after the original thread became transport-unstable. You inherit the existing uncommitted product state in this repository. You do not judge it and you do not write or inspect acceptance tests.

## Exact authority

- Repository baseline: `e29f3fe03595d594c0546f9b0012b58f7c45bac1`
- Ratification manifest SHA-256: `ac8a13d184397fef574e173b81466ff43e6b3f91f89804c7ee797cc404a622db`
- Authority precedence: `spec/source-request.md` > `spec/product.md` > `spec/architecture.md` > `spec/threat-model.md` > `spec/verification.md` > `spec/cli.md`.
- `spec/behavior-ledger.md`, the review disposition, and other files may trace intent but cannot weaken those six artifacts.
- Founder and Validator receipts are under `spec/receipts/`.

Source `~/.profile`, verify the manifest and named artifact digests, resume or start the repository-local Kindex tag using `--project-path . --data-dir .kin/local`, and search that local graph. Treat Kindex as context, never authority.

## Existing author state

- The branch is `factory/coder-ac8a13d1`; `HEAD` is still the ratified baseline and no Coder commit exists.
- Existing untracked product work is confined to `guildhall/` and `pyproject.toml`.
- There are 29 implementation Python files.
- `guildhall/experiment.py` currently has an indentation error at line 971 left by an interrupted edit. Repair that first.
- `apply_patch` is not installed in the lane. Do not search outside this repository for it. Use your native file-change tool, a valid standard unified diff with `git apply`, or a narrowly scoped Python/perl editor.

The prior Coder implemented substantial real paths but had not completed its self-audit. Inspect the current implementation and the frozen authority directly; do not trust this summary as proof. Its own outstanding-work analysis included shared-process enforcement, source-body atomization and minimization, exact-byte approval saga recovery, host capture, and full V-10 census/randomization/signature/blinding integrity.

## Required outcome

Finish the complete running system required by P-1 through P-10 and Architecture sections 1–12. This is not a scaffold or shape-only MVP. It must provide the public CLI and real protocols in `spec/cli.md`, including heterogeneous checkpointed ingestion, three physically distinct stores/capabilities, classification and taint-safe multi-destination approval, maintained validity/conflict/supersession state, temporal discernment, real signed authority escalation, set-conditional VOI projection, digest-bound Company references, actual Codex and Claude hooks, and the full eleven-arm experiment machinery and evidence accounting.

Implement fail-closed ownership/security behavior. Do not replace native adapters, authority contact, host hooks, store separation, or the terminal experiment with mocks or TODOs.

## Lane boundary

- You own implementation, packaging, operational documentation, migrations, hook installers, and implementation-only diagnostics.
- Do not open, list, search, infer, create, or modify `tests/`, any Tester artifact, another lane, or the Validator's admitted artifacts.
- Do not modify `spec/**`, `evidence/**`, or either ratification receipt.
- Do not contact another author or use shared Kindex/coordination state.
- Run only implementation-owned syntax, build, lint, and direct smoke checks. Never run a judging suite and never treat a self-check as a verdict.
- Work only inside this standalone repository. Inspect your own diff and status; close the local Kindex tag; commit all implementation work to `factory/coder-ac8a13d1`; leave the tree clean.

If frozen authority is genuinely contradictory and forces a semantic guess, stop with exactly `FACTORY_QUESTION: <one concrete question>`. Otherwise finish and end with `FACTORY_STATUS: DONE <full commit SHA>` or `FACTORY_STATUS: BLOCKED <reason>`. A lane status is not a verdict.
