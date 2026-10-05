# Kinbase

Kinbase is the company-memory member of a three-product Kindex system. Its site is
[kinbase.tools](https://kinbase.tools) and it is a Wander project.

- **Kindex Personal** remembers private conversations and personal context.
- **Kinbase / Kindex Company** carries organization-wide architectural
  and operational knowledge into every authorized coding task.
- **Kindex Codebase** carries repository-specific knowledge in Git under `.kin/`.

[Kindex](https://kindex.tools) is the individual and codebase index and ships today.
Kinbase is the corpus above it: a company's engineering direction, architecture,
standards, ownership, and history, held by named authorities and composed into every
coding session. Same engine, same protocol, physically separate stores.

A coding agent dropped into an unfamiliar repository lacks the constraints and
rationale a long-tenured engineer carries. Kinbase captures that context from
conversations, code, Git, tests, operations, and named authorities; keeps it current;
and supplies the smallest decision-relevant set without copying private notes into
Company or repository state.

This repository is a proof of the concept, not a boundary-shaped prototype. It
passes only if the running system ingests heterogeneous evidence, maintains the
three corpora, discriminates durable direction from recent noise, asks the proper
human authority when evidence is insufficient, routes atoms without private-data
leakage, and materially improves independently judged brownfield implementation
quality to within the preregistered fully-informed `oracle-spec` margin—the valid
operational test of the founder's greenfield-quality goal.

Current status: **exact-byte specification ratified; isolated Coder and Tester
dispatch in progress; the concept remains unproven**. Amendment 003
([`spec/amendment-003-ruling-contract.md`](spec/amendment-003-ruling-contract.md),
rulings rather than per-byte approvals) is ratified and bound in the manifest. Two
candidate amendments are in review and are not authority until ratified:

- [`spec/amendment-001-rust-vast.md`](spec/amendment-001-rust-vast.md) — Rust
  implementation and the self-hosted GLM-5.3 Coder;
- [`spec/amendment-002-emission-ledger.md`](spec/amendment-002-emission-ledger.md)
  — emission ledger, leak stories, withhold, and redaction by reference, so that a
  shared-data leak is answered by a query rather than an investigation.

Reading order:

1. [`spec/README.md`](spec/README.md) — map, vocabulary, and authority order;
2. [`source-request.md`](spec/source-request.md) — what the founder actually asked;
3. [`product.md`](spec/product.md) — observable behavior and proof thresholds;
4. [`architecture.md`](spec/architecture.md) — ownership, boundaries, and mechanisms;
5. [`threat-model.md`](spec/threat-model.md) — the finite, qualified disclosure claim;
6. [`verification.md`](spec/verification.md) — independent tests and experiment;
7. [`behavior-ledger.md`](spec/behavior-ledger.md) — source-to-oracle traceability;
8. [`cli.md`](spec/cli.md) — concrete user/configuration contract;
9. [`glossary.md`](spec/glossary.md) — terms;
10. [`review-rubric.md`](spec/review-rubric.md) — what reviewers optimize for;
11. [`leak-runbook.md`](spec/leak-runbook.md) — containment and apology process;
12. the candidate amendments above.

Public documentation lives in [`docs/`](docs/), published by GitHub Pages: an
overview, the proof conditions in plain words, the amendment register, and
`llms.txt` for agents. The canonical marketing site and its privacy notice live in
the separate Kinbase-Tools repository and are served at kinbase.tools; `docs/` links
to them and never duplicates them.

## Status

The frozen black-box acceptance suite passes in full: **371 nodes, 0 failures**, run
2026-09-09 against product `f7696c5` and instrument `f571517`. Every product gate is
green — V-1 through V-10, nonfunctional, and evidence.

The brownfield outcome experiment has **not** run. The terminal verdict is therefore not
`PROVEN`. A green suite is necessary and insufficient: it shows the system does what the
specification says, not that it helps anyone ship code. If the blinded brownfield
experiment does not meet its outcome threshold, the concept is not proven.

Start with
[`evidence/factory-run/validator-verdict-2026-09-09.md`](evidence/factory-run/validator-verdict-2026-09-09.md).
It states what this run proves, what it does not, which gates the instrument itself
fails, and where the independence between the building and certifying seats is real and
where it is not.

## Personal recall through Kindex (branch addition, not ratified)

The specification makes the Personal store Kindex but the proof of concept never
wired it. On this branch, with `[personal] kindex_executable` configured, what
`kinbase ingest codex_jsonl|claude_jsonl` reads of each host transcript is also
handed to the Kindex graph at the Personal root, and `kinbase recall --question
TEXT [--as-of DATE]` answers the principal's own question from it through
`kin ask`. Both run where the Personal root is held; nothing either reads or
returns enters a shared store, a projection or a hook.

**Kindex version.** This needs a Kindex with `kin ingest conversations` (with
`expires`, `retracted` and `--limit 0`), `kin digest` and `kin ask --as-of` /
`--context-file`. No Kindex release has them yet: they are in
[wandercom/kindex#73](https://github.com/wandercom/kindex/pull/73), which must
merge first. Until a release ships them, install Kindex from that branch, point
`kindex_executable` at its `kin`, and pin it with `shasum -a 256 "$(command -v kin)"`;
a Kindex upgrade changes the digest, and Kinbase refuses a `kin` that no longer
matches its pin.

- The hand-off exports the ingest scan's records, so the scan's bounds apply
  (an oversized transcript is skipped, an oversized directory refused).
- A transcript is one conversation per calendar day its messages carry, with an
  id made of the host's session id and a digest of the transcript's path.
- Each transcript is kept for its retention: a `.retention` sidecar's
  `private_retention_seconds`, else `kindex_retention_seconds`, else the
  24-hour private raw-session default, counted from its last change. Kindex is
  told the day the retention ends (it expires by calendar day); a ledger under
  the Personal root keeps the exact deadline and retracts a conversation (and
  everything Kindex derived from it) once it passes, at the next hand-off or
  `recall`, or when its transcript is emptied or gone from a source that is
  ingested again. The ledger is locked while a hand-off or purge runs.
- A hand-off reconciles only against what its own scan listed and read (a
  source that is gone lists nothing). The ledger records, for each transcript,
  when the newest scan that settled it began, and keeps that after retracting
  it: a scan that began earlier neither restores, re-sends nor retracts it. A
  day after a transcript last held a conversation its record is dropped, and
  any scan begun before that record changes nothing.
- Historical Personal text reaches a model only through a processor the
  principal has authorized, as `spec/threat-model.md` requires:
  - Kinbase resolves the Kindex config itself and passes it to every Kindex
    run with `--config`, so Kindex loads no global, project or profile config.
    The config comes from `kindex_config`, which must be JSON (Kindex reads JSON
    as YAML), or is empty. It may set only `llm`, `embedding`, `ask`,
    `conversations` and `budget`; any other section or key, or a value Kindex
    could read differently (`"enabled": "true"`), is refused.
  - Its processors are the LLM when `llm.enabled` and the embedding provider
    unless it is `local`. Each names its `provider` and `model`: `anthropic` or
    `openai` for the LLM, and `voyage`, `openai` or `gemini` for embeddings.
    Embeddings are local unless a provider is named.
  - Every processor must be listed in `kindex_processors`, whatever credentials
    are passed. Otherwise `recall` refuses with `PROCESSOR_UNAUTHORIZED`, and
    the hand-off stores the conversations but skips `kin digest`
    (`personal_kindex.digest_refused`). Storing a conversation makes no model
    call.
  - `kindex_env` passes only credentials (names ending in `_API_KEY`).
  - The recall receipt lists the processors and the SHA-256 of the question and
    team statements Kinbase handed Kindex.
- A hand-off that fails keeps the journal record and is reported (a warning on
  stderr in text mode, `personal_kindex.error` in JSON).
- The Personal root is checked before every Kindex run: not a symlink, owned by
  the effective user, mode 0700. Staging files are written under it, mode 0600.
- With `kindex_team_knowledge = true`, in a certified repository, recall also
  makes a read-only projection for the question and passes its released
  statements to the same processors (it is off by default). The projection
  raises no question to an owner and logs nothing. A withheld projection passes
  no shared statement, only a note that team guidance is pending; a released
  statement keeps its role, kind, store, standing, provenance and governed
  paths, and a stale authority snapshot is stated.
- Kindex runs under the classifier's executable rules (absolute path, owner,
  mode, directory chain, pinned SHA-256) with a scrubbed environment.

```toml
[personal]
data_root = "/private/example/kindex"
kindex_executable = "/opt/example/bin/kin"
kindex_executable_sha256 = "<sha256 of that file>"
kindex_env = ["OPENAI_API_KEY"]          # passed through; everything else is scrubbed
kindex_config = "/private/example/kin.json" # {"llm": {"enabled": true, "provider": "openai", "model": "gpt-6-luna"}}
kindex_processors = ["openai:gpt-6-luna"] # each authorized for historical Personal data
kindex_team_knowledge = false             # pass projected team statements to recall
kindex_digest = true                      # run `kin digest` after each hand-off
kindex_retention_seconds = 7776000        # keep handed-off transcripts 90 days
```

These keys and the `recall` command are additions to `spec/cli.md`, which this
branch does not change; they need an amendment before they are authority.

## Building and running

```
cargo build --release --offline --locked
./target/release/kinbase --help
```

Dependencies are exact-pinned; `rust-version` is set in the workspace manifest. The
build is offline and lockfile-exact. It is not byte-reproducible across directories,
because the release profile keeps debug info and so embeds absolute source paths.

[`tests/`](tests/) is the acceptance suite — the oracle. It was authored by a separate
lane that never saw the implementation, and it is published so the claim above is
checkable rather than asserted. It carries its own answer key, which is the cost of
making it checkable.
