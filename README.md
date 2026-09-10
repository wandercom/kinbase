# Kinbase

Kinbase is the company-memory member of a three-product Kindex system. Its site is
[kinbase.tools](https://kinbase.tools) and it is a Wander project.

The command is `kinbase`, and so is the protocol: every schema string, domain
separator, request header, environment variable and on-disk path. The project was
developed under the name Guildhall and renamed wholesale on 2026-09-09, which moved
the specification manifest digest and both ratification receipts. Two references to
the former name survive, in notes on the superseded receipts recording that the words
spoken at the original ratification said "Guildhall".

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
dispatch in progress; the concept remains unproven**. Two candidate amendments are
in review and are not authority until ratified:

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

A green unit suite is necessary and insufficient. If the blinded brownfield
experiment does not meet its outcome threshold, the concept is not proven.
