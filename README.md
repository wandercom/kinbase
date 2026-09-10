# Kinbase proving ground

Kinbase is the company-memory member of a three-product Kindex system:

- **Kindex Personal** remembers private conversations and personal context.
- **Kinbase / Kindex Company** carries organization-wide architectural and
  operational knowledge into every authorized coding task.
- **Kindex Codebase** carries repository-specific knowledge in Git under `.kin/`.

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
dispatch in progress; the concept remains unproven**.

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
10. [`review-rubric.md`](spec/review-rubric.md) — what reviewers optimize for.

A green unit suite is necessary and insufficient. If the blinded brownfield
experiment does not meet its outcome threshold, the concept is not proven.
