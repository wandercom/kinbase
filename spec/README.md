# Guildhall specification map

Guildhall is the Company-memory service in a three-product Kindex system. In plain
terms: `personal` is your private conversational memory, `company` is organization-
wide direction owned by named authorities, and `codebase` is repository-specific
knowledge shared in Git under `.kin/`. A coding session may compose authorized
Company and current Codebase facts, but it never reads Personal history.

The proof is not these documents. The proof is a running system that passes every
behavior/security gate and raises blindly scored brownfield work into the frozen
oracle-spec equivalence band.

Read in this order:

1. [`source-request.md`](source-request.md) — founder statements that no derived
   artifact may weaken.
2. [`product.md`](product.md) — observable behaviors P-1 through P-10 and the exact
   outcome claim.
3. [`architecture.md`](architecture.md) — store ownership, immutable protocol,
   reduction, projection, host, and experiment mechanisms.
4. [`cli.md`](cli.md) — concrete setup, operation, approval, and failure contracts.
5. [`threat-model.md`](threat-model.md) — the finite adversary and qualified privacy
   claim used by V-3.
6. [`verification.md`](verification.md) — independent instruments V-1 through V-10,
   role isolation, power, blinding, and verdict composition.
7. [`behavior-ledger.md`](behavior-ledger.md) — source-to-behavior-to-oracle map.
8. [`glossary.md`](glossary.md) — project terms and external tool/role names.
9. [`reviews/pre-ratification-disposition.md`](reviews/pre-ratification-disposition.md)
   — Constrain, Simulacrum, and Advocate findings and their explicit dispositions.
10. [`ratification-manifest.json`](ratification-manifest.json) — exact authority-file
   digests whose approval opens the isolated author lanes.
11. [`review-rubric.md`](review-rubric.md) — what every reviewer is optimizing for.
12. [`leak-runbook.md`](leak-runbook.md) — required containment and apology process.
13. `amendment-*.md` — candidate amendments in the append-only overlay format;
    each is `candidate` until the founder and a distinct Validator ratify its exact
    digest, and no Coder lane may read candidate bytes.

Status vocabulary:

- `candidate`: bytes are still under review and cannot be dispatched to author lanes;
- `ratified`: the founder and a distinct Validator approved the exact artifact
  digests for one immutable Factory run;
- `proven`: only a behavior-ledger status earned from its independent oracle plus the
  terminal P-10 experiment—never a synonym for implemented or locally green;
- run verdicts (`PROVEN`, `NOT_PROVEN`, `INCONCLUSIVE_*`, `INVALID_RUN`) describe one
  digest-identified execution and are separate from document status.

Factory, Agy, Constrain, Simulacrum, and Advocate are review/execution machinery, not
product authorities. Their definitions and sibling-checkout assumptions are in the
glossary. When any generated artifact conflicts with the chain
`source request > Product > Architecture > Threat Model > Verification`, the higher
authority wins and dispatch blocks.
