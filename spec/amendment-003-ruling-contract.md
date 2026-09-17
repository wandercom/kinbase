# Amendment 003 — Rulings, not approvals

Status: **ratified**. The founder ratified this amendment on 2026-09-17 together with
the manifest that binds its bytes; the receipts in `spec/receipts/` name that
manifest's digest. It is the seventh authority artifact and ranks after `cli.md`.

## Why

The per-byte approval gate and the outcome-study harness were removed from the
product. The claim the proof run tests changed with them. It used to be "no byte
reaches a shared store without a human approving it." It is now:

- facts are admitted directly, with a signed, content-addressed, revocable record;
- a human is interrupted only to **rule** on something genuinely contested;
- what a human rules carries **standing** that outranks volume;
- **provenance caps standing**, so agent-written code cannot become "the pattern".

## What this amendment supersedes

In every earlier artifact, this amendment supersedes the clauses that make a shared
write wait for a human: exact-byte human approval as the condition for a shared
admission (`product.md`, "exact-byte human approval" and "require separate
exact-byte approval"), the per-run cap on shared-destination approval opportunities
(`product.md`, "Approval fatigue is product-critical"), and candidate expiry as a
precondition for admission. On those points this amendment governs despite its
position in the precedence chain. On every other point the earlier artifacts
govern. It does not amend the manifest's proof rule.

## Requirements

1. **Direct admission** (`direct-admission`). An ingested fact reaches its store
   without a human, keeps a signed, content-addressed event, and remains revocable.
2. **The ruling loop is the only interrupt** (`unknown`). Conflicting evidence with
   no authority in scope opens an Unknown and an `awaiting_authority` question. The
   question is durable and visible; it never resolves silently.
3. **Standing outranks volume** (`standing`). Given N `present` facts saying X and
   one `ratified` fact saying Y, the reduced view must say Y. A fixture that tests
   this makes N large, because counting is exactly what must lose.
4. **Provenance ceiling** (`provenance`). A fact whose provenance is `ai_generated`
   may never reach `prevalent`, however often the pattern recurs. The ceiling holds
   for the standing computation itself and end to end for commits that carry agent
   `Co-authored-by:` trailers.
5. **`shrug` is terminal** (`shrug`). Once something is ruled `shrug`, the system
   never opens another question about it. `unruled` is different: it keeps asking.
6. **Unlabelled history stays unlabelled** (`unlabelled`). A commit with no
   authorship marker is `unknown`, never `human`. Unmarked history is never credited
   as deliberate.

## Retained requirements

Everything the removal did not touch stays binding: the three-store separation,
private-to-shared leak refusal, temporal reduction and supersession, signature and
content-address integrity, revocation, crash recovery, and host hooks. In
particular:

- (`commands`) Signed events, content-addressed writes, independent destination
  receipts and recovery after a crash remain required. Private data must not leak
  to shared stores. Raw private-session retention remains bounded. Repeating
  admission must reuse durable receipts rather than duplicate events. An explicit
  ruling is not an approval of each byte. Retired commands must be absent from CLI
  help.
- (`apology`) Independent destination receipts survive partial fan-out; the
  admitting principal is responsible and a named destination authority closes an
  orphan.
- (`retry`) Receipt replay returns the original receipt in a fresh process without
  duplicating events.
- (`diagnostics`) Diagnostics remain useful after restart: fsck, doctor, corpus
  status and question status.
- (`independence`) No cross-store transaction or shared private lineage token
  exists.
- (`close-five-taint`) A canary-bearing message with a durable architectural fact
  yields Codebase and Personal admissions, with the canary in neither, while the
  private record retains its taint. No candidate queue or candidate-count
  precondition is required.

## Provenance

These requirements were first written as the acceptance-suite brief
`tests/RULING-CONTRACT.md`, which stays in the tree as a trace. Until this
amendment, that brief was not an authority: a test that cited only it failed the
suite's backreference check. The acceptance suite now cites this amendment.
