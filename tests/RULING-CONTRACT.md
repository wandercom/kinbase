# Astra: rewrite the acceptance suite around rulings, not approvals

Branch `rescue/ruling-loop`, worktree `~/WanderRepos/kinbase-work`. Build is green at
`7d558c0`. Opus is working `model.rs`, `reducer.rs`, `lifecycle.rs`, `projector.rs`
and `codebase.rs` in parallel — **do not touch those five.** Everything under
`tests/` is yours.

## Why

We deleted the per-byte approval gate (`proposals.rs`) and the outcome-study harness
(`experiment.rs`). 15 suite files still assert the deleted behaviour: that a fact
waits for a human, that a prompt budget caps admissions, that a candidate expires.
Those assertions now encode a design we deliberately removed, so they fail for the
right reason and must be rewritten rather than patched.

The product's claim has changed. It used to be "no byte reaches a shared store
without a human approving it." It is now:

  - facts are admitted directly, with a signed, content-addressed, revocable record;
  - a human is interrupted only to **rule** on something genuinely contested;
  - what a human rules carries **standing** that outranks volume;
  - **provenance caps standing**, so agent-written code cannot become "the pattern".

## What to write

Delete or rewrite every node that asserts approval-gating, prompt budgets, candidate
expiry, or the eleven-arm experiment. In their place assert the new invariants:

1. **Direct admission.** An ingested fact reaches the store without a human, keeps a
   signed content-addressed event, and remains revocable.
2. **Ruling loop is the only interrupt.** Conflicting evidence with no authority in
   scope opens an Unknown and an `awaiting_authority` question. Assert it is durable
   and visible — the bug Astra already fixed was that it silently returned.
3. **Standing outranks volume.** Given N `present` facts saying X and one `ratified`
   fact saying Y, the reduced view must say Y. N must be large in the fixture — the
   whole point is that counting loses.
4. **Provenance ceiling.** A fact whose provenance is `ai_generated` may never reach
   `prevalent`, however often the pattern recurs. Assert the clamp directly against
   `model::effective_standing`, and end-to-end through a git fixture whose commits
   carry `Co-authored-by:` agent trailers.
5. **`shrug` is terminal.** Once something is ruled `shrug`, the system never opens
   another question about it. Distinct from `unruled`, which must keep asking.
6. **Unlabelled history stays unlabelled.** A commit with no authorship marker is
   `unknown`, never `human`. Assert we do not credit unmarked history as deliberate.

Keep everything still true: the three-store separation, private-to-shared leak
refusal, temporal reduction and supersession, signature and content-address
integrity, revocation, crash recovery, host hooks.

## Rules

- The suite is the oracle. Do not weaken an assertion to make the product pass; if
  the product is wrong, say so and leave it red with a one-line finding.
- `cd tests && ./.venv/bin/python -m pytest -c pytest.ini -q acceptance/` is how you
  run it. `KINBASE_BIN` points at the release binary you build from this worktree.
- Small commits. Report node counts before and after, and anything you left red.

## Retained acceptance assertions

Signed events, content-addressed writes, independent destination receipts and
recovery after a crash remain required. Private data must not leak to shared
stores. Raw private-session retention remains bounded. Repeating admission must
reuse durable receipts rather than duplicate events. An explicit ruling is not
an approval of each byte. Retired commands must be absent from CLI help.

Independent destination receipts survive partial fan-out; the admitting principal
is responsible and a named destination authority closes an orphan. Receipt replay
returns the original receipt in a fresh process without duplicating events.
Diagnostics remain useful after restart: fsck, doctor, corpus status and question
status. No cross-store transaction or shared private lineage token exists.

The close-five brief requires a canary-bearing message with a durable architectural
fact to yield Codebase and Personal admissions, with the canary in neither, while
the private record retains its taint. All five existing closure tests remain;
no candidate queue or candidate-count precondition is required.
