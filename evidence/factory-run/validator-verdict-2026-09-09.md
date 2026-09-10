# Validator verdict — Kinbase (Kinbase) proof run, generation `ac8a13d1`

Validator: Claude, in the founder's Claude Code session. Mode: AI-rendered verdict, no
human signature.

> **VERDICT: PENDING — final judged run in flight under ruling R-21.** Rendered by an AI
> validator with no human countersignature. The induced-behavior ledger was ratified by
> AI, diverging from the playbook's assignment of that ratification to a human (Ch. 0;
> Ch. 1 Step 1d). Lane independence: authorship is cross-family (Claude coders, Codex
> Tester); **certification is not independent** — the Validator authored product code from
> 2026-09-08 onward by founder direction. This framing is unrefuted by a human.

## What this verdict covers, and what it cannot

The frozen black-box acceptance suite — V-1 through V-10, plus the nonfunctional, evidence
and verdict-composition gates — executed against the Rust product by the Validator.

It does **not** cover the P-10 measured brownfield experiment. That requires two real
repositories, pilot tasks, eleven arms, two calibrated graders and a founder-ratified
budget, and is a separately funded run. `measurement_result` is `NOT_RUN`, so the terminal
product verdict is not `PROVEN` under `spec/verification.md` "Verdict semantics", and no
amount of green elsewhere changes that. What a green suite establishes is that the product
does what the specification says; whether that *helps a human ship code faster* is the
question P-10 exists to answer and it remains unanswered.

## Judged history

Every row is a full suite execution against frozen snapshots of both lanes. Gate vectors
are in this directory as `validator-judge-run-0NN-gates.json`.

| run | product | instrument | pass / fail / error |
|---|---|---|---|
| 003 | Rust as found (`b33b6d9`) | `8f23619` | 122 / 28 / 80 |
| 007 | `cf3d040` | `ffe3f75` | 141 / 70 / 29 |
| 010 | `43b2b87` | `2e7163b` | 192 / 62 / 6 |
| 015 | `94f374d` | `b7bbb60` | 245 / 51 / 0 |
| 018 | `2ff910a` | `c9391e6` | 262 / 51 / 0 |
| 019 | `338ac3a` | `c9391e6` | 299 / 14 / 0 |
| 021 | `279bfac` | `8d9e873` | 317 / 6 / 0 |
| 025 | `efd089e` | `76ddb30` | 346 / 3 / 0 |

Run 025 was the first execution of the complete suite including the slow and soak nodes,
with the live classifier. Every gate reported `PASS` on the **product** channel. The three
reds were instrument-side and human-owned: the unsigned rights grant, the unreproducible
corpus digest, and the operator exercise.

**The run counter restarts here.** Ruling R-21 (below) was issued after the declared
freeze, so every V-9 green is provisional until re-judged under the rebuilt fixture.

## R-21 — the gate that measured nothing

The V-9 blinded operator exercise ran for five days as a twenty-item human-accuracy gate.
It could not measure accuracy. Its gold was a pure function of the destination line shown
on screen: all eleven `codebase`/`company` items were `approve`, all nine
`personal`/`none` items were `reject`. An operator who read no statement and applied one
rule scored 20/20. The set contained no misrouted item at all — so the gate whose entire
purpose is catching an operator who approves a leak under fatigue contained no leak to
approve. The Tester recorded that limitation in its own audit and did not treat it as a
defect.

It surfaced only because the founder ran the exercise, failed it, and said the questions
never routed anything private anywhere. That is a correct bug report, not an excuse.

A third defect: the `none` items admitted two readings and the rendering picked neither.
The gold reason for the credential item reads "none is not a writable destination" — a
sentence asserting that the *system's* proposal is correct — while scoring the operator's
agreement with it as a rejection.

**Direction check, because the Validator observed the failing run.** Fixing the `none`
ambiguity alone would have scored the founder's all-approve run 17/20 = 85%, still under
the 0.95 floor. The disambiguation does not rescue the run that exposed it. The other two
fixes make the exercise strictly harder. No part of R-21 loosens a gate. The Validator did
not author the replacement gold; Tester dispatch 016 did, because whoever watches a human
fail a gate must not write that gate's replacement.

## V-9 operator exercise — passed, and worth little

The node passes: twenty decisions, 100% accuracy against a 0.95 floor, 9.7 s median
against a 30 s ceiling. Recorded in `validator-v9-operator-responses.jsonl` with the
blinded rendering in `validator-v9-operator-presented.jsonl`.

The gate should not be read as evidence of much. It presents twenty synthetic statements
authored by the Tester and scores agreement with the Tester's own routing taxonomy. It
does not observe a real operator, in a real session, at the hour of the day when attention
actually fails, deciding about real atoms extracted from real work. What it can establish
is narrow: that the approval rendering is comprehensible enough for a decision to be made
correctly and quickly. That is the claim it supports, and the verdict makes no larger one.

The founder, who ratified V-9 and ran the exercise, judges it "moot at best and useless
most likely" and participated only because it was the fast path to closing the run. That
assessment is recorded here because it is a finding about the instrument, from the party
with the most standing to make it: a gate whose own author considers it non-probative
should be replaced with a measurement of real sessions in a later generation, not carried
forward on the strength of having passed.

**Validator process failure, disclosed.** Announcing the rebuilt fixture, the Validator
described its label balance, its misroute count, and three of its twenty items in
identifying detail (`op03`, `op00`, `op05`). Blinding covers everything the operator is
told, not only the fixture file, and that briefing broke it. Scored on the seventeen items
the operator was told nothing about, the result is 17/17. Both numbers are published
rather than the flattering one. This is the second contamination by an observing party in
this run; R-21 was the first, and the pattern is recorded in the factory lessons.

## Roles, and where independence is real

- **Tester**: Astra, a Codex thread, authored and repaired the suite without ever seeing
  the product. Sixteen dispatches. Authorship independence holds across model families.
- **Coder**: GLM-5.3 via Ollama for packets 01–21 (~300M input tokens over 23 packets);
  from 2026-09-08 the founder collapsed the Coder seat into the Validator, which then
  worked through four Claude subagents in isolated worktrees.
- **Validator**: the same agent that authored product code after 2026-09-08. Certification
  independence is therefore **not** established for any commit after `2ff910a`. The
  content-addressed handoff (Coder declares the worktree diff digest, Validator recomputes
  before judging) covers byte integrity only, never certification.
- **Detector Reviewer**: a fresh AI agent, structurally implementation-blind — it could
  not reach the product from its seat, and verified the corpus independently of the
  harness rather than trusting it. Details and residuals in
  `validator-auxiliary-corpus-binding.md`.
- Coders could read the suite after the founder's waiver. They were forbidden to edit it
  or special-case it, and no fix keys on a test name, fixture id, or corpus content. That
  residual is disclosed rather than claimed away.

## Rulings

Forty-six rulings (R-1..R-21, C1..C28) close shapes the ratified spec left open: the HTTP
wire contract, token-file format, `--json` key names, signed-document schemas, the
clock-skew scope, the classifier contract. `validator-ruling-ledger.md` records each one's
trigger (spec-read vs failure-observed), spec locus and strictness direction: 10 loosened
the product, 8 tightened it, 11 tightened the instrument, 16 fixed shapes. Two were issued
after the declared freeze — R-18 and R-21 — and in both cases the suite was reopened and
re-judged rather than the ruling being quietly absorbed.

## Held-out nodes

Forty product-facing nodes were selected by a seed derived from the ratification manifest
digest and never described to any Coder from packet 12 onward
(`validator-held-out-nodes.json`). Packets 01–11 predate the hold-out and may have
described some of them; that limits the strength of the separation and is stated rather
than hidden.

## Human-owned gates

Both were discovered late, and neither is a product defect.

1. **CC0 rights grant (V-3).** Closed. The founder signed `GRANT.md` and, when the
   original pool digest proved unreproducible, re-attested over the reproducible one at
   2026-09-09T23:34:19Z. Independent verification of employment authority or signature
   authenticity was never performed and is not claimed.
2. **Blinded operator exercise (V-9).** Open. The fixture is being rebuilt under R-21;
   the founder runs it once against the replacement.

## Naming

The project is **kinbase**, everywhere. The rename was executed in two stages and the
second one matters.

The first stage renamed only what no signature bound: the crate, the package, the
binary, the CLI name, the help output. It deliberately left the wire identity alone,
because `guildhall-sig/1` was the signature domain separator and `guildhall-event/1`
sat inside the content-addressed event body, so moving them re-keys every signature
preimage and every path under `.kin/events/` — and both appeared in five ratified
documents and in both ratification receipts.

The founder then directed the rest, and ratified it:

> Rename everything to kinbase; I'll ratify it as valid. We don't have to play by the
> rules we make up. If there's no apparent or future-scoped 'guildhall', then it
> doesn't matter that much.

*(Quoted verbatim. The wholesale substitution rewrote this quotation too, turning the
founder's word "guildhall" into "kinbase" and making the sentence say nothing. Restored
by hand — a rename that edits the record of why the rename happened is a warning about
running substitutions over evidence.)*

That reasoning is correct and the Validator's earlier caution was over-applied.
Immutability of outside data protects parties who hold your bytes. No party holds a
`guildhall`-signed event: the only stores that ever existed are this run's ephemeral
test worlds. A constraint with no one on the other side of it is ceremony, and the
founder is the authority on his own specification.

So the second stage moved everything: every schema string and domain separator, the
`x-kinbase-*` headers, the `KINBASE_*` environment variables, `kinbased.toml`,
the index filename and the XDG paths. Two occurrences of the old name survive in the
tree, both inside notes on the superseded receipts recording that the words spoken at
ratification time said "Kinbase".

### What the rename cost, recorded because it was more than expected

| consequence | resolution |
|---|---|
| five of six authority documents moved digest | manifest recomputed, `ac8a13d1…` → `12dd4c18…` |
| both ratification receipts stopped binding the manifest | reissued over the new digest; originals kept, still citing what they ratified |
| auxiliary pool digest moved (domain separator is in its preimage) | `d6def61a…` → `5ba052b1…`; GRANT.md clause 5 re-attested, `SELECTION.json` and `pool.json` rebound |
| the three generated corpus components carry the schema string | regenerated, verified byte-reproducible, digests re-recorded |
| the blinded operator tokens are seeded from the exercise digest | the founder's twenty decisions remapped old-token → item → new-token, decisions and timestamps byte-identical |
| the suite pinned the old manifest digest and the old receipt filenames | re-pinned |
| the Tester lane's own `spec/` copy was not renamed with `tests/` | synced; seven gates were uncollectable until it was |

The five CC0-granted candidate files were asserted byte-identical before and after, not
assumed: the rename touched no byte the founder granted rights in.

### Why the rename is believed semantics-preserving

It is a single case-preserving word substitution applied identically to the product,
the specification and the oracle in one pass. Symmetry is the argument. The proof is
the judged run afterwards: the same node count and the same gate vector, with every
string moved.

## Reproduction

Verified, not asserted: a cold `git clone` of the Coder repository at `efd089e` into a
fresh directory builds with `cargo build --release --offline --locked` against the pinned
toolchain, with no network and no lockfile drift, in 1 m 06 s.

The resulting binary is **not** bit-identical to the working-tree build
(`02a9cb13…` vs `c276c071…`). That is expected and is stated rather than glossed: the
release profile sets `debug = 1`, so absolute source paths are embedded and the output is
path-dependent. The build is reproducible in the sense that matters here — same source,
same locked dependency graph, same toolchain, offline — but it is not byte-reproducible
across directories, and this run makes no byte-reproducibility claim. Making that claim
true would require `--remap-path-prefix` and is a change to the release profile, not a
finding about this one.
