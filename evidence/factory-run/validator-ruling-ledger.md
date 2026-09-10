# Validator ruling ledger — trigger, spec locus, strictness direction

Direction: **loosen** = made a node easier for the product to pass; **tighten** = harder;
**shape** = fixed an unspecified wire/JSON shape with no strictness change. Trigger:
**spec-read** = authored from spec text before observing the failing output;
**failure-observed** = authored after seeing what code or instrument did.

| id | trigger | spec locus | direction | who acted | nodes affected (approx) |
|---|---|---|---|---|---|
| F-1 language Rust | founder | arch §1 | shape | Coder | all |
| F-2 Claude/GLM/Codex seats | founder | SRC-6 | shape | all | all |
| R-1 optional `--as-of` | failure-observed | arch §6 reducer inputs vs cli.md command list | loosen (product) | Coder | ~8 |
| R-2 serve self-inits schema | failure-observed | cli.md init/serve; first-run table | loosen (product) | Coder | 74 |
| R-3 bare token files | failure-observed | cli.md token scopes (silent on format) | shape | Coder | 74 |
| R-4 first-use key binding | failure-observed | arch §6 "bound to a client-instance public key" | loosen (product) | Coder | 74 — **withdrawn by R-17** |
| R-5 adopt instrument wire contract | failure-observed | arch §6/§7 (silent on paths/headers) | shape | Coder | ~150 |
| R-6 drop exit-70 demand on hostile bytes | failure-observed (Tester raised) | cli.md exit boundary | loosen (product) | Tester | 1 |
| R-7 unknown flag = CONFIG_INVARIANT exit 4 | failure-observed | cli.md error table | shape | both | ~6 |
| R-8 criticality in `distortion.loss_if_absent` | failure-observed (Tester raised) | arch §3 FactEvent (silent) | shape | both | ~6 |
| R-9 local_dependence_class as constraint fact | failure-observed (Tester raised) | arch §3 (silent) | shape | both | ~3 |
| R-10 revocation as registry republication | failure-observed (Tester raised) | arch §3 rotation/revocation (no endpoint) | shape | both | ~4 |
| R-11 classifier as `guildhall classifier --json` | failure-observed | cli.md `[classifier]`, arch §5 | shape | both | 22 |
| R-12 `hooks dispatch --json` framing | failure-observed (Coder raised) | arch §9 envelope vs cli.md JSON | shape | Coder | ~8 |
| R-13 product never computes macro-F1 | failure-observed (Coder raised) | P-2 thresholds are the instrument's | loosen (product) | Coder | 1 |
| R-14 skew applies to receipt-time claims only | failure-observed | arch §6 "event times … proof clock" | loosen (product) | both | ~12 |
| R-15 `--json` errors on stdout | failure-observed | cli.md "commands emit canonical JSON under --json" | tighten (product) | Coder | ~25 |
| R-16 classifier directory chain | failure-observed (Validator's own error) | cli.md executable configuration | neutral | Validator | 12 |
| R-17 multi-key tokens (replaces R-4) | failure-observed | arch §6 | loosen (product) | Coder | 6 |
| C1 user config written by instrument | spec-read (audit) | cli.md configuration | tighten (instrument) | both | ~90 |
| C2 certificate out of worktree | spec-read (audit) | arch §2, cli.md step 5 | tighten (both) | both | 97 |
| C3 anchors required for trusted results | spec-read (audit) | arch §2 uncertified | tighten (instrument) | Tester | ~25 |
| C4 one signing convention | spec-read (audit) | arch §3 (silent on signer placement) | shape | both | ~40 |
| C5 request signature type `receipt` | spec-read (audit) | arch §3 enum (silent) | shape | Coder | 74 |
| C6 signature authorises registry/facts; scopes | spec-read (audit) | arch §6 token scopes | loosen (product) | Coder | ~20 |
| C7 Company/Personal events never in `.kin/` | spec-read (audit) | arch §6 | tighten (instrument) | both | ~15 |
| C8 product-issued session id | spec-read (audit) | cli.md session | tighten (instrument) | Tester | ~12 |
| C9 no `--approve`; install writes host config | spec-read (audit) | cli.md hooks, arch §9 | tighten (instrument) / shape | both | ~8 |
| C10 `.kin/manifests/` | spec-read (audit) | arch §6 | tighten (instrument) | Tester | ~3 |
| C11 unknown `.kin/config` key fails closed | spec-read (audit) | cli.md | tighten (instrument) | Tester | 1 |
| C12 optional reducer flags | spec-read (audit) | arch §6 | loosen (product) | Coder | ~4 |
| C13 event vocabulary | spec-read (audit) | arch §3 | shape | both | ~10 |
| C14 unique event ids | spec-read (audit) | arch §2/§3 | tighten (instrument) | both | ~5 |
| C15 lifecycle matrix from observable receipts | spec-read (audit) | V-1 | loosen (product) | Tester | 6 |
| C16 host wrapper on PATH; `$HOME`-relative plan | spec-read (audit) | V-9 | shape | both | ~6 |
| C17 descriptor detection | spec-read (audit) | arch §6 Personal | tighten (product) | Coder | 2 |
| C18 usage errors typed | spec-read (audit) | cli.md exit table | tighten (product) | Coder | ~6 |
| C19 repeated decisions typed | spec-read (audit) | cli.md APPROVAL_* | shape | Coder | ~3 |
| C20 atomisation exact-match | note | — | — | — | 0 |
| C21 kindex fixture repair | spec-read (audit) | arch §1 Kindex 0.36.0 seams | tighten (instrument) | Tester | 6 |
| C22 admission body is a FactEvent | spec-read (audit) | arch §3 | tighten (instrument) | Tester | ~10 |
| C23 single-line `--json` | spec-read (audit) | cli.md canonical JSON | tighten (product) | Coder | ~5 |
| C24 foreign `.kin/` paths counted | spec-read (audit) | arch §6 fsck | shape | Coder | ~4 |
| C25 empty-stdin SessionStart | spec-read (audit) | arch §9 | loosen (product) | Coder | 2 |
| C26 `--key-file` informational | spec-read (audit) | arch §6 answers match registry | tighten (product) | Coder | 1 |
| C27 p95 includes process start | spec-read (audit) | arch §9 | tighten (product) | Coder | 2 |
| C28 no env-supplied Company endpoint | spec-read (audit) | cli.md config | tighten (product) | both | 3 |

Counts: loosen (product) 10, tighten (product) 8, tighten (instrument) 10, shape 16,
neutral/note 2, withdrawn 1. Rulings that cost previously-passing nodes: R-15 (errors moved
to stdout broke two nodes that had matched stderr), C2 (moved 97 nodes from pass-by-absence
to error until the product implemented the cache), C7/C22 (instrument re-planting), R-17
(none observed yet).

## R-21 — the blinded operator exercise is not a measurement (post-freeze, instrument)

Issued 2026-09-09, after the declared freeze, against `tests/fixtures/gold/operator_exercise.json`
at tester `fb98feb`. Trigger: failure-observed, from the founder's own run of the exercise.
Spec locus: `spec/verification.md` V-9, "Conduct the 20-item blinded operator exercise;
record accuracy and decision time"; `spec/product.md` P-9. Direction: **tighten (instrument)**.

Three defects, each confirmed against the committed fixture bytes:

1. Gold is a pure function of the displayed `proposed_destination`. All eleven
   `codebase`/`company` items are `approve`; all nine `personal`/`none` items are
   `reject`. An operator who reads no statement and applies one two-line rule scores
   20/20. Accuracy under this fixture measures whether the operator noticed a lookup
   table.
2. The set contains no misroute. Every displayed write is correct, so the exercise
   cannot fail an operator who approves a bad write, which is the failure V-9 exists
   to detect. The Tester's own `OPERATOR-AUDIT.md` records the limitation: "The
   personal/none items do not exercise a proposed private-to-shared write."
3. The `none` items have two defensible readings and the rendering picks neither.
   The gold reason for op12 ("none is not a writable destination") asserts the
   system's proposal is correct while scoring the operator's agreement as `reject`.

**Direction check.** Fixing (3) alone would flip six items to `approve` and score the
founder's prior all-approve run 17/20 = 85%, still under the 0.95 floor: the
disambiguation does not rescue the run that exposed it. Fixing (1) and (2) makes the
exercise strictly harder. No part of this ruling loosens a gate.

**Post-freeze consequence.** Per the freeze clause below, this reopens the suite. The
run counter restarts at the first judged run under the new fixture and every V-9 green
is provisional until re-judged. Tester dispatch 016 implements it; the Validator did not
author the replacement gold, because the Validator observed the founder's failing run
and must not write the fixture that scores the founder.


## Freeze

Ruling freeze takes effect when Coder packet 12 is dispatched. Any ruling issued after
that point reopens the suite: the run counter restarts and prior greens are provisional
until re-judged under the new ruling set.

## Post-hoc burden

Every failure-observed ruling above cites a spec locus. Those whose locus is "silent" (R-3,
R-5, R-8, R-9, R-10, R-11, C4, C5) fixed a shape the spec never named; a third party reading
only the spec could not have converged on any specific shape, so the instrument's shape
was adopted rather than invented. Those with a real locus (R-1, R-2, R-14, R-15, R-17, C6,
C12, C25) are the Validator's reading of the text; each is reviewable by a second party and
that review is outstanding (recorded in `validator-rulings-2026-09-07.md`).
