# Advocate disposition — Kinbase acceptance no-vacuity

Review artifact:
`evidence/reviews/advocate-acceptance-no-vacuity-018.json`

- Reviewers: Helland, Adversarial, Red Team, SME, Good Friend
- Findings: 56
- Reported cost: USD 0.8222
- Tool-reported disagreements: none

All five summaries agree on the core disposition: the current suite remains
inadmissible even if its 12 runtime self-test failures are repaired. It can pass
when the product receives answer-bearing scenario labels or emits no evidence.
The review does not render a product verdict and does not authorize a change to
the ratified specification.

## Accepted findings

1. **Outcome ownership is inverted.** The harness owns raw stimulus and expected
   outcome; the product must uniquely own the derived actual outcome. A case ID
   that supplies the expected answer makes the product a courier, not the measured
   authority.
2. **Silence is Unknown, never PASS.** Missing, null, empty, unexercised, or
   unread load-bearing evidence cannot satisfy a proof obligation. Environmental
   inability remains distinguishable as `INVALID_HARNESS`; it is still non-green.
3. **The product cannot grade itself.** Product-reported `PROVEN`, success, or
   field presence cannot decide which Validator obligation runs. The Validator
   derives the expected disposition from independent evidence.
4. **Scale means real work.** Event-count and maintenance claims require the
   seeded population to traverse the shipping ingestion/reducer path. A scalar
   count cannot stand in for that population. The ratified 10x ceiling is hard:
   oversized intake must refuse new writes and show no admitted post-state.
5. **Positive mechanism is required.** The linked-worktree gate must observe one
   common-directory lock, real contention behavior, and one ordered manifest
   lineage; absence of a wrong lock is insufficient.
6. **Guess/correction paths require real apologies.** Classification, temporal,
   projection, supersession, and authority cases must construct an earlier
   plausible decision, evidence that falsifies it, and the exact compensating
   record/rebuild/Unknown required by the spec.
7. **Time and randomness have test ownership.** The frozen clock and seed are
   explicit, recorded inputs. Scenario names are not substitutes for timestamped
   events.
8. **Compressed fixtures are allowed only as data-on-the-outside.** They must be
   immutable/versioned and replayed through the same public ingestion/write path
   shipping callers use. Store-internal snapshots and case-label jump tables are
   not probative.
9. **Security-sensitive gates receive priority.** Private-data non-disclosure and
   authority over-granting require planted leaking/over-granting mutants that the
   suite demonstrably rejects before either claim is admissible.

## Corrections to the review packet

The packet's original non-oracularity wording used an existential condition and
was gameable. It is superseded by this operational test:

- For assertions about content, hold real product state fixed and vary the control.
  A correct implementation's asserted content must remain invariant; otherwise the
  control carries answer bits.
- A scheduling/fault control may change only timing, termination, ordering, or a
  real dependency failure. It may not fabricate asserted content.
- Independently of that differential, the expected result must be derivable from
  recorded raw state without consulting the control label.

The headline count of 40 acceptance variables is an inventory, not proof that all
40 are invalid. Before admission, the Detector Reviewer must issue a complete
40-row classification: variable, consuming test and assertion, control class,
whether it carries answer bits, whether it substitutes work, how occurrence is
witnessed, and whether it is reachable in the shipping artifact.

For Python, “compiled out” is not assumed. Result-selecting and work-substituting
paths are removed. Narrow deterministic fault injection is handled through
Validator-owned source mutants or an isolated composition seam outside the
shipping artifact, with an exact delta binding back to the same production core.

## Mechanical admission requirements

These requirements enforce already-ratified `spec/verification.md` instrument
validity; they do not amend product behavior:

1. Load-bearing JSON is parsed through strict typed/total evidence accessors. A
   product-facing test cannot use a bare early return, truthiness-gated assertion,
   default-zero success, or empty collection loop for required evidence.
2. Each proof test declares its evidence obligations; the harness records and
   verifies that every obligation executed. A missing observation is
   `INVALID_HARNESS` or `PRODUCT_FAILURE` according to its owner, never PASS.
3. Every frozen positive proof has the paired negative control or product/detector
   mutation required by the ratified catalog. Every named must-fail node must fail
   under its mutant; no surviving catalog mutation is tolerated.
4. Fault injection must independently witness that the fault occurred, identify a
   physical operation boundary rather than a semantic answer label, and assert
   recovery from durable state rather than product self-report.
5. A null product and a uniformly refusing product must make every relevant gate
   non-green. The Validator also inspects individual tests that remain green to
   distinguish legitimate negative controls from vacuity.
6. A source/static check inventories every acceptance-only product read and blocks
   result-selection or work-substitution paths from the shipping artifact.
7. Exact ratified baseline, Tester commits, failure deltas, collection counts, and
   mutation results remain immutable evidence. A reduced assertion/threshold/control
   is a semantic change requiring explicit disposition, not a repair by deletion.
8. The specification-mandated second implementation-blind Detector Reviewer must
   review the frozen repaired suite and dispose coverage, positive/negative controls,
   mutation sensitivity, and oracle privacy before any Coder snapshot is combined.

## Immediate Factory disposition

- Preserve the currently running Claude repair as an instrument-runtime repair
  only; do not admit its output merely because self-tests turn green.
- After that exact Tester commit freezes, dispatch the separate blind Detector
  Reviewer against specs/tests/fixtures only.
- Return the Detector Reviewer's failure categories to the Tester without any Coder
  or product output.
- Keep the GLM-5.3 Coder route blocked pending founder amendment or quota recovery.
- Do not combine a Coder snapshot until the Detector Reviewer has no unresolved
  finding and the Validator's no-vacuity/mutation probes pass.
