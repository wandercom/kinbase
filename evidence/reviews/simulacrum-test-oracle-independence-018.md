# Simulacrum review — acceptance controls and no-vacuity

Date: 2026-09-05

## Claim reviewed

The Validator proposed categorically rejecting every unratified
`KINBASE_ACCEPTANCE_*` input because scenario labels, synthetic counts, and
optional evidence assertions can let a proof-shaped implementation pass without
doing the measured work.

## Simulacrum correction

The proposed discriminator was too broad. Ratification is a governance property,
not an epistemic one: approving `TEMPORAL_CASE` would not stop it from leaking the
expected answer. The actual property is **oracle independence**:

> No input may cross the product boundary from which the product can infer the
> expected output, and no input may substitute for the computation the test claims
> to measure.

Applied to the observed suite:

- `TEMPORAL_CASE` and `V7_FIXTURE` are result-selecting oracle leaks when their
  labels select canned expected outputs.
- `SYNTHETIC_EVENT_COUNT` substitutes a number for processing the events and
  therefore cannot prove scale.
- `CRASH_AT` may be a legitimate deterministic fault injection because an external
  signal is unlikely to hit a microsecond durability seam. It is admissible only
  when it stops/delays/reorders/fails real work, never returns a result, preserves
  downstream production recovery over real state, and is provably absent from the
  shipping configuration.

## Four conditions for an acceptance-only control

1. Non-oracular: holding the control fixed while real product state changes must be
   capable of changing the expected output.
2. Terminal or scheduling-only: the control may stop, delay, reorder, or fail an
   operation; it may not select or fabricate a result.
3. It does not substitute for the measured work.
4. It is provably absent from the shipping configuration, with that absence itself
   tested.

## Binding no-vacuity criterion

A positive proof test is admissible only when all three conditions hold:

1. Every load-bearing assertion consumes a named field through a total accessor
   that rejects absent, null, or empty evidence. No truthiness-gated assertion,
   optional field check, empty-loop success, or early return may turn missing
   evidence into PASS.
2. The test declares the assertion/evidence obligations that must execute and the
   harness verifies all of them were exercised.
3. A paired negative control runs the same observation path against a constructed
   state where the claimed property is false and demonstrates that the instrument
   rejects it. If no falsifying state can be constructed independently of the
   control value, the test is a tautology rather than evidence.

## Concrete repair direction

- Materialize temporal histories and projection corpora as real events/files and
  let the product derive the result.
- Generate the actual event population for scale claims; if that is infeasible,
  narrow or withdraw the claim rather than fabricate N.
- Keep deterministic crash injection only under the four conditions above.
- Add mechanical suite-level enforcement for total evidence access, executed
  obligations, paired falsifiers, and shipping-build exclusion of test controls.

This review changes the Validator's initial categorical ban: acceptance-only
controls are not forbidden merely because they are unratified; result-selecting,
work-substituting, or shipping-reachable controls are forbidden because they
invalidate the proof.
