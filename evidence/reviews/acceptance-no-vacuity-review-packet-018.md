# Kinbase acceptance no-vacuity review packet

## Review question

Would the current independently authored acceptance suite establish the ratified
Kinbase concept if it went green, or can a proof-shaped implementation satisfy
it without performing the claimed work? Identify fatal gaps, admissible versus
inadmissible test controls, and the minimum repair that makes the evidence
decision-worthy. Do not optimize for milestone appearance or delivery speed.

## Authority and objective

- Ratification manifest:
  `ac8a13d184397fef574e173b81466ff43e6b3f91f89804c7ee797cc404a622db`
- Ratified baseline: `e29f3fe03595d594c0546f9b0012b58f7c45bac1`
- Exact Tester artifact:
  `f8d9cba2cdd3de05663de9d9fffa9d0176f9d747`
- The founder requires a proof that **does the thing**: heterogeneous ingestion,
  maintained three-store knowledge, temporal discrimination, real authority
  escalation, private-data non-disclosure, Codex and Claude lifecycle behavior,
  and a terminal blinded brownfield outcome experiment near the informed oracle.
- A green unit suite is explicitly necessary and insufficient.

## First execution

The Validator cherry-picked the exact Tester commit onto the pristine baseline.
`tests/run-acceptance.sh -m selftest --tb=line -q` collected 266 tests, selected
83, and returned 12 failures / 71 passes. The instrument therefore remains
`INVALID_HARNESS`. A separate repair is active; this packet asks whether runtime
self-repair alone would be enough. It would not address the observations below.

## Oracle and work-substitution surfaces

The suite passes 40 distinct `KINBASE_ACCEPTANCE_*` variables into the product.
None is in the ratified specification. Lack of ratification is not by itself the
epistemic objection; the question is whether the control supplies an expected
answer or replaces the measured work.

Concrete examples from the admitted Validator copy:

1. `tests/acceptance/test_v5_temporal.py:154` creates only an empty initialized
   repository. At line 174 every temporal case passes its semantic case ID as
   `KINBASE_ACCEPTANCE_TEMPORAL_CASE`, then asserts the answer associated with
   that same ID. No event history constructs the DST, rollback, supersession,
   conflict, or unregistered-environment state.
2. `tests/acceptance/test_v7_projection.py:69` also creates only an empty
   repository. At line 105 it sends `KINBASE_ACCEPTANCE_V7_FIXTURE=1`; the
   product is expected to emit the exact candidate roles, selection trace,
   complementarity, redundancy, distortion, and stopping answer the test asserts.
3. `tests/acceptance/test_v4_maintenance.py:450` and line 466 send only
   `KINBASE_ACCEPTANCE_SYNTHETIC_EVENT_COUNT` instead of creating the population
   whose intake and diagnosis cost is claimed. The oversized intake is permitted
   to return success at lines 454-457, so a product that accepts 10x the admission
   ceiling can pass that part of the test.
4. Other result- or scenario-selecting controls include
   `MANIFEST_SCENARIO`, `DIGEST_SCENARIO`, `COMPANY_CRITICALITY`,
   `LOCAL_DEPENDENCE`, `FACT_VALIDITY`, `DEPENDENCE_CLASS`, `START_STATE`, and
   `MAINTENANCE_WORKLOAD`.

Deterministic fault injection such as `CRASH_AT` may be different: a control that
only terminates real work at a narrow boundary can be more probative than an
external signal. The review must distinguish failure scheduling from result
selection and work substitution.

## Missing-evidence-is-pass surfaces

At least 16 bare early returns occur in product-facing test functions, with many
more truthiness-gated assertions. Examples:

1. `test_v4_maintenance.py:561-585`: pre-revocation replay passes when the
   `pre_revocation_replay` evidence object is absent.
2. `test_v4_maintenance.py:603-641`: linked-worktree admission checks that no
   worktree-local lock exists, but never requires a common-directory lock to
   exist or proves serialization/one manifest lineage.
3. `test_v2_classification.py:717-755`: the crash test never proves a crash
   occurred, then treats absent `duplicate_events` and `recursive_apologies` as
   zero.
4. `test_evidence_packet.py:217-239`: retention/incident-hold enforcement returns
   successfully when the product emits no verdict packet; the asserted fields
   are optional when output exists.
5. `test_evidence_packet.py:367-382`: Factory method labeling passes when the
   verdict command refuses, emits no output, or omits the method label.
6. `test_v10_protocol.py:1032-1053`: the licensed-claim test returns on missing
   verdict output and requires the claim template only when the product itself
   reports `PROVEN`.
7. `test_verdict_composition.py:221-258`: the product-composition comparison
   returns on missing output and makes each composed result optional.

## Proposed admissibility rule after Simulacrum

An acceptance-only control is admissible only if all four hold:

1. It is non-oracular: holding the control fixed while real state changes can
   change the correct output.
2. It may stop, delay, reorder, or fail real work, but cannot select/fabricate a
   result.
3. It cannot substitute for the work the test claims to measure.
4. It is structurally absent from shipping configuration, and that absence is
   itself tested.

A positive proof test is admissible only if:

1. load-bearing evidence uses total accessors—absent, null, empty, or
   unexercised evidence rejects the test rather than passing;
2. required evidence/assertion obligations are declared and mechanically shown
   to execute; and
3. the same observation path rejects a constructed falsifying state independent
   of the expected-answer input.

## Questions for Advocate

1. Is this proposed oracle-independence rule sufficient, too strict, or still
   gameable?
2. Which of the observed controls can legitimately survive, under what exact
   structural constraint?
3. Must every semantic scenario be built as real events/files/service responses,
   or are any compressed fixtures probative?
4. What denial probes prevent a green test harness from becoming a second oracle
   implemented inside the product?
5. What would a technical leader be unable to defend if the current suite were
   used to claim the concept proven?
