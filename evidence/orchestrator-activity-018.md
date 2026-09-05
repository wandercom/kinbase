# Orchestrator activity delta — cursor 18

## New review evidence

The Validator's systematic test audit plus Simulacrum review was bound at
`32f2567`. Advocate then ran Helland, Adversarial, Red Team, SME, and Good Friend
against immutable packet `bcdd7c8`: 56 findings, USD 0.8222, no tool-reported
disagreements. Exact output and disposition are committed at `27870c8`.

All five summaries agree that repairing the 12 runtime self-test failures is not
enough. The suite currently permits answer-bearing scenario labels, substitutes
counts for real work, allows missing evidence to pass, and lets product-reported
`PROVEN` gate a Validator-owned obligation. The disposition narrows the rule to
oracle independence rather than banning every acceptance-only control.

## Proposed action

1. Allow the currently isolated Claude Tester runtime repair to complete, but do
   not admit it merely because self-tests become green.
2. Freeze and audit its exact commit.
3. Satisfy `spec/verification.md` by dispatching a fresh implementation-blind
   **Detector Reviewer** in a new standalone clone containing only the ratified
   specs and exact Tester artifact. Proposed model: GPT-5.6, because SRC-6 fixes
   only Coder=GLM-5.3 and Tester=Claude; the Detector Reviewer is a distinct
   mandatory role. It receives no Coder/product implementation or logs and may
   only review, not author tests or issue a product verdict.
4. Require the Detector Reviewer to disposition coverage, positive/negative
   controls, mutation sensitivity, oracle privacy, every early-return/optional
   assertion, and all 40 acceptance-control variables under the criteria in
   `evidence/reviews/advocate-acceptance-no-vacuity-disposition-018.md`.
5. Return only reviewer findings to the same blind Tester for repair. Keep Coder
   stopped and hidden throughout.

## Requested assessment

Assess whether this sequencing and distinct GPT-5.6 Detector Reviewer preserve the
frozen Factory authority, independence, and founder's actual proof objective.
Return `BLOCK` or `NO-OP` only. You may not approve the instrument, authorize
spend, amend routing, implement, test, or render a product verdict.
