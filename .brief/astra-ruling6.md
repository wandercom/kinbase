# Astra: the six remaining ruling-loop failures

`tests/` and the fixture are yours; I own model.rs, reducer.rs, projector.rs,
questions.rs, lifecycle.rs. Ruling loop is 10/16.

I fixed three real product gaps and they are committed:
- a current `shrug` fact now suppresses unknowns for its logical key (reducer.rs,
  filtered once at the end of reduction);
- a `conflict` unknown now raises a question regardless of `loss_if_absent`, because
  the threshold is right for uncertainty that might not matter and wrong for two
  incompatible statements both being carried;
- an ownerless conflict (`UNKNOWN_OWNER_UNRESOLVED`) now counts as open, so the
  absence of a registered authority stops being the reason nobody is ever asked.

Still failing, and I think the remainder is fixture rather than product:

    test_conflicting_evidence_without_answering_authority_opens_question
    test_shrug_is_terminal_while_unruled_remains_actionable[shrug|unruled]
    test_git_authorship_survives_ingestion_without_inventing_human_review[False]
    test_automatically_admitted_shared_fact_remains_revocable

The first two share a precondition: two planted `present` facts on one logical key
must produce a conflict head pair, and `questions list` still returns `[]`. Before
changing product code, confirm the fixture actually reaches `trace.state == "conflict"`
-- run `explain` on the key and look. If the two plants are being collapsed (same
statement identity, a supersession, or one rejected as ineligible) the fixture never
contests anything and no product change will help.

If it *is* reaching conflict and no question appears, that is a real product gap and
I want to know precisely where it dies: reducer unknown -> projector open_unknowns ->
ensure_question -> `questions list`. Name the stage.

`test_automatically_admitted_shared_fact_remains_revocable` matters more than its
count suggests: removing the approval gate must not have removed the ability to take
something back. If revocation is genuinely broken, stop and say so loudly rather than
fixing the test.

Do not weaken an assertion to make a count go green.
