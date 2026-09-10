# Six-case ruling follow-up

No product files were edited. The ownerless conflict was reproduced against the
worktree release binary using a private copy of the real `pytest-725` fixture
and its signed cached authority snapshot. It is not a newly run Company service.

## Conflict and terminal-ruling preconditions: product gap

`explain scheduler/ruling-conflict` reports:

- `trace.state = conflict`;
- two eligible, live, distinct statements;
- both planted IDs in `conflict_event_ids`;
- an open reducer Unknown with loss 9000 and both heads as evidence.

`project --task scheduler/ruling-conflict --decision 'Which rule governs
scheduler/ruling-conflict?'` retains that open conflict in its output but returns
`question_id = null`; `questions list` returns `[]`.

The stage that drops it is **projector's outer `has_blocking_unknown` guard**,
before `ensure_question`. The predicate compares the task/decision to the literal
`decision_blocked` string, `use of logical key scheduler/ruling-conflict`. Neither
the named task key nor the natural-language decision matches it. The new inner
conflict exception consequently never runs. Repeating the diagnostic call with
that exact literal decision raises an `awaiting_authority` question, proving
`ensure_question` and persistence/listing work when reached.

The tests keep their ordinary wording. Both conflict fixtures now explicitly
check the two-head reduction and corresponding Unknown before testing questions.
The shrug/unruled tests remain red if no initial question opens; terminal behavior
cannot be assessed past that failed precondition.

## Unmarked Git history: product gap

A fresh isolated fixture with 32 unmarked commits was ingested using the copied
signed cache. Ingest returns exit 0, but the observation JSON contains neither
`provenance` nor `standing`. `lifecycle::SourceRecord.provenance` is computed by
the adapter but is not copied into `model::Observation` or the ingest response.
The existing assertions remain unchanged: treating missing data as `unknown`
would conceal the loss of the agent attribution as well.

## Revocation: correct the time precondition, retain the gate

The source failure occurs **before revocation**. The default recorded proof clock
precedes the wall-clock effective time of the automatically admitted signed event,
so the trace rejects it as `NOT_YET_EFFECTIVE`. A diagnostic `explain --as-of` at
that event's effective time returns a current, trusted fact.

The test now explicitly reads before revocation at the signed effective time and
after revocation at a fresh explicit time. Its final assertion additionally
requires the exact admitted event's `REVOKED` or `SUPPORT_REVOKED` rejection;
unrelated withholding/expiry no longer satisfies it. Signature, content address,
current-before-revocation and retained-record checks remain.

Live registry revocation cannot be rerun in this sandbox because loopback socket
binding is denied. This change repairs the demonstrated precondition; it does
**not** establish an end-to-end revocation pass.

## Verification

- Offline locked release build: pass (47.49 seconds on the final rebuild).
- Formatting check and `git diff --check`: pass.
- Instrument regressions: **142 passed**, including four positive/negative
  conflict-fixture controls and two host-resolution controls.
- Ruling pytest module: **3 passed, 13 setup errors**, all setup errors from the
  sandbox's loopback-bind denial. No service-backed assertion result is claimed.
- The Git commit is blocked by sandbox denial of the shared worktree's
  `index.lock`; the changes remain in `tests/` for the owner to commit.
