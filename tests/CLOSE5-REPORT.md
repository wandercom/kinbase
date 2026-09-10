# Close-five admission migration

All five requested nodes remain present. They now read `admissions` from
`session observe`, concurrent `session checkpoint` results, or native host Stop
checkpoint results. None of the five reads the candidate queue.

- Orphan expiry uses one fan-out source and binds the apology to its failed and
  committed admission receipt IDs. Its signed terminal-event, withdrawal and
  zero-pending-orphan assertions remain.
- Crash recovery still witnesses all five transitions and SIGKILL. Both concurrent
  retries must succeed and return the same nonempty receipt set. Durable event
  counts and recursive-apology checks no longer depend on candidates.
- Cross-store independence inspects the actual Codebase/Company receipts, requires
  both destinations, distinct receipt identities and no global rollback.
- Taint checks exactly two committed admissions, Codebase and Personal. It resolves
  their signed, content-addressed events, checks the canary is absent from both
  events and receipts, and checks private atom taint survives checkpoint/replay.
- Host parity submits matched conversation bodies through native hook envelopes
  and session observation, checks Stop retains admission receipts, and compares
  admitted fact semantics, canonical receipt content and post-admission projections.
  Per-invocation IDs, signatures and clocks are not canonical payload fields.

The frozen catalog and controls reflect these assertions. One additional instrument
node proves that admission receipts resolve without a candidate queue, and that
queue-only input and missing event bytes fail. Existing crash-recovery mock tests
now exercise the admission response shape.

Validation:

- `cargo build --release --offline --locked`: passed.
- `cargo fmt --all -- --check`: passed.
- Instrument/catalog/backreference regression set: **141 passed**.
- Catalog and green-path checks after the final metadata edit: **29 passed**.
- The five requested nodes: **5 setup errors**, all socket-bind `PermissionError`.
- Full suite: **219 passed, 117 setup errors, zero assertion failures** in 102.82s;
  **336 collected**, up from 335 solely because of the new instrument guard.
- `git diff --check`: passed.

All 117 full-suite setup errors are the sandbox denying loopback socket binds.
They occur before product assertions. The user's reported unsandboxed baseline
of 304 passed / 5 failing is not represented as a locally verified result, and
this report does not claim the five product failures are closed.

Run the five from `tests/` with the worktree binary:

```sh
export KINBASE_BIN=~/WanderRepos/kinbase-work/target/release/kinbase
export KINBASE_SPEC_ROOT=~/WanderRepos/kinbase-work
./.venv/bin/python -m pytest -c pytest.ini -q \
  acceptance/test_v2_classification.py::test_expired_closing_deadline_emits_one_signed_orphan_abandoned \
  acceptance/test_v2_classification.py::test_kill_at_every_transition_then_concurrent_retry \
  acceptance/test_v2_classification.py::test_no_cross_store_transaction_exists \
  acceptance/test_v3_privacy.py::test_hard_blocking_taint_is_never_cleared_by_deidentification \
  acceptance/test_v9_host_lifecycle.py::test_matched_conversations_produce_identical_canonical_payloads
```

Only `tests/` was edited. No dependencies or Cargo projects were added. Changes
remain uncommitted pending the requested unsandboxed five-node pass.
