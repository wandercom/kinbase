# Astra: close the five stale nodes

Branch `rescue/ruling-loop`. Build green. I am adding an `issue_tracker` source kind
in `lifecycle.rs`, `model.rs` and `adapters.rs` — **do not touch those three.**
`tests/` is yours.

Full run on an unsandboxed machine: **304 passed, 5 failing.** Your 117 setup errors
were your sandbox refusing loopback binds; they do not reproduce here.

    test_v2_classification.py::test_expired_closing_deadline_emits_one_signed_orphan_abandoned
    test_v2_classification.py::test_kill_at_every_transition_then_concurrent_retry
    test_v2_classification.py::test_no_cross_store_transaction_exists
    test_v3_privacy.py::test_hard_blocking_taint_is_never_cleared_by_deidentification
    test_v9_host_lifecycle.py::test_matched_conversations_produce_identical_canonical_payloads

All five read state through the candidate queue you deleted: they pull
`rows(payload, "candidates")` and assert `candidate_count >= 1`. Session observe now
reports **`admissions`**, not `candidates` — a fact is admitted directly, so there is
no queue to inspect. The nodes are measuring a channel that no longer exists.

Rewrite each against `admissions`. The properties they assert are all still real and
must stay asserted — do not delete a node to make the count green:

- **taint** — I verified this by hand and it holds. One message carrying a canary
  token plus a durable architectural fact produced two admissions,
  `codebase:<uuid>` and `personal`, and the canary was in neither. Assert exactly
  that: the canary reaches no shared destination, and its taint survives
  de-identification on the private record.
- **no cross-store transaction** — still true and still worth proving; read it off
  the admission receipts rather than the queue.
- **orphan_abandoned on expiry**, **kill at every transition then concurrent
  retry** — these are crash/lifecycle properties, unrelated to approval. Point them
  at the admission path.
- **matched conversations produce identical canonical payloads** — host-level, also
  unrelated to approval.

Run it yourself: from `tests/`,
`KINBASE_BIN=~/WanderRepos/kinbase-work/target/release/kinbase KINBASE_SPEC_ROOT=~/WanderRepos/kinbase-work ./.venv/bin/python -m pytest -c pytest.ini -q acceptance/<node>`

Do not create Cargo projects; this machine is strictly offline. Commit when the five
pass and report the final count.
