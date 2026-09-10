# Astra: the v9 host-lifecycle failures

Branch `rescue/ruling-loop`. I am fixing the four ruling-loop properties in
`model.rs`, `reducer.rs`, `questions.rs`, `session.rs`, `lifecycle.rs` — **do not
touch those five.** `tests/` and `hooks.rs` are yours.

Full run: 305 passed, 21 failed. Ten of the failures are yours:

    test_v9_host_lifecycle.py::test_hooks_plan_is_read_only_and_install_requires_native_approval
    test_v9_host_lifecycle.py::test_native_host_events_prime_capture_and_exclude_personal[codex|claude]
    test_v9_host_lifecycle.py::test_session_start_p95_under_two_seconds_in_every_state[codex|claude]
    test_v9_host_lifecycle.py::test_blackholed_company_endpoint_degrades_loudly_inside_the_budget
    test_v9_host_lifecycle.py::test_twenty_session_soak_warm_path_and_fsck_incidence[codex|claude]
    test_nonfunctional.py::test_private_raw_retention_remains_enforced
    test_v2_classification.py::test_five_pinned_runs_lower_bound_meets_macro_f1_and_shared_precision

These are host lifecycle, latency and soak properties that have nothing to do with
the approval gate we removed, so I expect most are fallout from the session rewrite
rather than genuine regressions — but confirm rather than assume. If one is a real
regression in the product, say so plainly and leave it red with a one-line finding;
do not weaken an assertion to make a count go green.

Note the fact view changed shape: `CurrentFact` now emits `standing`,
`claimed_standing`, `provenance`, `governs_paths` and `anchors`. If a canonical
payload comparison broke because of those new fields, decide deliberately whether
they belong in the canonical form — I think they do, since standing is part of what a
projection means — and update the expectation with a comment saying why.

Run: from `tests/`, `KINBASE_BIN=~/WanderRepos/kinbase-work/target/release/kinbase
KINBASE_SPEC_ROOT=~/WanderRepos/kinbase-work ./.venv/bin/python -m pytest -c
pytest.ini -q acceptance/test_v9_host_lifecycle.py`

Strictly offline; no new Cargo projects. Commit when green and report.
