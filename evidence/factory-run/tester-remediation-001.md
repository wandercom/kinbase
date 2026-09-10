# Kinbase Factory Tester remediation 001

You remain the independent **Tester** for the Kinbase proof ratified by manifest
`ac8a13d184397fef574e173b81466ff43e6b3f91f89804c7ee797cc404a622db`.
This is a continuation of Tester session
`7b88a154-cc04-48b3-854f-08902f264c66` from exact Tester commit
`f8d9cba2cdd3de05663de9d9fffa9d0176f9d747`.

Your authority is still test authorship only. Do not inspect any Coder, Validator,
or product implementation path. Do not contact the Coder. Do not edit product
code, `spec/**`, or `evidence/**`. Work only in your existing standalone Tester
repository and change only `tests/**`. Do not issue a product verdict.

## Validator observation

The Validator cherry-picked your exact commit onto the pristine ratified baseline
and ran:

```sh
tests/run-acceptance.sh -m selftest --tb=line -q
```

No Coder commit or product implementation was present. The run collected 266
tests, selected 83, and returned 12 failures / 71 passes / 183 deselections in
0.60 seconds. Therefore this is `INVALID_HARNESS`; none of it is product evidence.
The emitted gate vector incorrectly called these failures `PRODUCT_FAILURE`.
Its SHA-256 was
`aabeb898b0204501ba36ae3f2e9c87ed37f8f085aa10b59b7abfae15ebf76e24`.

Exact failing nodes and concise observations:

1. `test_harness_selftest.py::test_detector_catches_every_frozen_transformation_family`
   — `urlsafe_b64decode()` received unsupported `validate=False`.
2. `test_harness_selftest.py::test_decoys_do_not_trip_the_detector`
   — same decoder defect.
3. `test_harness_selftest.py::test_randomized_sensitivity_meets_the_frozen_wilson_bound`
   — same decoder defect.
4. `test_harness_selftest.py::test_detector_mutations_miss_their_positive_control`
   — `disable_sqlite_blob_scan` did not blind its named capability.
5. `test_harness_selftest.py::test_packed_objects_and_sqlite_blobs_are_reachable`
   — same decoder defect surfaced during the probe.
6. `test_harness_selftest.py::test_findings_never_carry_raw_bytes`
   — same decoder defect surfaced during the probe.
7. `test_harness_selftest.py::test_normalised_views_cover_the_declared_encodings`
   — the ladder did not publish a `json_escape` view.
8. `test_nonfunctional.py::test_acceptance_suite_declares_all_its_dependencies`
   — its source scanner falsely reported `''`, ````product_failure``;``, `a`,
   `json,`, `the`, and `time,` as undeclared third-party modules.
9. `test_v10_protocol.py::test_normal_approximation_table_is_internally_consistent`
   — for `sd=0.05`, the frozen table says `N=8` while the test's computation gives
   `4`, outside its own tolerance.
10. `test_v3_attacks.py::test_every_frozen_attack_family_has_a_probe`
    — family 5, signed prompt-injection prose, had no mechanically recognized probe.
11. `test_v3_qualification.py::test_randomized_qualification_publishes_every_denominator`
    — same decoder defect.
12. `test_v3_qualification.py::test_mechanical_recovery_rule_is_frozen_before_the_run`
    — same decoder defect.

## Required remediation

- Repair the observation instrument without weakening, deleting, skipping, or
  xfail-marking any frozen control or threshold.
- Make harness/instrument defects classify as `INVALID_HARNESS`, never
  `PRODUCT_FAILURE`, including unexpected exceptions inside self-tests.
- Reconcile the README's `239` authored-test claim with actual pytest collection;
  report the exact post-repair collection count and why it differs if it still does.
- Run only product-independent instrument validation, including the exact command
  above and collection/backreference integrity. Do not run product-facing tests.
- Ensure the full changed footprint remains only `tests/**`, the tree is clean,
  and commit the repair on `factory/tester-ac8a13d1`.
- Return exact commit, parent, tree, changed paths, collection count, self-test
  result, commands run, and any residual uncertainty.

Your terminal line must be exactly one of:

```text
FACTORY_STATUS: DONE <40-hex-commit>
FACTORY_STATUS: BLOCKED <concise-reason>
```
