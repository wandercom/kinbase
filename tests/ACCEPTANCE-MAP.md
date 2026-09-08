# Acceptance map — ratified obligation to instrument

Every row ties a ratified gate to the modules that observe it. Counts are
resolved `@spec_ref` backreferences, not test counts; a single test may carry
several exact citations.

The machine-readable catalog is `tests/fixtures/catalog/obligations.json`
(digest `8320395313ff6f00`): 117 obligations and
482 thresholds, each freezing a
threshold, positive control, negative control, product mutation and detector
mutation. `tests/fixtures/catalog/planters.json` records the 35
executable pre-execution planters and `tests/fixtures/controls/controls.json` the frozen raw positive and
negative controls. 259 node ids collect; none is unbackreferenced.
Kill-ledger digest: `b16d7fd1b37174a5`; frozen-controls digest: `584e528d085ba7f6`.
The 140 selftest nodes include seven dispatch-007 and ten dispatch-008 regression guards.

Authority precedence (`spec/ratification-manifest.json`):
`source-request.md > product.md > architecture.md > threat-model.md >
verification.md > cli.md`.

| gate | modules (resolved backreferences) |
|---|---|
| `V-1` | `test_v1_ingestion.py` (12) |
| `V-2` | `test_v2_classification.py` (15) |
| `V-3` | `test_v3_attacks.py` (2), `test_v3_privacy.py` (11), `test_v3_qualification.py` (2) |
| `V-4` | `test_v4_maintenance.py` (11) |
| `V-5` | `test_v5_temporal.py` (15) |
| `V-6` | `test_v6_authority.py` (6) |
| `V-7` | `test_v7_projection.py` (18) |
| `V-8` | `test_v8_company_refs.py` (12) |
| `V-9` | `test_v9_fatigue.py` (6), `test_v9_host_lifecycle.py` (7) |
| `V-10` | `test_v10_protocol.py` (47) |
| `NONFUNCTIONAL` | `test_nonfunctional.py` (27) |
| `EVIDENCE` | `test_evidence_packet.py` (20) |
| `VERDICT` | `test_verdict_composition.py` (18) |
| `INSTRUMENT` | `test_backreference_integrity.py` (6), `test_harness_selftest.py` (33) |

## Instruments

| module | purpose |
|---|---|
| `_harness/requirements.py` | manifest/digest verification; `spec_ref` exact-quote binding |
| `_harness/cli.py` | black-box driver for the `spec/cli.md` command and error contract |
| `_harness/service.py` | loopback `guildhalld` client with individually defeatable controls |
| `_harness/detectors.py` | deterministic canary detector, normalisation ladder, detector mutations |
| `_harness/scanners.py` | recursive surface sweep: files, archives, packed Git objects, SQLite blobs, process artifacts |
| `_harness/canaries.py` | synthetic canary generation and the twelve frozen transformation families |
| `_harness/vault.py` | Tester-custodied mode-0700 canary vault and sealed registry |
| `_harness/crypto_box.py` | hermetic ChaCha20 + HMAC-SHA256 for the vault |
| `_harness/ed25519_pure.py` | RFC 8032 signing, independent of any product library |
| `_harness/canonical.py` | RFC 8785 JCS, `guildhall-sig/1` domain separation, control/bidi rejection |
| `_harness/stats.py` | Wilson, paired bootstrap, TOST, kappa, exact binomial, Monte Carlo power, call envelope |
| `_harness/gates.py` | verdict composition transcribed from the ratified table |
| `_harness/ordering.py` | V-10 phase ledger, blindness predicates, arm-difference bindings |
| `_harness/mutations.py` | the 41-entry frozen mutation catalog and must-fail node sets |
| `_harness/evidence.py` | evidence-packet schema, failure-row and retention rules |
| `_harness/hosts.py` | real host resolution, native envelopes, latency and soak budgets |
| `_harness/synth.py` | native-format source generators for all ten adapters |
| `_harness/gitfix.py` | deterministic repository fixtures for every lifecycle cell |
| `_harness/lifecycle_observations.py` | C15 matrix derivation from public Observation records, linked facts/Unknowns, and adapter receipts |

## Frozen numeric thresholds asserted by the suite

| quantity | value | authority |
|---|---:|---|
| held-out routing messages / mixed / canary-bearing | 120 / 40 / 100 | V-2, P-2 |
| seeded private canaries | 30 | P-2 |
| classifier runs, macro-F1 lower bound, shared precision | 5 / 0.90 / 0.95 | V-2, P-2 |
| annotator Cohen's kappa per destination | 0.80 | V-2 |
| calibration corpus size | 60 | V-2 |
| randomized positives / decoys | 300 / 500 | V-3, threat model |
| per surface/encoding family stratification floor | 10 | V-3 |
| detector sensitivity Wilson lower / false-positive Wilson upper | 0.98 / 0.01 | V-3 |
| revocation cascade bound | 120 s | V-4 |
| `.kin/` intake ceiling | 10,000 events / 128 MiB | operational limits |
| projection ceiling | 32 facts / 128 KiB | operational limits |
| SessionStart p95, every state | 2 s | V-9 |
| Company connect budget | 250 ms | V-9 |
| full fsck at ceiling | 120 s | V-9 |
| invocations per host/state | 200 | V-9 |
| soak sessions / warm path / full-fsck incidence | 20 / ≥90% / ≤5% | V-9 |
| prompt budget per sliding hour / consecutive | 4 / 3 | P-9 |
| operator exercise items / accuracy / median time | 20 / 95% / 30 s | P-9 |
| maintenance workload / durable facts / slots / admissions | 100 / 20 / ≥18 / ≥17 | P-9 |
| arms / measurement seeds / structural task floor | 11 / 3 / 8 | P-10 |
| pilot tasks / repositories / seeds | 12 / 3 / 3 | P-10 |
| reserved coding calls | `396 + 33*N + 11*ceil(0.10*3*N)` | V-10 |
| block reserve | 10%, rounded up | P-10 |
| static prior | ≤ 2 KiB | P-10 |
| composite weights | 0.50 / 0.20 / 0.10 / 0.10 / 0.10 | architecture §10 |
| co-primary lifts | 0.15 baseline, 0.15 null, 0.10 static/top-k/store | P-10 |
| equivalence band | ±0.05 | P-10 |
| residency / mean facts / resident precision | ≥80% / ≤12 / ≥0.25 | P-10 |
| joint and marginal power | ≥80% each | V-10 |
| blinding failure thresholds | 1/11 + 0.15, p<0.05; balanced 0.65, p<0.05 | P-10 |
| denial-stratum density | 20–40% by count and bytes | P-10 |
