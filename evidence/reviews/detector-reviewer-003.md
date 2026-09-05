# Detector Reviewer report — dispatch 003

## Disposition

The acceptance instrument is blocked from exposure to a product snapshot. This is an instrument-validity disposition only; it is not a product or proof verdict.

## Binding and information-boundary attestation

| Binding | Observed |
|---|---|
| HEAD | `263d41d77ae11e4e62f2ce2716378a8e1ebdc7f2` — exact match |
| HEAD tree | `61af5f8966f9a070e36eef31681d2c6c98a68c58` — exact match |
| Manifest SHA-256 | `ac8a13d184397fef574e173b81466ff43e6b3f91f89804c7ee797cc404a622db` — exact match |
| Founder receipt | Binds the exact manifest at [founder-ratification-ac8a13d1.json:7](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/receipts/founder-ratification-ac8a13d1.json:7) |
| Validator receipt | Binds the exact manifest at [validator-ratification-ac8a13d1.json:7](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/receipts/validator-ratification-ac8a13d1.json:7) |

All six authority-artifact digests were recomputed and matched [ratification-manifest.json:13](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/ratification-manifest.json:13):

- `source-request.md`: `1b2548e7025d00a8e06ab2e1445e89fdabf9f27833885c9f7953a8a0da354350`
- `product.md`: `452c81e1c59bd96b59239939f1cb485a0016cd6e82f2dd627d853e448cf4c090`
- `architecture.md`: `4b8d9bfc241f59af9e4c3188e3343f52186c923b73816671694577612a77c520`
- `threat-model.md`: `6391c14853c0bc1a059a0a4aded31c878ed74eddecb5578903717aa152f10f09`
- `verification.md`: `2a07e44a68380cc2ab305e12fcff6b5501dd6854d8a0aef790dac1a8ac8ae94c`
- `cli.md`: `0a0edc5e6ebe13a42c7e325836f9fe5e3eeca329006c02631736e3cde0448b6d`

The tracked top-level tree contains `.kin`, `evidence`, `spec`, `tests`, and repository metadata, with no separate tracked product source tree. `spec/**` and `tests/**` are clean by scoped status and staged/unstaged diff checks.

Full worktree cleanliness could not be established: Git could not stat 17 tracked paths under `.kin/**` and `evidence/**`, reporting `Operation not permitted`. Those paths were not opened. Consequently, untracked or modified material in those forbidden areas cannot be excluded.

I inspected only `spec/**`, `tests/**`, and necessary Git metadata. I did not inspect the contents of `.kin/**`, `evidence/**`, parent/sibling directories, another repository, product implementation, prior-review material, Kindex/global memory, user history/configuration, or the web. I did not source `~/.profile`, invoke the Simulacrum, spawn agents, or make repository edits. Reviewer execution wrote only ephemeral pytest state outside the repository, which the Reviewer-safe script removed.

## Methods and commands

Principal commands and checks were:

```text
git rev-parse HEAD
git rev-parse HEAD^{tree}
sha256sum spec/ratification-manifest.json
git status --short --untracked-files=all -- spec tests
git diff --quiet -- spec tests
git diff --cached --quiet -- spec tests
git status --short --untracked-files=no
git ls-tree --name-only HEAD

tests/reviewer-selftest.sh -vv

python3 -m pytest -c tests/pytest.ini -p no:cacheprovider \
  --collect-only -q tests/acceptance
```

Additional read-only Python/AST checks:

- Recomputed all six manifest-bound artifact hashes.
- Parsed the catalog independently rather than trusting its reported counts.
- Counted obligations and threshold clauses by gate.
- Checked duplicate obligation IDs, threshold tags, consumer declarations, and collected functions.
- Compared all catalog consumer nodes and all mutation `must_fail_nodes` against the 266-item collection.
- Located every literal `O.check("<oid>", ...)` coupling.
- Executed the product-independent 401-row synthetic kill ledger.
- Counted permissive collection defaults, optional loops, guarded assertions, bare returns, and skip calls.
- Recomputed auxiliary component hashes, entry counts, and the combined digest.

## Reviewer-safe selftest and gate vector

`tests/reviewer-selftest.sh -vv` produced:

- `108 passed`
- `158 deselected`
- `266 collected`
- no executed skip
- three unknown-config warnings
- process exit `0`

The complete reported vector was:

| Group | Reported | Instrument | Product | Executed/expected |
|---|---|---|---|---:|
| V-1 | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | 0/11 |
| V-2 | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | 2/14 |
| V-3 | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | 2/13 |
| V-4 | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | 0/11 |
| V-5 | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | 0/6 |
| V-6 | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | 0/6 |
| V-7 | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | 0/7 |
| V-8 | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | 0/12 |
| V-9 | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | 0/13 |
| V-10 | `PASS` | `PASS` | `PASS` | 2/2 |
| NONFUNCTIONAL | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | 0/0 |
| EVIDENCE | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | 0/0 |
| VERDICT | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | 0/0 |
| INSTRUMENT | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | 0/0 |

Thus the green process is not semantically green overall. More importantly, V-10 reports product `PASS` even though no product exists and only two static, selftest-marked protocol assertions ran.

## Complete obligation matrix

### Independently reconstructed totals

| Gate | Obligations | Threshold rows | Ratified execution domain |
|---|---:|---:|---|
| V-1 | 11 | 38 | Ten native adapters and 64 lifecycle cells through ingest/rebuild/status |
| V-2 | 13 | 54 | Held-out and independent calibration corpora, five classifier runs, four labels, fan-out saga seams |
| V-3 | 13 | 51 | Nineteen attack families, all shared surfaces, encodings, lifecycle stages, reconstruction |
| V-4 | 11 | 48 | Signed events, manifests, clones/worktrees, 13-stage cycles, rewrite/replay/lock/scale |
| V-5 | 6 | 19 | Nine signed temporal histories, reducer traces, counterfactuals |
| V-6 | 6 | 36 | Live Company service, registered authority channel, signed round trip |
| V-7 | 7 | 22 | Signed candidate set, working-set changes, evidence tiers, marginal-value terms |
| V-8 | 11 | 49 | Live Company facts/history, references, certificates, cache/revocation truth table |
| V-9 | 13 | 82 | Real Codex/Claude install and invocation, four start states, topology, fatigue/operator workloads |
| V-10 | 1 | 2 | Only the static arms/envelope row is represented in this catalog |
| **Total** | **92** | **401** | V-1–V-9 alone: 91 obligations and 399 rows |

The asserted counts 92, 401, 35, 266, and 108 are numerically correct.

### Matrix legend

Each entry below is:

```text
obligation[thresholds | surfaces/vectors | PC/NC/PM/DM | checker link | fail-closed]
```

- `SV`: nonempty surface/vector strings exist.
- `BAD-V`: malformed vector declaration.
- `S/S/S/S`: all four controls are synthesized from the same clause definition, not independently observed.
- `C`: the suite contains a literal call to `O.check()` for this exact obligation.
- `U`: the named function collects, but does not consume this obligation’s checker.
- `PF`: declared `PRODUCT_FAILURE`.
- `IH`: declared `INVALID_HARNESS`.

```text
V-1
 adapters-native[3|SV|S/S/S/S|U|PF]
 receipt-not-count[3|SV|S/S/S/S|U|PF]
 build-manifest[5|SV|S/S/S/S|U|PF]
 idempotence[5|SV|S/S/S/S|U|PF]
 disposition-change[2|SV|S/S/S/S|U|PF]
 lifecycle-matrix[1|SV|S/S/S/S|C|PF]
 support-retirement[5|SV|S/S/S/S|U|PF]
 clock-skew[3|SV|S/S/S/S|U|PF]
 misextraction[5|SV|S/S/S/S|U|PF]
 never-true-authority[3|SV|S/S/S/S|U|PF]
 origin-trust[3|SV|S/S/S/S|U|PF]

V-2
 corpus-floors[6|SV|S/S/S/S|U|IH]
 annotators[3|SV|S/S/S/S|U|IH]
 pinned-runs[8|SV|S/S/S/S|U|PF]
 calibration[5|SV|S/S/S/S|U|PF]
 atomisation[2|SV|S/S/S/S|U|PF]
 metrics[5|SV|S/S/S/S|U|PF]
 low-confidence[2|SV|S/S/S/S|U|PF]
 independent-candidates[3|SV|S/S/S/S|U|PF]
 partial-fanout[7|SV|S/S/S/S|U|PF]
 retry-receipt[4|SV|S/S/S/S|U|PF]
 orphan-abandoned[5|SV|S/S/S/S|U|PF]
 crash-recovery[2|SV|S/S/S/S|C|PF]
 no-cross-store[2|SV|S/S/S/S|U|PF]

V-3
 lifecycle-scan[5|SV|S/S/S/S|C|PF]
 positive-control[4|SV|S/S/S/S|U|IH]
 qualification[8|SV|S/S/S/S|C|IH]
 capability[1|SV|S/S/S/S|U|PF]
 sandbox[4|SV|S/S/S/S|U|PF]
 inherited-fd[4|SV|S/S/S/S|U|PF]
 process-artifacts[3|SV|S/S/S/S|U|PF]
 taint[3|SV|S/S/S/S|U|PF]
 paraphrase[3|SV|S/S/S/S|U|PF]
 egress[4|SV|S/S/S/S|U|PF]
 claim[4|SV|S/S/S/S|U|PF]
 attack-families[1|SV|S/S/S/S|U|IH]
 reconstructor[7|SV|S/S/S/S|U|PF]

V-4
 incremental-cycle[4|SV|S/S/S/S|C|PF]
 conflict[5|BAD-V|S/S/S/S|U|PF]
 manifest-comparison[4|SV|S/S/S/S|U|PF]
 normalisation[4|SV|S/S/S/S|U|PF]
 determinism[3|SV|S/S/S/S|U|PF]
 as-of[3|SV|S/S/S/S|U|PF]
 ceiling[5|SV|S/S/S/S|U|PF]
 cascade[5|SV|S/S/S/S|U|PF]
 replay[5|SV|S/S/S/S|U|PF]
 common-dir-lock[6|SV|S/S/S/S|U|PF]
 kindex-compat[4|SV|S/S/S/S|U|PF]

V-5
 cases[1|SV|S/S/S/S|C|PF]
 no-newest-wins[3|SV|S/S/S/S|C|PF]
 independence[4|SV|S/S/S/S|C|PF]
 scope[3|SV|S/S/S/S|C|PF]
 runtime-vs-architecture[4|SV|S/S/S/S|C|PF]
 unregistered-environment[4|SV|S/S/S/S|C|PF]

V-6
 registration[8|SV|S/S/S/S|U|PF]
 question[9|SV|S/S/S/S|U|PF]
 round-trip[8|SV|S/S/S/S|U|PF]
 wrong-role[3|SV|S/S/S/S|U|PF]
 degraded[4|SV|S/S/S/S|U|PF]
 call-ceiling[4|SV|S/S/S/S|U|PF]

V-7
 candidate-set[5|SV|S/S/S/S|C|PF]
 set-conditional[3|SV|S/S/S/S|C|PF]
 no-crowding[3|SV|S/S/S/S|C|PF]
 marginal-terms[1|SV|S/S/S/S|C|PF]
 complementarity[3|SV|S/S/S/S|C|PF]
 voi-stop[6|SV|S/S/S/S|C|PF]
 query-log[1|SV|S/S/S/S|C|PF]

V-8
 fresh-clone[5|SV|S/S/S/S|C|PF]
 reference-fields[12|SV|S/S/S/S|U|PF]
 stricter-class[1|SV|S/S/S/S|C|PF]
 steward-only-exception[5|SV|S/S/S/S|U|PF]
 digest-attribution[2|SV|S/S/S/S|C|PF]
 uncertified[6|SV|S/S/S/S|C|PF]
 identity[4|SV|S/S/S/S|C|PF]
 publish-manifest[4|SV|S/S/S/S|C|PF]
 expiry[4|SV|S/S/S/S|U|PF]
 cache-table[2|SV|S/S/S/S|C|PF]
 counts-only[4|SV|S/S/S/S|U|PF]

V-9
 setup[11|SV|S/S/S/S|U|PF]
 native-events[8|SV|S/S/S/S|U|PF]
 parity[5|SV|S/S/S/S|U|PF]
 latency[4|SV|S/S/S/S|U|PF]
 blackhole[6|SV|S/S/S/S|U|PF]
 topology[5|SV|S/S/S/S|U|PF]
 soak[6|SV|S/S/S/S|U|PF]
 prompt-budget[7|SV|S/S/S/S|C|PF]
 reset[5|SV|S/S/S/S|U|PF]
 reissue-atomicity[6|SV|S/S/S/S|U|PF]
 interleave[6|SV|S/S/S/S|U|PF]
 operator[6|SV|S/S/S/S|U|PF]
 adequacy[7|SV|S/S/S/S|U|PF]

V-10
 envelope[2|SV|S/S/S/S|U|IH]
```

There are no duplicate obligation IDs or duplicate per-obligation threshold tags, and all 95 declared consumer-function names collect. However, only 26 of 92 obligations call their exact checker; 66 are semantically uncoupled. For V-1 through V-9, that is 26 coupled and 65 uncoupled.

### Mutation reconciliation

The separate semantic mutation catalog contains:

| Gate | Product mutations | Detector mutations | Interposer planters |
|---|---:|---:|---:|
| V-1 | 2 | 0 | 2 |
| V-2 | 4 | 0 | 4 |
| V-3 | 15 | 6 | 15 |
| V-4 | 5 | 0 | 5 |
| V-5 | 3 | 0 | 3 |
| V-6 | 1 | 0 | 1 |
| V-7 | 1 | 0 | 1 |
| V-8 | 1 | 0 | 1 |
| V-9 | 3 | 0 | 3 |
| **Total** | **35** | **6** | **35** |

The 41 mutations contain 57 `must_fail` references covering 52 distinct functions. All 52 functions collect. None was executed under its selected semantic mutation in this Reviewer-safe run.

The product-independent ledger did execute all 401 synthetic clause rows:

```text
accepted positive controls: 401
synthetic product kills:    401
blinded detectors:          401
clean negative controls:    401
unsound rows:               0
digest: 4303638206a038ba79bd26db985143ac07b721534c8a97e3c4452b697b2ef1f8
```

Those results do not establish semantic mutation sensitivity because the expected payload, violation, benign perturbation, and checker are all generated from the same clause object.

## Oracle privacy and product-bound control disposition

| Channel | Data reaching eventual product | Classification/disposition |
|---|---|---|
| Raw files | Native transcript JSONL, source trees, test results, Git history, ADRs, GitHub exports, runtime records, `.kin` events/manifests, authority answers, maintenance observations | Legitimate raw input in principle; several tests substitute shaped metadata for the claimed native transition |
| CLI arguments/cwd | Repository/store paths, session and host IDs, event types, tasks, decisions, working-set IDs, candidate IDs, destinations, approval digests, reason codes, questions, `as_of`, authority cursor, config/certificate/key/answer paths | Mostly native contract data; several exact test/case identities leak |
| Stdin | Codex/Claude hook envelopes and authority-process question JSON | Raw host/service input in principle; host envelopes are dispatched through the product rather than through installed hosts |
| Services | Company URLs, loopback Company service, closed-port and blackhole endpoints | Environment/fault state; V-6/V-8 services are not populated with the required registries or facts |
| Environment | HOME/XDG roots, PATH, locale, timezone, temp, Git identity/config, terminal settings, Company URL | Declared environment controls |
| Explicit clock control | `GUILDHALL_PROOF_CLOCK_OFFSET_SECONDS` | Fault schedule; several witnesses record only that the harness requested an offset, not the resulting native state |
| Other faults | chmod, deletion/corruption, endpoint blackhole, process kill, races, descriptors | Legitimate only when the targeted seam and postcondition are independently observed; several tests do not do so |
| Harness-held gold | V-2 opaque-ID map, V-5 expected cases, V-7 role map, V-9 labels | Explicit keys are generally stripped, but V-2 metrics never join predictions back to gold and V-9 trusts product-reported results |

Observed result selectors/test identities crossing the boundary include:

- V-4 commits the exact manifest scenario name into Git history.
- V-8 embeds the exact digest-attribution case in the repository path.
- V-9 embeds the exact expected start state in the session ID.
- Numerous fixed `acceptance-v*` session IDs disclose acceptance-run identity.

Observed work substitutes include V-1 generic lifecycle JSON, V-2 sleep-labeled crash seams, V-3 a hardcoded lifecycle-stage list, V-4 hardcoded state-change flags and unconstructed scale/replay states, V-8 hardcoded cache construction, and V-9 shaped cache files and self-reported operator/adequacy outcomes.

Oracle privacy is therefore unresolved.

## Auxiliary-corpus disposition

The pool contains five source candidates with recorded versions and matching hashes. The three generated components also match their hashes and declared actual lengths:

- 64 transformation-dictionary entries
- 96 correlation records
- 512 decoy records

The combined digest recomputes to:

```text
994cbc35abcac4c33f9a5bdf6386a3bca1d88503dc073a03c7e34282b4955677
```

The selection record remains unfilled at [pool.json:93](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/fixtures/auxiliary/pool.json:93), as required before an independent selection.

The pool cannot be selected:

- [RIGHTS.md:3](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/fixtures/auxiliary/RIGHTS.md:3) and [pool.json:81](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/fixtures/auxiliary/pool.json:81) contain only Tester assertions of authorship, rightsholder identity, and CC0 dedication.
- The source bytes contain no author/rightsholder identity, signature, publication record, or independently verifiable provenance.
- The exact CC0 grant/legal bytes are not included.
- No generator, seed, or derivation recipe explains the dictionaries, correlations, or decoys.
- The combined digest hashes only the component content hashes; it does not bind `pool.json`, `RIGHTS.md`, rights metadata, versions, ordering, or the eventual selection record.

This does not meet [threat-model.md:198](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/threat-model.md:198).

## Numbered blocking findings

### 1. Full clean-state attestation is unavailable — BLOCKING

**Path/line:** Git metadata for `.kin/.gitignore`, `.kin/config`, `.kin/index.json`, and 14 named `evidence/**` paths; source line not applicable.

**Spec:** Detector isolation and pre-combination review at [verification.md:99](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/verification.md:99).

**Counterexample:** A modified or untracked product artifact beneath an inaccessible directory would not appear in the scoped `spec tests` status.

**Remediation:** Provide a boundary-safe clean-worktree attestation over the exact commit/tree, including untracked-path enumeration, or recreate the lane from the bound tree with forbidden directories absent/inaccessible by construction and rerun the review.

### 2. V-10 reports product PASS with no product — BLOCKING

**Path/line:** [conftest.py:51](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/conftest.py:51), [census.py:100](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/_harness/census.py:100), [test_v10_protocol.py:319](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v10_protocol.py:319).

**Spec:** `NOT_RUN` cannot become proof at [verification.md:12](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/verification.md:12).

**Counterexample:** The two catalogued V-10 functions read static tables/spec bytes. Their successful selftest calls cause both the instrument and product channels to resolve `PASS`.

**Remediation:** Give each expected node an explicit origin. Selftest-only nodes may affect only the instrument channel. Keep V-10’s product/measurement channel `NOT_RUN` until the actual frozen measurement executes.

### 3. Parameterized nodes collapse into one census record — BLOCKING

**Path/line:** [census.py:210](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/_harness/census.py:210), [census.py:255](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/_harness/census.py:255).

**Spec:** Every unexecuted or skipped obligation must remain non-green under [verification.md:118](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/verification.md:118).

**Counterexample:** `function[codex]` can be skipped while `function[claude]` passes; normalization maps both to one key, and the later record overwrites the former.

**Remediation:** Preserve every collected parameter node. Resolve a catalog function only after all collected parameter instances executed and passed, with skip/deselection retained.

### 4. The 401 controls and mutations are circular synthetic artifacts — BLOCKING

**Path/line:** [catalog.py:85](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/_harness/catalog.py:85), [clauses.py:145](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/_harness/clauses.py:145), [killledger.py:124](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/_harness/killledger.py:124).

**Spec:** Independent controls and detector mutations are required at [verification.md:120](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/verification.md:120).

**Counterexample:** `conforming()` manufactures the expected green object, `violating()` changes one field, `blind=tag` skips the same clause, and the same checker judges all four. No product state or independent detector behavior is involved. “Positive control” means accepting a shaped expected artifact, not catching a planted positive.

**Remediation:** Freeze separate raw positive/negative fixtures, causal product mutations, and detector mutations. Execute them through shipping surfaces and bind each result to independently captured raw evidence.

### 5. Sixty-six obligations lack their claimed executable checker coupling — BLOCKING

**Path/line:** Coupling is claimed at [obligations.py:1](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/_harness/obligations.py:1); the catalog selftest checks only text/function existence at [test_catalog_and_kill_ledger.py:135](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_catalog_and_kill_ledger.py:135). V-4’s malformed vector is at [catalog.py:1018](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/_harness/catalog.py:1018).

**Spec:** Complete catalog/consumer reconciliation at [verification.md:120](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/verification.md:120).

**Counterexample:** A weak named test can pass and satisfy the census even though it never calls the row’s checker. `V-4.conflict` passes a string rather than a singleton tuple, causing the vector to become individual characters.

**Remediation:** Require every catalog node to emit a content-addressed evidence record for its exact OID at runtime. Reject rows with no exact consumption. Fix the V-4 vector tuple and validate vector element types.

### 6. The no-green static audit misses the patterns it claims to forbid — BLOCKING

**Path/line:** [test_no_green_paths.py:91](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_no_green_paths.py:91), [test_no_green_paths.py:159](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_no_green_paths.py:159).

**Spec:** Absence, empty iteration, refusal, and defaults cannot become green under [verification.md:118](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/verification.md:118).

**Counterexample:** The linter checks only constant defaults `0`, `""`, and `False`; it misses `[]`, `{}`, `None`, truthy defaults, and `or []`. It considers an entire module safe if one total-quantifier name appears anywhere. Independent AST inspection found zero bare returns/skips, but 24 collection defaults, 17 loops over optional collections, and 41 assertion blocks guarded by return code/output/payload conditions.

**Remediation:** Analyze every test and every product-derived branch. Reject collection/default fallbacks, optional assertion guards, and unproved loop non-emptiness unless a typed prerequisite establishes the domain first.

### 7. Every product planter rewrites the result after execution — BLOCKING

**Path/line:** [planters.py:7](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/_harness/planters.py:7), [planters.py:259](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/_harness/planters.py:259).

**Spec:** Product and detector mutations at [verification.md:123](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/verification.md:123).

**Counterexample:** The wrapper runs the real product first, then changes stdout/exit status. `echo_success` converts any refusal to `{}` and exit zero. That mutates observation, not the product’s causal behavior.

**Remediation:** Apply source, fixture, config, filesystem, authority, or fault mutations before product execution and independently witness the mutated causal state. Treat output interposition only as a supplemental detector test.

### 8. The mutation runner can record infrastructure or partial failure as a kill — BLOCKING

**Path/line:** [mutation-run.sh:39](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/mutation-run.sh:39), [mutation-run.sh:47](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/mutation-run.sh:47), [cli.py:291](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/_harness/cli.py:291).

**Spec:** Each planted mutation must be killed for its intended reason under [verification.md:120](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/verification.md:120).

**Counterexample:** Any nonzero pytest process status marks the entire mutation `KILLED`, even if only one of two nodes fails or collection/setup/environment fails. Additionally, `Guildhall.base_env()` drops `GUILDHALL_PLANTER_SPEC` and `GUILDHALL_PLANTER_REAL`; the interposer requires them at `planters.py:201–202`, so it can fail before invoking the product and still be counted as a kill.

**Remediation:** Parse per-node call-phase reports, require every named node to fail for the expected semantic reason, and classify collection/setup/environment failures as `INVALID_HARNESS`. Wire interposer configuration to the wrapper without forwarding it to the real product.

### 9. Detector mutations never demonstrate gate-level invalidation — BLOCKING

**Path/line:** [detectors.py:18](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/_harness/detectors.py:18), [test_harness_selftest.py:400](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_harness_selftest.py:400).

**Spec:** A detector mutation must escape its positive control and cause gate rejection at [verification.md:123](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/verification.md:123).

**Counterexample:** One unit selftest constructs six mutant detector objects and confirms local blindness. No runner activates each mutation, executes its affected gate, and verifies `INVALID_HARNESS`. The 401 clause-blinding mutations are unrelated to these six semantic detector mutations.

**Remediation:** Execute one isolated run per detector mutation, require the exact positive control to escape, require the affected gate’s instrument channel to become `INVALID_HARNESS`, and content-address each result.

### 10. Assertion classification conflates instrument failure with product failure — BLOCKING

**Path/line:** [conftest.py:141](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/conftest.py:141).

**Spec:** Instrument/environment inability must remain distinct from product failure under [verification.md:19](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/verification.md:19).

**Counterexample:** Every non-selftest `AssertionError` is classified `PRODUCT_FAILURE`, including assertions about Tester fixture counts, absent calibration bytes, malformed gold, or unconstructed prerequisites. For example, the V-9 operator fixture-count assertion at `test_v9_fatigue.py:464` would accuse the product if the Tester fixture were wrong.

**Remediation:** Type every prerequisite and observation by origin. Harness fixtures, gold, environment, rights, and collection failures must raise `HarnessInvalid`; only mismatches derived from independently observed product behavior may raise `ProductFailure`.

### 11. V-1’s 64-cell lifecycle matrix is neither exact nor natively executed — BLOCKING

**Path/line:** [verification.md:170](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/verification.md:170), [catalog.py:280](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/_harness/catalog.py:280), [test_v1_ingestion.py:528](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v1_ingestion.py:528).

**Counterexample:** The ratified table sums to 64 cells, while the catalog requires only 61. “Create” may rewrite identical bytes, append/edit writes an empty string, and expiry/reconciliation/revocation/end/restart often create generic JSON under `run_root`, outside the adapter’s native source. Observed state comes solely from whatever the product reports, with no held expected state per cell. All cells reuse one generic receipt mutation.

**Remediation:** Enumerate all 64 exact cells with held expected pre/post native source, observation, fact/Unknown state, and a cell-specific mutation. Drive each transition in the adapter’s actual native format and observe it through the shipping contract.

### 12. V-2 lacks independent calibration, gold-derived metrics, and real saga transitions — BLOCKING

**Path/line:** [test_v2_classification.py:250](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v2_classification.py:250), [test_v2_classification.py:311](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v2_classification.py:311), [routing_corpus.json:1601](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/fixtures/gold/routing_corpus.json:1601).

**Spec:** [verification.md:197](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/verification.md:197).

**Counterexample:** `tests/fixtures/gold/calibration-manifest.json` is absent; a typed product refusal still makes the calibration test pass. Five-run bounds are product-reported. The only recomputation uses product-reported TP/FP/FN, not raw predictions joined to Tester gold. The opaque-ID binder is correct, but mixed-message tests look up original `m###` IDs, so a conforming opaque result appears empty. Several fan-out/retry/expiry tests run in fresh function-scoped roots without seeding the saga. Crash “seams” are labels assigned according to sleep duration, with `"recovered": True` hardcoded.

**Remediation:** Add a distinct frozen calibration corpus and annotations; retain raw per-run predictions; join opaque IDs to Tester-held gold; compute all metrics in the harness; seed each saga in the same test; and instrument/witness every named transition before killing it.

### 13. V-3 does not execute total attack, surface, encoding, and lifecycle coverage — BLOCKING

**Path/line:** [test_v3_attacks.py:94](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v3_attacks.py:94), [test_v3_qualification.py:86](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v3_qualification.py:86), [test_v3_privacy.py:237](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v3_privacy.py:237).

**Spec:** [threat-model.md:110](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/threat-model.md:110), [threat-model.md:157](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/threat-model.md:157).

**Counterexample:** Attack-family coverage verifies only that `spec_ref` anchor names exist. Qualification labels in-memory payloads with surface names and calls `detector.detects(payload)` without planting through those surfaces. The positive control requires receipts for only SQLite and Git objects. The lifecycle test executes a small command subset but reports the complete `LIFECYCLE_STAGES` constant. Empty candidate loops can pass.

**Remediation:** Build the complete surface × encoding × attack-family matrix; place native bytes on each actual surface; require exact detector/location receipts; execute every lifecycle action; and run exact positive, negative, product, and detector mutations for every family.

### 14. Shared signed worlds lack the ratified external trust prerequisites — BLOCKING

**Path/line:** [worldbuilder.py:103](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/_harness/worldbuilder.py:103), [architecture.md:143](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/architecture.md:143), [architecture.md:285](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/architecture.md:285).

**Counterexample:** `SignedWorld.create()` writes only a worktree `.kin/config` hint and generates local test signers. It provides no externally configured Company root, repository certificate, signed AuthorityRegistry, or environment registration. The architecture requires all such events to remain unverified without those inputs. A conforming product should therefore refuse the intended positive fixtures, while a product that improperly trusts worktree material could satisfy them.

**Remediation:** Start and populate the Company service, configure the external root outside the worktree, issue and install a repository certificate, publish registry keys/scopes/environments, then ingest the signed state. Keep uncertified behavior in separate negative tests. This affects V-4, V-5, V-7, V-8, and V-9 fixtures.

### 15. V-4 substitutes labels or self-reports for real transitions, scale, replay, and locking — BLOCKING

**Path/line:** [test_v4_maintenance.py:86](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v4_maintenance.py:86), [test_v4_maintenance.py:571](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v4_maintenance.py:571), [test_v4_maintenance.py:686](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v4_maintenance.py:686), [test_v4_maintenance.py:726](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v4_maintenance.py:726).

**Spec:** [verification.md:331](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/verification.md:331).

**Counterexample:** Rebuild/restart perform no transition but are marked changed; conflict never plants the required authorized parent-bound resolution; manifest comparison constructs three rather than four set relations and makes classification optional; ceiling tests do not build 10× input; cascade has no 10,000-event graph or real key revocation; replay constructs no replay; the lock test requires neither a common-dir lock file nor successful serialized lineage.

**Remediation:** Construct and independently digest every pre/post state, all four manifest relations, a 10× admission corpus, a 10,000-event revocation graph, a pre-revocation replay, and a concurrent lock witness proving one common-dir critical section.

### 16. V-6 has no registered live Chief Architect round trip — BLOCKING

**Path/line:** [test_v6_authority.py:111](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v6_authority.py:111), [test_v6_authority.py:149](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v6_authority.py:149), [test_v6_authority.py:343](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v6_authority.py:343).

**Spec:** [verification.md:390](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/verification.md:390), [architecture.md:614](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/architecture.md:614).

**Counterexample:** The fixture starts Company but never registers the helper path, public key, authority ID, scope, or channel. The test directly invokes the helper subprocess, then separately ingests its output; the product never delivers a question through a registered channel. Wrong-role and contradictory tests use fresh state without the required question/prior answer. Degraded mode does not create an expired cache. The two-call ceiling uses three different question IDs without establishing a common task.

**Remediation:** Register the separate process through the live Company AuthorityRegistry, verify the exact key/channel, require a product-originated delivery receipt and invocation digest, ingest the returned answer for the same question, and build real prior-answer/cache/task state for the remaining cases.

### 17. V-8’s live service contains no authoritative fact history, cache, or revocation state — BLOCKING

**Path/line:** [test_v8_company_refs.py:84](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v8_company_refs.py:84), [test_v8_company_refs.py:100](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v8_company_refs.py:100), [test_v8_company_refs.py:580](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v8_company_refs.py:580), [test_v8_company_refs.py:895](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v8_company_refs.py:895).

**Spec:** [verification.md:438](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/verification.md:438).

**Counterexample:** Company is started but no referenced fact/version/history is inserted. The repository reference uses fabricated IDs/digests. A certificate is written but not installed or supplied to the fresh clone. Digest cases therefore have no historical/current Company versions. Expiry does not request the running Company fixture and passes when no expiry event exists. Cache truth-table rows create no revocation snapshot/cache or revocation event and hardcode `state_constructed=True`.

**Remediation:** Populate Company through its live admission API, issue and install the certificate, retain historical versions, publish real manifests, trigger Company-side expiry/revocation, materialize signed cache snapshots, and require every expected event and owner state non-optionally.

### 18. V-9 does not perform real approved install, native host invocation, or required timing/topology work — BLOCKING

**Path/line:** [test_v9_host_lifecycle.py:129](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v9_host_lifecycle.py:129), [test_v9_host_lifecycle.py:217](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v9_host_lifecycle.py:217), [test_v9_host_lifecycle.py:505](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v9_host_lifecycle.py:505), [test_v9_host_lifecycle.py:642](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v9_host_lifecycle.py:642).

**Spec:** [verification.md:476](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/verification.md:476).

**Counterexample:** Setup tests only dry-run and refusal; they never perform approved install or verify installed files. “Native events” are synthetic envelopes sent to `guildhall hooks dispatch`; the real host executable need not run because the invocation assertion is conditional. Parity passes if either host produces no canonical result. Warm state is a shaped `{"state":"verified"}` file. The session ID discloses the expected start state. The 250 ms connection requirement is asserted as `<5.0s`; full fsck uses eight events, not 10,000; CPU/RAM/filesystem are not reported; topology never creates a submodule.

**Remediation:** Exercise the host’s actual approval/install flow, inspect installed configuration, invoke Codex and Claude themselves, require nonempty invocation records, use opaque session IDs, build real certified cache/event state, enforce 250 ms, record machine metadata, run the 10,000-event ceiling, and include a real submodule.

### 19. V-9 permits zero operator work and trusts product-reported adequacy — BLOCKING

**Path/line:** [test_v9_fatigue.py:384](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v9_fatigue.py:384), [test_v9_fatigue.py:457](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v9_fatigue.py:457), [test_v9_fatigue.py:515](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v9_fatigue.py:515).

**Spec:** [verification.md:505](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/verification.md:505).

**Counterexample:** The 20-item blinded file is never sent to an operator or product; absence of `operator_exercise` makes the test pass. The adequacy test sends the full 100-record file five times, makes no decisions, and trusts product-reported slots/correct admissions; missing displacement is accepted as clean. The interleave “barrier” records timestamps only after calls return, rendered zero passes, and crash handling does not establish that reservation occurred.

**Remediation:** Run a real blinded operator driver, independently time and score all 20 decisions, send distinct per-window raw arrivals, join output IDs to held gold, compute adequacy in the harness, and instrument an exact check/render barrier plus observed reservation state.

### 20. Product-bound control inspection is incomplete and case identity leaks — BLOCKING

**Path/line:** [test_control_policy.py:42](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_control_policy.py:42), [test_v4_maintenance.py:179](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v4_maintenance.py:179), [test_v8_company_refs.py:597](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v8_company_refs.py:597), [test_v9_host_lifecycle.py:515](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v9_host_lifecycle.py:515).

**Spec:** Oracle privacy review at [verification.md:128](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/verification.md:128).

**Counterexample:** The policy recognizes only literal keys inside literal `env={...}` arguments. It does not inspect variable environment maps, constructor `extra_env`, argv, cwd/path names, stdin, prompts, fixture/service payloads, or committed Git history. The V-4 scenario, V-8 digest case, and V-9 expected start state cross those unchecked channels.

**Remediation:** Freeze a complete dataflow inventory for every child-process field and service request. Use randomized opaque paths/session IDs with a harness-held mapping, reject semantic scenario names anywhere product-readable, and verify product-bound bytes against a closed schema before every invocation.

### 21. Auxiliary-corpus rights, provenance, freeze, and selection are unresolved — BLOCKING

**Path/line:** [RIGHTS.md:3](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/fixtures/auxiliary/RIGHTS.md:3), [pool.json:81](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/fixtures/auxiliary/pool.json:81), [test_v3_qualification.py:626](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/acceptance/test_v3_qualification.py:626).

**Spec:** [threat-model.md:198](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/threat-model.md:198).

**Counterexample:** A Tester-authored statement saying the Tester owns and dedicates the prose cannot independently prove authorship or authority to grant CC0. The combined digest omits the rights/selection metadata, generated components have no reproducible derivation, and the auxiliary test explicitly requires the selection to remain unfilled rather than verifying a completed Reviewer record.

**Remediation:** Include verifiable named rightsholder provenance and an exact rights grant, bind the legal/provenance bytes and complete pool manifest into the digest, provide generation algorithms/seeds, then have a fresh implementation-blind Reviewer execute and sign a deterministic selection record.

### 22. The Reviewer environment did not enforce pytest timeouts — BLOCKING

**Path/line:** [pytest.ini:42](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/pytest.ini:42), [requirements.txt:9](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/tests/requirements.txt:9).

**Spec:** Every external/process call must have a timeout under [verification.md:780](/Users/jmcentire/Code/guildhall-proof-lanes-ac8a13d1/detector-reviewer-2/spec/verification.md:780).

**Counterexample:** `pytest_timeout` is unavailable. Pytest warned that `timeout`, `timeout_method`, and `cache_dir` were unknown, yet the supposedly strict Reviewer-safe run exited zero. Global test timeouts were therefore not active.

**Remediation:** Run with a pre-provisioned, network-independent interpreter satisfying `tests/requirements.txt`, and make the Reviewer-safe entrypoint fail closed if the timeout plugin or any declared strict configuration option is unavailable.

## Explicit limitations

- No product was present or executed; no product behavior or product verdict is reported.
- No semantic mutation kill was executed against a product.
- Full repository cleanliness remains unverified because the forbidden `.kin/**` and `evidence/**` paths were inaccessible even to Git status.
- The auxiliary corpus was not selected because its rights/provenance basis could not be independently established.
- Supporting NONFUNCTIONAL, EVIDENCE, VERDICT, and INSTRUMENT census groups have zero expected nodes and remained `NOT_RUN`.
- The passing 108-test process establishes only that the current product-independent assertions accepted their own inputs; it does not clear the instrument.

DETECTOR_REVIEW_STATUS: BLOCKED 22
