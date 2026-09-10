# Kinbase Factory Detector Reviewer report — dispatch 001

**Disposition:** blocked by **17 unresolved blocking findings**. This is an acceptance-instrument review only. It is not a product verdict and does not claim the Kinbase concept proven or disproven.

## 1. Binding and information-boundary attestation

| Binding | Expected | Observed | Result |
|---|---|---|---|
| Ratified manifest SHA-256 | `ac8a13d184397fef574e173b81466ff43e6b3f91f89804c7ee797cc404a622db` | Same | Match |
| Tester repair commit | `244184e631695cc331d64667bd20cfae7f286526` | Same | Match |
| Tester repair tree | `893a6ba3bbc464762d479aa13305d3761adc07b4` | Same | Match |
| Index against `HEAD` | Clean required | No staged differences | Match |
| `spec/**`, `tests/**` tracked worktree | Clean required | No tracked differences | Match |
| `spec/**`, `tests/**` untracked files | None required | None found | Match |
| Full repository worktree | Clean required | Could not positively attest: `git status` emitted permission warnings for excluded `.kin/**` and `evidence/**` paths | **Unresolved** |

I inspected only:

- `spec/**`;
- `tests/**`; and
- Git object/index/worktree metadata needed for binding and cleanliness checks.

I did not inspect `.kin/**`, `evidence/**`, any parent or sibling repository, product implementation, Coder or Validator material, prior review results, Kindex/global memory, user configuration, or web content. I did not source `~/.profile`, invoke a skill stored outside the allowed paths, spawn another agent, edit files, or create artifacts.

The normal acceptance command was not executed because its bootstrap would violate this review boundary:

- [`tests/conftest.py:87–99`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/conftest.py:87) always calls `verify_manifest()`.
- [`tests/acceptance/_harness/requirements.py:201–227`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/_harness/requirements.py:201) reads the excluded evidence and receipt paths named by [`spec/ratification-manifest.json:39–46`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/spec/ratification-manifest.json:39).
- [`tests/run-acceptance.sh:34–42`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/run-acceptance.sh:34) may also create `tests/.venv` and install dependencies from the network.

## 2. Methods and commands run

Read-only binding checks:

```text
git status --porcelain=v1 --untracked-files=all
git rev-parse HEAD
git rev-parse 'HEAD^{tree}'
git ls-tree -r --name-only HEAD
shasum -a 256 spec/ratification-manifest.json
git diff --cached --name-status --
git diff-files --name-status -- spec tests
git ls-files --others --exclude-standard -- spec tests
git ls-tree -r --name-only HEAD -- tests/fixtures tests/acceptance
git cat-file -e HEAD:tests/fixtures/gold/calibration-manifest.json
```

Static inspection used:

```text
rg -n ... spec tests
nl -ba <allowed-file> | sed -n <line-ranges>
```

Read-only Python AST/JSON scripts were used to:

- parse all 40 Python files and 7 JSON files under the allowed surface;
- enumerate test functions, markers, bare returns, default-valued `.get()` calls, and tautological assertions;
- enumerate all environment controls;
- parse all 41 mutation declarations;
- resolve all 57 `must_fail` references to 52 distinct test functions.

Static results:

- 41 unique mutation IDs;
- 35 product mutations: 25 `validator_source_patch`, 10 `fixture`;
- 6 detector mutations;
- all named `must_fail` functions exist syntactically;
- no executable mutation-kill ledger or runner-side kill enforcement exists;
- the referenced calibration manifest is absent from `HEAD`.

No pytest collection or test execution was performed.

## 3. Path legend

The following abbreviations are used in dense tables:

| Abbreviation | Exact path |
|---|---|
| `V` | `spec/verification.md` |
| `TM` | `spec/threat-model.md` |
| `C` | `tests/conftest.py` |
| `REQ` | `tests/acceptance/_harness/requirements.py` |
| `CLI` | `tests/acceptance/_harness/cli.py` |
| `MUT` | `tests/acceptance/_harness/mutations.py` |
| `DET` | `tests/acceptance/_harness/detectors.py` |
| `SCAN` | `tests/acceptance/_harness/scanners.py` |
| `HS` | `tests/acceptance/test_harness_selftest.py` |
| `BR` | `tests/acceptance/test_backreference_integrity.py` |
| `T1`–`T8` | Corresponding `tests/acceptance/test_vN_*.py` |
| `T9F` | `tests/acceptance/test_v9_fatigue.py` |
| `T9H` | `tests/acceptance/test_v9_host_lifecycle.py` |
| `T10` | `tests/acceptance/test_v10_protocol.py` |
| `NF` | `tests/acceptance/test_nonfunctional.py` |
| `RG` | `tests/fixtures/gold/routing_corpus.json` |
| `MW` | `tests/fixtures/gold/maintenance_workload.json` |
| `AUX` | `tests/fixtures/policies/auxiliary-corpus-request.json` |

## 4. Green-result provenance summary

| Gate | Raw state that should establish the result | Actual asserted source | Independence disposition |
|---|---|---|---|
| V-1 | Native sources and executed lifecycle transitions | Some native fixtures; lifecycle largely comes from product `status` JSON | Partial; lifecycle and idempotence can self-attest or default green |
| V-2 | Hidden raw messages, separately held gold, raw predictions | Product receives JSONL records containing their own `gold_atoms`, `mixed`, and strata, then reports metrics | Oracle leak and self-attestation |
| V-3 | Executed lifecycle plus exhaustive surface reads and independent reconstruction | Some tester-owned byte scans; many product status claims, refusals, empty candidate lists, and an absent auxiliary corpus | Partial and non-total |
| V-4 | Mutated Git/event/manifests and real large corpora | Several real Git fixtures, but major cases use scenario/count environment selectors | Partial; work substitution |
| V-5 | Nine independently planted event histories | Empty initialized repository plus `KINBASE_ACCEPTANCE_TEMPORAL_CASE` | Direct result selector |
| V-6 | Registered live authority and independently delivered signed reply | Real service and signing helper exist, but the authority is never registered by the test | Incoherent setup; later selectors substitute state |
| V-7 | Candidate records ingested through the shipping corpus surface | Empty repository plus `KINBASE_ACCEPTANCE_V7_FIXTURE=1` | Direct work substitute |
| V-8 | Signed Company facts, certificates, live service, cache/revocation changes | Mostly unsigned/fake local fixture plus semantic environment selectors; no Company server fixture | Partial and non-independent |
| V-9 | Actual installed hooks, host invocations, real state transitions, operator actions, raw maintenance observations | Host presence is checked, but invocation witness is optional; state and workloads are commonly selected by environment | Partial; refusals and zero work often green |

## 5. V-1 through V-9 obligation matrix

The governing catalog rule is [`spec/verification.md:118–133`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/spec/verification.md:118): each gate must freeze its threshold, positive control, negative control, and detector mutation, with unresolved findings blocking combination.

| Gate | Ratified obligations and exact detector nodes | Positive and negative controls | Product mutations | Detector mutation | Fail-closed path and disposition |
|---|---|---|---|---|---|
| **V-1** | Adapters/native formats `T1:175,209`; ≥7-source build and manifest `T1:275`; idempotence `T1:324`; change/delete/reject/revert `T1:370`; all lifecycle cells `T1:458`; support retirement `T1:521`; three-cursor ordering/skew `T1:607`; misextraction/never-true `T1:669,709`; origin trust `T1:751`. Authority: `V:157–195`. | No V-1 test is formally marked or catalogued as a positive or negative control. Closest positive is `T1:175`; closest negatives are `T1:669,709`. | `v1.adapter_count_without_observations`; `v1.approver_mints_never_true`. | **Missing.** Both catalog entries mutate product/fixture behavior, not the detector. | Ordinary failures become `PRODUCT_FAILURE`; there is no missed-control → `INVALID_HARNESS` path. `T1:458` asks the product to describe all cells instead of executing them. **Partial/non-independent.** |
| **V-2** | Corpus floors `T2:129`; annotator agreement `T2:160`; five runs/thresholds `T2:213`; excluded calibration `T2:274`; atomization/metrics/low confidence `T2:315,357,401`; independent candidates `T2:442`; saga/retry/expiry/quarantine `T2:502,572,626,673`; crash recovery `T2:717`; no cross-store/accept-all `T2:772,808`. Authority: `V:197–235`. | No formal V-2 controls. Corpus and low-confidence tests are only informal candidates. | Four V-2 mutations at `MUT:117–164`. | **Missing.** | Gold is supplied to the SUT; metrics are product-reported; calibration input is absent; saga tests begin from fresh function-scoped roots without creating candidates. **Missing/non-independent.** |
| **V-3** | Lifecycle scan `T3P:233,276`; capabilities/sandbox/fd/process artifacts `T3P:333,381,436,480`; taint/paraphrase `T3P:548,592`; processor/egress `T3P:663,692`; reporting/reconstructor `T3P:730,772,808`; qualification and residual risks `T3Q:82–657`; 19 attack families, below. Authority: `V:237–329`, `TM:110–171`. | Formal positives: `HS:247,300,483`, `T3P:145`, `T3Q:82`. Formal negatives: `HS:275`, `T3Q:172`. They are not exact per-family controls. `T3P:145` is gate-marked, not `selftest`, so a missed detector control is classified as `PRODUCT_FAILURE`, contrary to the required `INVALID_HARNESS`. | Fifteen V-3 product mutations at `MUT:165–301`. | Six generic detector mutations at `MUT:453–501`, but not one exact mutation per attack family; five named sensitivity nodes pass under their selected mutant. | `SCAN:60–64` can silently omit unreadable directories; absent roots yield empty scans; numerous empty/refusal paths pass. Auxiliary corpus is absent and the reconstructor is only product-reported. **Missing/partial.** |
| **V-4** | Incremental cycle `T4:95`; incompatible heads `T4:142`; manifest cases `T4:227`; normalization `T4:286`; determinism/as-of `T4:354,395`; 10× ceiling `T4:439`; dense revocation `T4:502`; replay `T4:561`; linked lock `T4:603`; pinned-Kindex compatibility `T4:662`; attributes `T4:714`. Authority: `V:331–368`. | No formal V-4 controls. Real Git cases are mixed with result selectors and optional assertions. | Five V-4 mutations at `MUT:302–351`. | **Missing.** | Scenario/count controls replace state; `T4:377` is an unconditional `... or True`; several refusal branches return green; common-dir lock candidates are computed but never asserted. **Partial/non-independent.** |
| **V-5** | Nine frozen cases `T5:206`; nine counterfactuals `T5:242`; newest/authority/repetition cases `T5:281,307,331,365`; runtime and unregistered environment `T5:399,433`. Authority: `V:370–388`. | No formal V-5 controls. The table is both the test oracle and, via case ID, an input to the SUT. | Three V-5 mutations at `MUT:352–380`. | **Missing.** | No event histories establish any case. Holding repository state fixed and changing `KINBASE_ACCEPTANCE_TEMPORAL_CASE` selects semantic output. **Non-independent.** |
| **V-6** | Service/registry `T6:146`; ambiguity/question/delivery `T6:205`; wrong role `T6:280`; signed separate-process answer and material change `T6:334`; conflicting answer `T6:447`; unavailable/cache `T6:510`; frozen service call ceiling `T6:566`; registry privacy `T6:615`. Authority: `V:390–419`. | No formal V-6 controls. Closest positive is `T6:334`; closest negatives are `T6:280,510`. | `v6.synthesize_answer_from_model_prior`. | **Missing.** | The test creates a key-owning helper but never registers its key/channel. Delivery is asserted only if the call succeeds. Cache and frozen service states are environment substitutes. **Missing/incoherent.** |
| **V-7** | Candidate roles `T7:131`; working-set sensitivity `T7:163`; duplicate/invariant `T7:198`; recomputation `T7:234`; complementarity `T7:275`; distortion `T7:325`; stale fact `T7:370`; VOI stop `T7:399`; query log `T7:454`; claim scope `T7:499`. Authority: `V:421–436`. | No formal V-7 controls. | `v7.independent_scalar_topk`. | **Missing.** | All semantic candidates and traces come from the SUT after `KINBASE_ACCEPTANCE_V7_FIXTURE=1`; no raw candidate set is ingested. **Work substitute/oracle leak.** |
| **V-8** | Fresh reference/no-copy `T8:135`; reference fields `T8:211`; stricter class `T8:260`; exception/relaxation `T8:321,398`; digest handling `T8:464,519`; uncertified/fork `T8:566`; identity `T8:633`; publication `T8:696`; expiry `T8:740`; cache table `T8:787`; counts-only host `T8:851`. Authority: `V:438–474`. | No formal V-8 controls. Closest positive is fresh-clone/relaxation; closest negatives are maintainer minting, uncertified clone, and digest mismatch. | `v8.codebase_authorizes_exception_to`. | **Missing.** | The fixture contains an unsigned fake-path reference, does not start Company, and uses semantic result selectors. Success, refusal, missing events, and missing projection can all pass in multiple nodes. **Partial/non-independent.** |
| **V-9** | Hook setup `T9H:114`; native events `T9H:190`; host parity `T9H:260`; capture/flush `T9H:325,406`; four-state timing `T9H:462`; blackhole/connect/fsck `T9H:519,575`; topology `T9H:642`; soak `T9H:713`; runbook `T9H:788`; flood/reset/reissue/interleave `T9F:87,165,245,343`; operator `T9F:421`; maintenance `T9F:483`; reporting `T9F:553`. Authority: `V:476–525`. | No formal V-9 controls. Closest positives are native events/soak/maintenance; negatives include denied install/blackhole/flood. | Three V-9 mutations at `MUT:419–452`. | **Missing.** | Denied install may succeed; host invocation witness is conditional; parity is conditional; timing states and event counts are substitutes; zero prompts passes; operator execution is optional; the maintenance gold file is supplied to the SUT. **Partial/non-independent.** |

### V-3 frozen attack-family matrix

`TM:157–162` requires an exact positive control, negative control, and detector mutation for every family, not merely an anchor bearing its family name.

| Family | Tester probe(s) | Control/mutation disposition |
|---:|---|---|
| 1 | `T3P:145,233,276`; `T3Q:82` | Randomized “surface” is only a label while transformed bytes are passed directly to `detector.detects`; no exact PC/NC/mutation per destination and surface. |
| 2 | `HS:247,300`; `T3Q:82,172` | Transformation decoder tests exist, but the V-3 negative marker checks family enumeration, not a per-family negative surface traversal. |
| 3 | `T3A:269,335` | Approval/path probes depend on missing candidates or accept refusal; no exact PC/NC and no full expiry/preview/symlink schedule. |
| 4 | `T3A:514,589`; `T3Q:307,361` | Some signed fixtures exist; cache/revocation tests can return without establishing a prior trusted fact. |
| 5 | `T3A:159` | Projection refusal returns green at `T3A:218–219`; action trace need not be observed. |
| 6 | `T3Q:207,264` | History fixture is substantive, but sparse-checkout refusal is only checked if it happens and unrelated failures pass. |
| 7 | `T3A:675`; `T2:717` | Parser probes exist; crash schedule uses a nonexistent candidate and default-zero recovery counters. Backup/restore and all boundary cells are not total. |
| 8 | `T3P:276,480`; `T3Q:461` | Only selected process/filesystem artifacts are scanned; missing processes/surfaces are not a failure. |
| 9 | `T3P:381`; `T3Q:541` | Sandbox status is product self-attestation; same-UID test never supplies the stolen bytes to the promotion attempt. |
| 10 | `T3P:808`; `T3Q:598` | No eligible auxiliary corpus exists; reconstruction is read from product `status`, not an independent reconstructor. |
| 11 | `T3A:780,825,909,958` | Useful malicious inputs exist, but no paired valid exact-scope negative control is catalogued for each parser/authorization detector. |
| 12 | `T3A:335,636,675` | Signature/parser cases exist, but exact per-vector controls and detector mutations are absent. |
| 13 | `T3A:846,878` | Token denial probes exist; no exact valid-scope control or total rotation/replay/anomaly reconciliation. |
| 14 | `T3P:480` | Inspects one service process and one projector error record, not every shared writer/projector; empty fields are accepted. |
| 15 | `T3A:406`; `T2:717`; `T9F:343` | Zero successful approvals/prompts passes the cardinality bounds; crashes and interleaving are not independently witnessed. |
| 16 | `T3A:1186` | Config refusals are tested, but no private-input egress canary proves refusal occurred before delivery. |
| 17 | `T3A:1009` | Observe/list/show refusal or an empty candidate list makes every payload case green. |
| 18 | `T3A:1093` | `statement=(injection + " ")[:max(64, per_fact)]` never pads the short string, so the claimed 128-KiB saturation is not constructed; projection refusal also returns green. |
| 19 | `T3A:1275`; `T3P:436` | Path replacement occurs between separate CLI processes, not between check and exec. The open descriptor is not inherited because `CLI:372–379` supplies no `pass_fds`. |

## 6. Complete out-of-band control inventory

Classification values are exactly the requested classes. In the final column:

- `H` means harness-only;
- `P/U` means physically passed into the product process by `CLI:345–375`, but no ratified shipping surface or recognition/effect is established;
- `P/C` means an ordinary configuration/fault input whose external effect is at least partly witnessed.

Every `KINBASE_ACCEPTANCE_*` name also discloses acceptance-run identity to the SUT even where the “answer bits” column says the value itself contains no semantic answer.

### `KINBASE_ACCEPTANCE_*` controls

| Control and exact occurrence | Gate / consuming assertion | Classification | Answer bits? | Substitutes work? | Independent occurrence/effect witness | Shipping reach |
|---|---|---|---:|---:|---|---|
| `ADMIT_TAG` — `T4:621` | V-4 linked-worktree admission | `fault_schedule` | No | No | Concurrent calls occur, but tag effect and common lock acquisition are not proven | P/U |
| `CACHE_EXPIRED` — `T6:524` | V-6 degraded policy | `work_substitute` | Yes: expired state | Yes | No real cache is created then expired | P/U |
| `CERTIFICATE` — `T8:603` | V-8 attacker certificate | `raw_input` | No | No | File exists; no receipt proves it was consumed | P/U |
| `COMPANY_CRITICALITY` — `T8:279` | V-8 effective class | `result_selector` | Yes | Yes | No Company fact carries the value | P/U |
| `COMPANY_PROSE_CANARY` — `T8:168` | V-8 no-copy scan | `work_substitute` | Protected bytes, not expected result | Yes | Git absence is scanned; Company delivery is not witnessed | P/U |
| `CRASH_AT` — `T2:739`, `T9F:394` | V-2 transitions; V-9 reservation | `fault_schedule` | Schedule only | No | No crash/transition receipt; invalid candidate or optional budget checks | P/U |
| `CYCLE_STAGE` — `T4:110` | V-4 incremental cycle | `work_substitute` | Scenario identity | Yes | Repository/event state is unchanged across named stages | P/U |
| `DEPENDENCE_CLASS` — `T8:810` | V-8 cache table | `result_selector` | Yes | Yes | No dependence fact is planted | P/U |
| `DIGEST_ALG_VERSION` — `T8:477` | V-8 unsupported digest | `result_selector` | Yes | Yes | Fixture still contains `sha256/1`; success is accepted | P/U |
| `DIGEST_SCENARIO` — `T8:532` | V-8 attribution table | `result_selector` | Yes | Yes | No historical Company query is performed | P/U |
| `DISCOVERY_HINT` — `T8:639,644` | V-8 stable identity | `environment` | No | No | Equality is checked only if both UUIDs are reported | P/U |
| `EVENT_COUNT_OVERRIDE` — `T8:711` | V-8 manifest regression | `work_substitute` | Regression bit | Yes | No lower-count manifest is independently inspected; success passes | P/U |
| `FACT_VALIDITY` — `T8:809` | V-8 cache table | `result_selector` | Yes | Yes | No fact clock/state is planted | P/U |
| `FORCE_CEILING` — `NF:466` | Projection ceiling | `work_substitute` | Limit condition | Yes | Assertion runs only if product self-reports `ceiling_stop` | P/U |
| `FROZEN_ANSWER_SERVICE` — `T6:578` | V-6 two-call service | `work_substitute` | Service mode | Yes | No external frozen answer service exists | P/U |
| `HINT_RESOLVES_TO_UUID` — `T8:660` | V-8 repinning | `result_selector` | Yes | Yes | No actual discovery endpoint resolves the UUID | P/U |
| `HOST_APPROVAL` — `T9H:146` | V-9 unapproved install | `result_selector` | Yes: denied | Yes | No native approval interaction; install success is accepted | P/U |
| `HOST_INSTANCE` — `T9F:103,354,393` | V-9 budget shard | `work_substitute` | No | Yes | No signed native host identity; budget record is optional | P/U |
| `INHERITED_FD` — `T3P:452` | V-3 descriptor denial | `work_substitute` | No | Yes | FD is opened, but is not inherited by `subprocess.run` | P/U |
| `INJECT_OPERATOR_PROSE` — `T10:430` | V-10 frozen-run denial | `raw_input` | No | No | Value is passed; consumption is not independently witnessed | P/U |
| `INTERLEAVE_AT` — `T9F:355` | V-9 slot/render race | `fault_schedule` | Schedule only | No | Threads run, but there is no barrier or trace proving the interleaving occurred | P/U |
| `LAUNCH_LABEL` — `T10:296` | V-10 census denial | `raw_input` | No | No | Three values are passed; only refusal is observed | P/U |
| `LOCAL_DEPENDENCE` — `T8:280` | V-8 effective class | `result_selector` | Yes | Yes | No maintainer-owned fact carries the value | P/U |
| `MAINTENANCE_WORKLOAD` — `T9F:504` | V-9 adequacy | `work_substitute` | **Yes: full gold labels** | Yes | File existence/count checked, not ingestion or independent decisions | P/U |
| `MANIFEST_SCENARIO` — `T4:237` | V-4 lag/incomplete/expiry | `result_selector` | Yes | Yes | No matching manifest histories are constructed | P/U |
| `RAISE_BUDGET` — `T10:740` | V-10 immutable budget | `raw_input` | No | No | Requested value and refusal observed | P/U |
| `REISSUE_TAG` — `T9F:254` | V-9 reissue race | `work_substitute` | No | Yes | No candidate or changed source bytes; zero issued results passes | P/U |
| `REPLAY_PRE_REVOCATION` — `T4:569` | V-4 replay | `work_substitute` | Yes | Yes | No revocation then replay is constructed; empty replay passes | P/U |
| `REQUEST_PROMPT` — `T9F:102,356` | V-9 flood/interleave | `work_substitute` | Destination bit | Yes | Product refusal is counted as suppression; no real prompt eligibility | P/U |
| `REVOCATION_SNAPSHOT` — `T8:808` | V-8 cache table | `result_selector` | Yes | Yes | No signed snapshot is changed | P/U |
| `REVOKE_DENSE_KEY` — `T4:520` | V-4 cascade | `work_substitute` | Revocation bit | Yes | No key/facts/graph are created and revoked | P/U |
| `SIMULATED_WINDOWS` — `T9F:505` | V-9 adequacy timing | `fault_schedule` | Timing only | Yes, combined with gold workload | No independently advanced clock or per-window execution trace | P/U |
| `SKIP_CENSUS` — `T10:297` | V-10 pre-launch refusal | `fault_schedule` | No | Yes | Missing census is not independently enumerated | P/U |
| `SOURCE_TRUST` — `T9F:315` | V-9 reissue denial | `result_selector` | Yes: untrusted | Yes | A branch exists, but product trust derivation is replaced by the value | P/U |
| `START_STATE` — `T9H:477,594` | V-9 four-state timing/cold projection | `work_substitute` | Timing-state bit | Yes | Wall time is measured, but cache/fsck state is not created or verified | P/U |
| `SYNTHETIC_EVENT_COUNT` — `T4:450,466,519`; `T9H:608` | V-4 overload/cascade; V-9 fsck | `work_substitute` | Load bit | Yes | No 10,000/100,000-event corpus exists | P/U |
| `TASK_ID` — `T6:579` | V-6 call ceiling | `raw_input` | No | Partial | Three CLI calls share a value, but no external service/task record exists | P/U |
| `TASK_PRINCIPAL` — `T10:527` | V-10 least privilege | `raw_input` | Principal class | Yes: replaces authenticated identity | Refusal only; no signed principal binding | P/U |
| `TEMPORAL_CASE` — `T5:174` | Every V-5 semantic assertion | `result_selector` | **Yes** | **Yes** | Raw repository state is fixed and empty | P/U |
| `V7_FIXTURE` — `T7:105` | Every V-7 mechanics assertion | `work_substitute` | **Yes** | **Yes** | No candidate records traverse ingestion | P/U |

### Other named or analogous controls

| Control and exact occurrence | Consumer | Classification | Answer/work disposition | Witness and reach |
|---|---|---|---|---|
| `KINBASE_ACCEPT_DETECTOR_MUTATION` — `DET:37,50–59`; `C:118,227` | Detector selection/reporting | `result_selector` | Conveys mutant identity and changes detector behavior | H; selection recorded, kill not enforced |
| `KINBASE_ACCEPT_MUTATION` — `MUT:37,58–66`; `C:111,226` | Product-mutation selector | `result_selector` | Conveys expected mutation ID but does not apply it | H; header/output only |
| `KINBASE_ACCEPT_GATE_VECTOR` — `C:217–235` | Output path | `environment` | No answer bits or work substitution | H; artifact sink |
| `KINBASE_BIN` — `CLI:255–278` | SUT executable | `environment` | No answer bits | H→shipping entrypoint; existence/exit would witness execution |
| `KINBASE_SPEC_ROOT` — `REQ:118–137` | Authority root | `environment` | No answer bits | H; manifest digest checked, but verification crosses excluded evidence |
| `KINBASE_TESTER_VAULT` — `tests/acceptance/_harness/vault.py:44,111–135` | Canary custody | `environment` | No answer bits | H; location/mode/worktree checks are substantive |
| `KINBASE_HOST_CODEX`, `KINBASE_HOST_CLAUDE` — `tests/acceptance/_harness/hosts.py:91–114` | Host executable selection | `environment` | No semantic answer bits | H/P; `--version` is read, but actual hook invocation is not mandatory |
| `KINBASE_CLASSIFIER_PROVIDER` — `T3P:673` | V-3 egress denial | `environment` | Names the forbidden provider | P/U; no real private event or outbound attempt is witnessed |
| `KINBASE_COMPANY_URL` — occurrences listed at `T2:536,685`, `T3Q:330`, `T6:153–621`, `T8:167–807`, `T9H:539,582`, `NF:245` | Live/dead/blackholed Company endpoint | `environment` | No answer bits | P/C where a server/blackhole is independently started; P/U elsewhere |
| `KINBASE_PROOF_CLOCK_OFFSET_SECONDS` — `T2:634`, `T8:747`, `NF:510` | Expiry schedule | `fault_schedule` | Timing only | P/U; no independently witnessed clock receipt or actual prerequisite state |
| `ACCEPT_PYTHON` — `tests/run-acceptance.sh:22,32` | Test interpreter | `environment` | No answer bits | H; version/fingerprint not frozen |
| `ACCEPT_NO_VENV` — `tests/run-acceptance.sh:23,34` | Dependency environment | `environment` | No answer bits | H; changes dependency source |
| Arbitrary pytest arguments/`-m` — `tests/run-acceptance.sh:49`, `tests/README.md:21–27` | Collection selector | `result_selector` | Selects which gates execute | H; unselected gates nevertheless remain preinitialized `PASS` |
| `PYTHONHASHSEED` — `tests/run-acceptance.sh:47`, `CLI:301` | Determinism | `environment` | No answer bits | H/P; value passed, effect not separately attested |
| `PATH` — `CLI:295`, `T9H:204`, `tests/acceptance/_harness/gitfix.py:80` | Executable resolution/host recorder | `environment` | No answer bits | P/C only if invocation log is required; current assertion is conditional |
| `HOME`, `XDG_*`, `GIT_CONFIG_*`, Git identity, `TERM`, `NO_COLOR` — `CLI:329–346` | Isolation | `environment` | No answer bits or work substitute | P/C; temporary roots establish much of the environment |
| `LANG`, `LC_ALL`, `TZ`, `TMPDIR`, `SYSTEMROOT` — `CLI:294–302` | Ambient execution environment | `environment` | No answer bits | P/U; allowed through without a complete environment fingerprint |
| Fixed Git author/committer dates — `tests/acceptance/_harness/gitfix.py:83–88` | Git fixtures | `environment` | No answer bits | H; deterministic fixture metadata |

## 7. Catalog mutation and `must_fail` reconciliation

The catalog has 41 unique entries and 57 `must_fail` references to 52 distinct functions. Every named function exists statically. That establishes naming only, not sensitivity.

Status codes:

- `P0`: product source mutation is declarative; no patch or executable planter exists.
- `F0`: fixture negative case exists, but selecting the catalog ID neither changes the fixture nor inverts/enforces result polarity.
- `D0`: detector mutant exists, but its named `must_fail` test explicitly constructs the mutant and asserts that it is blind, so the test passes.
- `D?`: structurally likely to fail under the selected mutant, but was not executable within this review and no runner checks the required kill.

| Catalog entry / method | Exact `must_fail` nodes | Reconciliation |
|---|---|---|
| `v1.adapter_count_without_observations` (`MUT:92`, source patch) | `test_v1_ingestion.py::test_adapter_receipt_reports_observations_not_counts` (`T1:209`); `...::test_end_to_end_build_uses_at_least_seven_source_classes` (`T1:275`) | P0 |
| `v1.approver_mints_never_true` (`MUT:104`, fixture) | `...::test_misextraction_notice_is_approver_owned_and_withholds_only` (`T1:669`); `...::test_never_true_requires_subject_matter_authority` (`T1:709`) | F0 |
| `v2.whole_message_single_label` (`MUT:117`, source patch) | `...::test_mixed_messages_atomise_rather_than_take_one_label` (`T2:315`); `...::test_exact_match_atomization_and_per_label_metrics` (`T2:357`) | P0 |
| `v2.shared_by_default_low_confidence` (`MUT:129`, source patch) | `...::test_low_confidence_shared_label_demotes_to_none_or_unknown` (`T2:401`) | P0 |
| `v2.common_fanout_transaction` (`MUT:140`, source patch) | `...::test_partial_fanout_failure_does_not_roll_back_committed_destination` (`T2:502`); `...::test_no_cross_store_transaction_exists` (`T2:772`) | P0 |
| `v2.remove_nonce_uniqueness_recovery` (`MUT:152`, source patch) | `...::test_kill_at_every_transition_then_concurrent_retry` (`T2:717`); `...::test_retry_returns_original_receipt_without_duplication` (`T2:572`) | P0 |
| `v3.transcript_digest_in_receipt` (`MUT:165`, source patch) | `test_v3_privacy.py::test_no_transcript_digest_or_path_on_any_shared_surface` (`T3P:276`) | P0 |
| `v3.mount_personal_in_coding_query` (`MUT:173`, source patch) | `...::test_shared_writer_has_no_personal_capability` (`T3P:333`); `...::test_sandbox_denies_personal_root_for_shared_processes` (`T3P:381`) | P0 |
| `v3.trust_kin_trust_json` (`MUT:184`, fixture) | `test_v3_attacks.py::test_worktree_cannot_mint_trust_root_or_certificate` (`T3A:514`) | F0 |
| `v3.clear_taint_after_deidentification` (`MUT:192`, source patch) | `T3P::test_hard_blocking_taint_is_never_cleared_by_deidentification` (`:548`); `...::test_paraphrase_only_output_stays_private_by_taint_policy` (`:592`) | P0 |
| `v3.reread_candidate_path_after_approval` (`MUT:203`, source patch) | `T3A::test_approved_bytes_are_the_exact_buffer_rehashed_at_commit` (`:335`) | P0 |
| `v3.worktree_only_key_admission` (`MUT:212`, fixture) | `T3A::test_unauthorized_and_worktree_only_signers_are_refused` (`:589`) | F0 |
| `v3.signature_reuse_across_message_types` (`MUT:220`, fixture) | `T3A::test_cross_message_type_signature_reuse_is_refused` (`:636`) | F0 |
| `v3.verify_one_parse_apply_another` (`MUT:229`, fixture) | `T3A::test_parser_differential_duplicate_and_reordered_keys_refuse` (`:675`) | F0 |
| `v3.wildcard_authority_scope` (`MUT:237`, fixture) | `T3A::test_facts_token_scope_sets_require_exact_canonical_membership` (`:780`); `...::test_empty_scope_set_grants_nothing` (`:825`) | F0 |
| `v3.sql_interpolation` (`MUT:249`, fixture) | `T3A::test_sql_like_glob_fts_and_nul_metacharacters_do_not_widen_matching` (`:909`) | F0 |
| `v3.personal_path_in_shared_argv_config` (`MUT:257`, source patch) | `T3P::test_process_artifacts_contain_no_personal_root_canary` (`:480`) | P0 |
| `v3.remove_scoped_token_enforcement` (`MUT:265`, source patch) | `T3A::test_stolen_base_facts_token_cannot_read_directory_or_admit_answers` (`:846`); `...::test_administrative_issuance_has_no_body_read_capability` (`:878`) | P0 |
| `v3.remove_nonce_uniqueness` (`MUT:276`, source patch) | `T3A::test_approval_replay_and_retarget_are_refused` (`:269`) | P0 |
| `v3.race_concurrent_approvals` (`MUT:284`, fixture) | `T3A::test_concurrent_approvals_and_double_submission_produce_one_event` (`:406`) | F0; zero committed events satisfies the bound |
| `v3.raw_terminal_output` (`MUT:292`, source patch) | `T3A::test_terminal_deception_payloads_are_rejected_or_bijectively_escaped` (`:1009`) | P0 |
| `v4.greatest_timestamp_wins` (`MUT:302`, source patch) | `T4::test_incompatible_heads_remain_conflict_until_authorized_parent_bound_event` (`:142`); `T5::test_newest_wins_is_not_the_rule` (`:281`) | P0 |
| `v4.omit_as_of` (`MUT:313`, source patch) | `T4::test_rebuild_is_deterministic_over_frozen_inputs` (`:354`); `...::test_omitting_as_of_breaks_determinism_and_is_refused` (`:395`) | P0; first node contains tautology |
| `v4.stale_company_head_as_git_authority` (`MUT:324`, fixture) | `T4::test_manifest_comparison_classifies_lag_incomplete_and_expiry` (`:227`) | F0 |
| `v4.worktree_local_lock` (`MUT:333`, source patch) | `T4::test_linked_worktrees_serialize_on_one_common_dir_lock` (`:603`) | P0; common lock existence is not asserted |
| `v4.content_path_before_revocation` (`MUT:342`, source patch) | `T4::test_pre_revocation_replay_returns_history_without_readmission` (`:561`) | P0; absent replay returns green |
| `v5.newest_wins` (`MUT:352`, source patch) | `T5::test_newest_wins_is_not_the_rule` (`:281`); `...::test_rejected_pr_does_not_displace_current_adr` (`:307`) | P0 |
| `v5.highest_authority_always_wins` (`MUT:363`, source patch) | `T5::test_scope_bounds_authority_rather_than_prestige` (`:365`) | P0 |
| `v5.repetition_as_independence` (`MUT:372`, source patch) | `T5::test_copied_chorus_does_not_outweigh_one_independent_decision` (`:331`) | P0 |
| `v6.synthesize_answer_from_model_prior` (`MUT:381`, source patch) | `T6::test_signed_answer_from_a_separate_process_materially_changes_the_decision` (`:334`); `...::test_unavailable_authority_yields_declared_degraded_policy` (`:510`) | P0 |
| `v7.independent_scalar_topk` (`MUT:394`, source patch) | `T7::test_duplicates_do_not_crowd_out_the_high_distortion_invariant` (`:198`); `...::test_marginal_value_is_recomputed_against_the_current_set` (`:234`) | P0 |
| `v8.codebase_authorizes_exception_to` (`MUT:407`, fixture) | `T8::test_only_company_steward_may_sign_a_relaxation` (`:398`); `...::test_maintainer_may_request_but_not_mint_an_exception` (`:321`) | F0 |
| `v9.disable_mid_session_capture` (`MUT:419`, source patch) | `T9H::test_mid_session_capture_continues_across_native_events` (`:325`); `...::test_precompact_and_stop_flush_pending_proposals` (`:406`) | P0 |
| `v9.reservation_after_render` (`MUT:431`, source patch) | `T9F::test_interleaved_sessions_never_exceed_four_prompts_per_window` (`:343`) | P0; zero prompts passes |
| `v9.check_outside_transaction` (`MUT:441`, source patch) | `T9F::test_reissue_and_reservation_commit_in_one_immediate_transaction` (`:245`) | P0; zero issued candidates passes |
| `detector.disable_archive_scan` (`MUT:453`, detector) | `HS::test_detector_mutations_miss_their_positive_control` (`:361`) | D0 |
| `detector.disable_sqlite_blob_scan` (`MUT:461`, detector) | Same node `HS:361` | D0; raw SQLite file scan can also mask lost cell scanning |
| `detector.disable_normalization_decoding` (`MUT:469`, detector) | Same node `HS:361` | D0 |
| `detector.disable_manifest_comparison` (`MUT:478`, detector) | Same node `HS:361` | D0; only a capability property is inspected |
| `detector.disable_partial_match` (`MUT:486`, detector) | Same node `HS:361` | D0 |
| `detector.disable_fail_closed` (`MUT:494`, detector) | `HS::test_scanner_error_fails_closed` (`:471`) | D?; default detector would likely miss the expected exception, but no kill result exists and the runner does not enforce it |

The mutation runner has no polarity implementation. `active_mutation()` is consumed only for the report header and output artifact at `C:111–120,226`; failures are still classified as ordinary product/harness failures. Therefore:

- a surviving mutation can leave every gate `PASS`;
- a killed product mutation is reported as `PRODUCT_FAILURE`, not as a successful sensitivity result;
- no assertion verifies every selected mutation killed every `must_fail` node; and
- no negative-control result is coupled to a mutation run.

## 8. Green-path and fail-closed audit

| Failure pattern | Exact occurrences and escape |
|---|---|
| Preinitialized PASS | `C:100` sets all 14 states to `PASS`; `C:212` defaults missing states to `PASS`. |
| Unexecuted/filtered/skipped nodes | `C:196–203` records only failed reports. Passing, skipped, deselected, collection-missing, and never-called tests create no execution receipt. Arbitrary pytest `-m` selection leaves all other gates green. |
| Skip becomes green | `HS:165` uses `pytest.importorskip`; the skip is never recorded and `INSTRUMENT` remains `PASS`. |
| Bare-return success | `T3A:219,1136`; `T3Q:383,422`; `T4:196,529,575`; `T8:537,544,754,817,821,870`. |
| Tautological assertion | `T4:377`: changed `as_of` is accepted regardless of result by `... != first or True`. |
| Default-zero success | `T1:349,352`; `T2:607,750,753`; `T3A:448`; `T9H:375–387`. Missing counters become zero. |
| Missing-view equality | `T1:341–347` serializes absent `current_view` as `null` twice, which is byte-identical. |
| Empty-loop success | `T2:413–423` low-confidence atom scan; `T3P:559–573` taint scan; `T3P:628–638` paraphrase candidate scan; `T3P:702–708` outbound request records; `T8:755–766` expiry events; `T9H:223–225` payload facts; multiple receipt/status loops. |
| Optional/truthiness-gated assertions | `T2:387`; `T3P:261–264,559,702`; `T4:251–265,476–480,530–542,576–581`; `T6:261–264,487–492,530–545,590–597`; `T8:173–178,286–305,436–443,481–488,536–548,649–670,716–720,760–766,815–834,869–887`; `T9F:124–141,199–207,277–286,399–404,446–461,533–537`; `T9H:243–244,296–304,421–435,598–603,676–685,766–771,800–816`. |
| Refusal as green without evidence duty | V-2 calibration accepts configured refusal; V-3 prompt/saturation probes return; V-4 conflict/replay/cascade return; V-6 delivery is optional; V-8 multiple semantic cases return; V-9 timing and host paths accept quick refusal. |
| Product self-attestation | V-1 lifecycle matrix; V-2 metrics; V-3 capability/privacy/reconstructor reports; V-4 scenario/cascade reports; all V-5 decisions; all V-7 candidates/traces; most V-8 state; V-9 budget, start-state, and maintenance adequacy. |
| Permissive JSON source | `CLI:168–174` accepts JSON from stderr when stdout is invalid. Many tests then use `{}`, `[]`, or optional fields instead of requiring the expected exit/state and complete schema. |
| Scanner omission | `SCAN:60–64` provides no `os.walk(onerror=...)`; `SCAN:68–69,136–137,202–203` turns absent roots/databases/repos into empty iteration; `SCAN:297–299` calls any empty finding set clean. |
| Product failure hides invalid detector | `C:179–183` lets any product assertion dominate an invalid detector without proving it is separately content-addressed and detector-independent. |

## 9. Oracle privacy and lane-boundary disposition

**Oracle privacy is not established.**

Concrete leaks and arm/gate selectors include:

1. The V-2 runtime JSONL is built with `{**record, "text": text}` at [`test_v2_classification.py:91–101`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v2_classification.py:91). Each `record` contains `gold_atoms`, `mixed`, and `stratum`; [`routing_corpus.json:3723–3762`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/fixtures/gold/routing_corpus.json:3723) shows expected atoms/destinations adjacent to message text. That same JSONL is passed to `session observe` at `T2:216–223`, `318–325`, `360–367`, `404–411`, and `445–452`.

2. V-5 gives the SUT the exact table row ID at [`test_v5_temporal.py:161–183`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v5_temporal.py:161), while expected state/fragments are defined at lines 59–150.

3. V-7 supplies `KINBASE_ACCEPTANCE_V7_FIXTURE=1` from an otherwise empty repository at [`test_v7_projection.py:82–114`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v7_projection.py:82).

4. V-8 supplies digest scenario, criticality, validity, dependence, revocation, identity resolution, and event-count results through environment selectors rather than signed state.

5. V-9 passes the full gold maintenance file to the SUT. [`maintenance_workload.json:5–26`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/fixtures/gold/maintenance_workload.json:5) includes `durable_shared_fact`, `gold_correct_admission`, `gold_label`, trust class, and severity. It is passed at `T9F:498–506`.

6. Every acceptance-prefixed environment name is visible to the SUT because `CLI:345–375` merges overrides into the child environment. The product can branch on acceptance identity even when the value is a legitimate fault schedule.

Positive privacy properties observed statically:

- The dedicated canary vault validates that its root is outside the repository and forbidden roots and sets mode 0700.
- Raw V-2 canary values are generated at runtime rather than committed.
- Sanitized detector findings omit raw canary bytes.
- Git object and SQLite readers exist.

Those properties do not repair the direct expected-result inputs above.

## 10. Harness result-model disposition

**Invalid.**

The ratified semantics define `INVALID_HARNESS` as non-green and require an unperformed measurement not to become proof. The dispatch further requires unexecuted gates to be `NOT_RUN` or an equivalent non-green state.

Current behavior:

```text
pytest_configure:
    every gate = PASS

pytest_runtest_makereport:
    record failures only

pytest_terminal_summary:
    missing gate state => PASS
```

Consequences:

- `tests/run-acceptance.sh -m v1` can print `PASS` for V-2 through V-9.
- An empty collection after successful configuration can retain an all-PASS vector.
- A skip remains PASS.
- A selected mutation whose required nodes pass remains PASS.
- There is no expected-node census, executed-node count, control count, or mutation-kill count in the gate artifact.
- The mutation runner never turns a surviving mutant into `INVALID_HARNESS`.
- Product failures dominate invalid instrumentation without the separate content-addressing predicate required by `V:34–36`.

Required model:

- initialize gates/nodes as `NOT_RUN` or equivalent;
- record setup, call, teardown, pass, fail, skip, deselection, and collection state;
- require the full expected node/control/mutation census;
- keep instrument invalidity distinct from product failure;
- retain product failure over invalidity only when independently content-addressed and detector-independent;
- require all positive controls and mutation kills, while all negative controls remain clean.

## 11. Auxiliary-corpus disposition

**No eligible corpus can be selected.**

The only auxiliary file is [`tests/fixtures/policies/auxiliary-corpus-request.json`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/fixtures/policies/auxiliary-corpus-request.json:1). It describes eligibility classes and says at line 48 that it is only a request and recording contract.

Absent from the allowed surface are:

- actual licensed-public source candidates;
- source-rights/license records;
- exact contents and versions;
- a selection procedure over concrete candidates;
- frozen generated transformation dictionaries;
- preregistered correlation records;
- preregistered decoy records; and
- an `auxiliary_corpus_sha256` value binding the selected bytes.

`T3Q:598–629` merely confirms that names such as `source_rights`, `contents`, and `versions` appear inside `reviewer_must_record`; it does not require values or a selected corpus.

Per `TM:198–204`, I did not broaden the input surface or invent a selection.

## 12. Numbered findings

### 1. [BLOCKING] Full repository cleanliness is not attestable

- **Location:** repository Git worktree metadata; `git status --porcelain=v1 --untracked-files=all`.
- **Violated requirement:** dispatch immutable binding and clean-repository precondition.
- **Escape:** unstaged changes or untracked files under excluded unreadable paths could exist while the allowed surface and index appear clean.
- **Required remediation:** provide a boundary-compatible, content-addressed cleanliness attestation or make Git status metadata available without exposing excluded contents, then rerun the binding check.

### 2. [BLOCKING] The prescribed self-test path crosses the Reviewer boundary and can mutate/network-install

- **Locations:** [`tests/conftest.py:87–99`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/conftest.py:87), [`requirements.py:201–227`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/_harness/requirements.py:201), [`run-acceptance.sh:34–42`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/run-acceptance.sh:34).
- **Violated spec:** `V:128–133`, which gives this Reviewer only specs, tests/fixtures, detector design, and the auxiliary pool.
- **Escape:** runtime collection, imports, marker behavior, and sensitivity failures cannot be established through the provided command; dependency floors can also resolve to different implementations.
- **Required remediation:** provide an immutable offline reviewer environment and a reviewer-specific bootstrap restricted to `spec/**` and `tests/**`; defer evidence receipt verification to the Validator.

### 3. [BLOCKING] Unexecuted work is preinitialized and emitted as PASS

- **Locations:** [`tests/conftest.py:100`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/conftest.py:100), [`tests/conftest.py:196–203`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/conftest.py:196), [`tests/conftest.py:206–235`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/conftest.py:206).
- **Violated spec:** `V:8–36`, `V:118–133`, and the dispatch’s total-work/fail-closed rule.
- **Counterexample:** select only `-m v1`; V-2 through V-9 remain `PASS` without collection or execution.
- **Required remediation:** initialize `NOT_RUN`, record every expected node and outcome, and make skips, deselections, missing collection, empty parameter sets, and incomplete controls non-green.

### 4. [BLOCKING] Invalid instrumentation can be hidden by an unverified product assertion

- **Location:** [`tests/conftest.py:179–183`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/conftest.py:179).
- **Violated spec:** [`spec/verification.md:34–36`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/spec/verification.md:34).
- **Counterexample:** a detector self-test fails, then an ordinary assertion in the same gate fails; the state becomes `PRODUCT_FAILURE` even though no separate content address or detector independence was established.
- **Required remediation:** preserve parallel instrument/product channels and apply dominance only after verifying an independently content-addressed product observation.

### 5. [BLOCKING] The preregistered catalog does not contain all four required elements per gate and obligation

- **Locations:** [`mutations.py:1–14`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/_harness/mutations.py:1), [`test_backreference_integrity.py:170–192`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_backreference_integrity.py:170), [`ACCEPTANCE-MAP.md:52–86`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/ACCEPTANCE-MAP.md:52).
- **Violated spec:** `V:118–126`.
- **Counterexample:** `BR:180–187` computes `marked_controls` but never asserts it; lines 188–191 only require some mutation entry per gate. V-1, V-2, and V-4 through V-9 have no formal positive/negative control and no detector mutation.
- **Required remediation:** create a machine-readable, per-obligation catalog naming threshold, exact positive control, exact negative control, product mutation, detector mutation, surface/vector, expected outcome, and fail-closed result.

### 6. [BLOCKING] Catalog mutation coverage is declarative rather than executable and total

- **Locations:** [`mutations.py:58–66`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/_harness/mutations.py:58), [`tests/conftest.py:111–120`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/conftest.py:111), [`test_harness_selftest.py:361–480`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_harness_selftest.py:361).
- **Violated spec:** `V:120–126`; `TM:157–162`.
- **Counterexample:** set `KINBASE_ACCEPT_MUTATION=v5.newest_wins`; no code applies that mutation or checks its nodes. Five detector entries point to a self-test that intentionally passes when the mutant is blind.
- **Required remediation:** provide executable planters/patches, run each of all 41 entries, enforce every `must_fail` node, require negative controls to remain clean, and emit a content-addressed total kill ledger.

### 7. [BLOCKING] Expected answers and case identities reach the SUT

- **Locations:** [`test_v2_classification.py:91–101`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v2_classification.py:91), [`routing_corpus.json:3723–3762`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/fixtures/gold/routing_corpus.json:3723), [`test_v5_temporal.py:161–183`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v5_temporal.py:161), [`test_v7_projection.py:90–114`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v7_projection.py:90), [`test_v9_fatigue.py:483–537`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v9_fatigue.py:483).
- **Violated spec:** `V:128–133`, `TM:180–204`, and the dispatch’s oracle-independence criterion.
- **Counterexample:** a product can map temporal case IDs, V-7 fixture mode, V-8 scenario strings, or maintenance gold labels directly to expected JSON without measuring raw work.
- **Required remediation:** expose only raw input through ratified shipping surfaces; retain labels and expected outputs solely in the harness; limit controls to independently witnessed timing/ordering/failure schedules.

### 8. [BLOCKING] V-1 lifecycle and idempotence can pass without required raw evidence

- **Locations:** [`test_v1_ingestion.py:324–353`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v1_ingestion.py:324), [`test_v1_ingestion.py:458–502`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v1_ingestion.py:458).
- **Violated spec:** `V:159–195`.
- **Counterexample:** omit `current_view`, `duplicate_observations`, and `duplicate_facts`; two `null` views compare equal and missing counters default to zero. A product can print the lifecycle cell names and arbitrary `negative_mutation` strings without running any transition.
- **Required remediation:** execute every one of the 64 matrix cells against raw sources, independently inspect observations/facts/Unknowns, require present counters and nonempty views, and kill at least one real negative mutation per cell.

### 9. [BLOCKING] V-2 has a missing calibration input, leaked gold, self-reported metrics, and disconnected saga state

- **Locations:** [`routing_corpus.json:1601–1602`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/fixtures/gold/routing_corpus.json:1601), [`test_v2_classification.py:213–299`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v2_classification.py:213), [`test_v2_classification.py:502–654`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v2_classification.py:502), [`test_v2_classification.py:717–755`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v2_classification.py:717).
- **Violated spec:** `V:199–235`.
- **Counterexample:** the referenced `tests/fixtures/gold/calibration-manifest.json` does not exist, yet a `CONFIG_INVARIANT`/`SCORER_UNCALIBRATED` refusal passes. Function-scoped roots mean saga tests list candidates without first ingesting the corpus. Crash probes use a nonexistent candidate and missing counters default to zero.
- **Required remediation:** add the distinct frozen 60-message input, keep its gold from the SUT, compute metrics from raw predictions in the harness, seed each saga in its own test, and require independently witnessed crash points and exactly-once outcomes.

### 10. [BLOCKING] V-3 does not execute the finite threat model totally or fail closed

- **Locations:** [`scanners.py:60–90`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/_harness/scanners.py:60), [`test_v3_attacks.py:91–135`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v3_attacks.py:91), [`test_v3_privacy.py:145–259`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v3_privacy.py:145), [`test_v3_qualification.py:82–159`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v3_qualification.py:82).
- **Violated spec:** `V:237–329`; `TM:110–171`.
- **Counterexample:** an unreadable subdirectory may be silently omitted by `os.walk`; three precreated surface families are enough for a clean scan; attack-family coverage checks anchor names only; randomized surface labels never traverse those surfaces; refusals/empty candidates satisfy multiple attacks; the FD is not inherited; the saturated payload is not saturated.
- **Required remediation:** provide every enumerated vector/surface with exact PC/NC/detector mutation, require nonzero per-location receipts, propagate traversal errors, execute successful prerequisite work, use `pass_fds`, construct the full ceiling payload, run an independent reconstructor with the selected corpus, and require total family/control/mutation accounting.

### 11. [BLOCKING] V-4 substitutes scenario selectors and contains vacuous assertions

- **Locations:** [`test_v4_maintenance.py:95–126`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v4_maintenance.py:95), [`test_v4_maintenance.py:227–268`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v4_maintenance.py:227), [`test_v4_maintenance.py:354–379`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v4_maintenance.py:354), [`test_v4_maintenance.py:439–643`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v4_maintenance.py:439).
- **Violated spec:** `V:331–368`.
- **Counterexample:** fixed repository state plus `CYCLE_STAGE`/`MANIFEST_SCENARIO`/synthetic counts can produce expected reports; changed `as_of` always passes because of `or True`; replay/cascade may be absent; common lock existence is never asserted.
- **Required remediation:** construct the actual event/manifests, 10× corpus, dense graph, revocation, replay, and linked-worktree operations; assert all four reducer input variations, exact lock/receipt lineage, and nonempty fail-closed state.

### 12. [BLOCKING] V-5 is entirely selected by a test-only semantic oracle

- **Locations:** [`test_v5_temporal.py:59–150`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v5_temporal.py:59), [`test_v5_temporal.py:153–183`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v5_temporal.py:153).
- **Violated spec:** `V:370–388`.
- **Counterexample:** all nine cases use the same empty initialized repository; changing only `KINBASE_ACCEPTANCE_TEMPORAL_CASE` changes the asserted state, fragment, and counterfactual.
- **Required remediation:** plant independently signed event histories for each case through shipping ingestion, remove the selector, compute expected state from tester-held gold, and assert exact trace/counterfactual content.

### 13. [BLOCKING] V-6 never registers the authority whose round trip it claims to measure

- **Locations:** [`test_v6_authority.py:50–130`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v6_authority.py:50), [`test_v6_authority.py:146–180`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v6_authority.py:146), [`test_v6_authority.py:205–264`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v6_authority.py:205), [`test_v6_authority.py:510–598`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v6_authority.py:510).
- **Violated spec:** `V:390–419`.
- **Counterexample:** the helper creates a public key and channel process, but no public API registers either. The “registration” test merely lists status. Delivery receipt is optional. Cache expiration and answer service are environment modes.
- **Required remediation:** explicitly register the authority/key/channel through a shipping API, require delivered-question and authority-process receipts, build actual cache state before expiry, and use a separate frozen service whose requests/results are independently logged.

### 14. [BLOCKING] V-7 replaces the measured candidate set with a fixture-mode flag

- **Location:** [`test_v7_projection.py:82–114`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v7_projection.py:82).
- **Violated spec:** `V:421–436`.
- **Counterexample:** an implementation can detect `KINBASE_ACCEPTANCE_V7_FIXTURE=1` and emit the exact roles, selection trace, and stopping reason expected by the tests.
- **Required remediation:** encode raw candidate records independently, ingest them through the shipping corpus surface, keep fixture roles/expected set selection outside the SUT, and kill scalar-top-k using that raw state.

### 15. [BLOCKING] V-8 does not establish live Company/reference/cache behavior

- **Locations:** [`test_v8_company_refs.py:74–114`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v8_company_refs.py:74), [`test_v8_company_refs.py:135–191`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v8_company_refs.py:135), [`test_v8_company_refs.py:260–305`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v8_company_refs.py:260), [`test_v8_company_refs.py:464–548`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v8_company_refs.py:464), [`test_v8_company_refs.py:696–834`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v8_company_refs.py:696).
- **Violated spec:** `V:438–474`.
- **Counterexample:** the published reference event is unsigned and stored under a fabricated digest path; the certificate is not wired into the clone; no Company server starts. Semantic values are sent through environment selectors. Manifest regression success, absent expiry events, absent projection, and several refusals pass.
- **Required remediation:** run a real Company service; publish properly signed, correctly content-addressed fact versions and certificates; mutate live state/cache/revocation; require exact events and Unknowns; remove semantic result selectors.

### 16. [BLOCKING] V-9 can pass without installation, host invocation, real state, prompts, or operator work

- **Locations:** [`test_v9_host_lifecycle.py:114–165`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v9_host_lifecycle.py:114), [`test_v9_host_lifecycle.py:190–308`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v9_host_lifecycle.py:190), [`test_v9_host_lifecycle.py:462–617`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v9_host_lifecycle.py:462), [`test_v9_fatigue.py:87–141`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v9_fatigue.py:87), [`test_v9_fatigue.py:421–537`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v9_fatigue.py:421).
- **Violated spec:** `V:476–525`.
- **Counterexample:** denied install may succeed; zero invocation records skip `assert_not_mocked`; two refusing hosts skip parity; every timing call may immediately refuse; the claimed 250-ms connect check permits five seconds; zero rendered prompts passes; operator results are optional; maintenance gold is supplied to the product. No submodule is constructed.
- **Required remediation:** require approved and denied installation outcomes plus exact file deltas, mandatory invocation/config receipts, actual cache/fsck state construction, a 250-ms bound, real submodule topology, nonzero eligible prompt work, completed operator decisions/times, and raw gold-free maintenance observations.

### 17. [BLOCKING] Required licensed-public auxiliary corpus pool is absent

- **Locations:** [`auxiliary-corpus-request.json:1–49`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/fixtures/policies/auxiliary-corpus-request.json:1), [`test_v3_qualification.py:598–629`](/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/detector-reviewer/tests/acceptance/test_v3_qualification.py:598).
- **Violated spec:** `TM:198–204`; `V:128–133`, `V:250–252`.
- **Counterexample:** a request listing field names passes the self-test despite containing no selectable source, rights record, version, content, selected bytes, or digest.
- **Required remediation:** place the concrete eligible licensed-public pool, source-rights records, generated dictionaries, correlation records, and decoys under the permitted review surface. Then have a fresh Reviewer select and record procedure, contents, versions, rights, and digest before combination.

## 13. Limitations

- This was a static, implementation-blind instrument review. No product snapshot was inspected or selected.
- Pytest collection and self-tests were not run because the provided bootstrap reads forbidden `evidence/**` material and may create/install files.
- Full worktree cleanliness could not be established without inspecting excluded paths.
- Mutation kills were not executed; static reachability does not count as a kill.
- No eligible auxiliary-corpus pool was present, so no selection or digest could be produced.
- Git file names were used only as repository metadata; excluded file contents were not read.
- This report does not issue a product/proof verdict.

DETECTOR_REVIEW_STATUS: BLOCKED 17
