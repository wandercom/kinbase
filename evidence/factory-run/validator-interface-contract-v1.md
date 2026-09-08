# Guildhall interface contract — generation ac8a13d1, Rust product

Issued by the Validator. This document fixes the interface shapes the ratified spec leaves open. Where it conflicts with spec text, the spec wins and the conflict is a spec-defect to raise. Section 7 contains the Validator rulings that resolve known conflicts; they are binding for this generation.


Conventions in this document:
- `A | B` = the instrument accepts either key (alternatives, first present wins).
- `?` = optional / read with no-default accessor (`field()` returns None; the catalogue then decides).
- `list[obj{...}]` = list of JSON objects with at least the listed keys.
- "vocab" = closed string set the instrument compares against.

---

## 0. Process-level contract (applies to every CLI invocation)

**Entry point resolution** : `GUILDHALL_BIN` (shell-split argv prefix) → `guildhall` on `PATH` → `sys.executable -m guildhall` (the tests' own venv interpreter; `import guildhall` must succeed there). None resolving = product failure, not instrument failure.

**Environment the product receives** . Everything else is scrubbed.
- Passed through from the Tester shell if set: `PATH LANG LC_ALL TZ TMPDIR SYSTEMROOT PYTHONHASHSEED` (`run-acceptance.sh` sets `PYTHONHASHSEED=0` by default).
- Always set: `HOME=<base>/home`, `XDG_CONFIG_HOME=<base>/config`, `XDG_DATA_HOME=$HOME/.local/share`, `XDG_STATE_HOME=$HOME/.local/state`, `XDG_CACHE_HOME=$HOME/.cache`, `GIT_CONFIG_GLOBAL=$HOME/.gitconfig`, `GIT_CONFIG_SYSTEM=/dev/null`, `GIT_TERMINAL_PROMPT=0`, `GIT_AUTHOR_NAME/EMAIL`, `GIT_COMMITTER_NAME/EMAIL` (fixture identity), `NO_COLOR=1`, `TERM=dumb`, `PYTHONIOENCODING=utf-8`.
- Per-test overrides (the only semantic env inputs, ):
  - `GUILDHALL_COMPANY_URL=http://127.0.0.1:<port>` — Company endpoint override .
  - `GUILDHALL_PROOF_CLOCK_OFFSET_SECONDS=<int>` — advance the product's proof clock by N seconds for that invocation . Values used: `0`, `3600*k`, `86400`, `604800`, `900+60`.
- Never present: any `GUILDHALL_ACCEPTANCE_*`, `GUILDHALL_HOST_*`, `GUILDHALL_BIN`, vault/mutation vars .

**cwd**: always the repository root under test (or a clone/worktree/submodule path), except `experiment *` calls which run from the fixture repo root without `--repo`.

**stdin**: normally closed/empty (`subprocess.run(input=None)`). Some `hooks dispatch` calls pass a JSON document on stdin (§1.10); one probe passes 64× a hostile byte string to `status`  — the product must ignore stdin there.

**Inherited descriptors**: one test passes an extra open `O_RDONLY` directory fd (the Personal root) via `pass_fds` .

**Timeouts**: every invocation is killed (SIGKILL) at 120 s by default ; `session start/observe`, `proposals decide` via `popen()` waited ≤120–180 s.

**`--json` output contract** :
- `stdout.strip()` must parse as *one* JSON document (`json.loads`). If stdout does not parse, stderr is tried as the error document. Empty stdout under `--json` is a product failure.
- Every line of `stdout+stderr` from `doctor --repo X --json` must individually `json.loads` : therefore emit the `--json` document as a **single line** and any stderr diagnostics as **JSON-lines objects**. No raw private message bytes anywhere in stdout/stderr.
- No `Traceback (most recent call last)` text may ever appear on stdout/stderr .
- Exit codes are exactly the `spec/cli.md` table `{0,2,3,4,5,6,70}`; **exit 1 is always a product failure** wherever observed .
- Error object: instrument reads `payload["error"]["code"]` directly in most places (`field(payload, "error", "code")`), and `Result.error` also accepts a bare top-level error object. **Emit the nested form**: `{"error": {"code": <vocab>, "message": str, "remediation": str, "retryable": bool, "evidence_id": str}, ...}`; all five keys required; `code` must be in the closed taxonomy . A nonzero exit must carry this object . Exit-per-code pairs actually consumed: `COMPANY_UNREACHABLE→{6,3}`, `CACHE_EXPIRED→3`, `REVOCATION_STALE→3`, `REPO_UNCERTIFIED→2`, `FOREIGN_REPO_EVENTS→4`, `SIGNATURE_INVALID→5`, `DIGEST_MISMATCH→5`, `DIGEST_ALGORITHM_UNSUPPORTED→3`, `MANIFEST_INCOMPLETE→{5,3}`, `MANIFEST_HEAD_REGRESSION→4`, `LIMIT_EXCEEDED→4`, `APPROVAL_EXPIRED→2`, `APPROVAL_REPLAY→4`, `AUTHORITY_WRONG_SCOPE→4`, `AUTHORITY_SCOPE_DENIED→4`, `UNKNOWN_OWNER_UNRESOLVED→3`, `PERSONAL_TAINT_BLOCKED→5`, `HOOK_APPROVAL_REQUIRED→2`, `UNSUPPORTED_HOST_VERSION→3`, `UNSUPPORTED_KINDEX_VERSION→3`, `PROCESSOR_UNAUTHORIZED→5`, `MODEL_FINGERPRINT_CHANGED→70`, `ORACLE_LEAKAGE→70`, `SCORER_UNCALIBRATED→70`, `RUN_CENSUS_MISSING→70`, `CONFIG_INVARIANT→4`, `RUN_INTEGRITY_FAILED→70` .
- Commands whose success payload the instrument reads may also carry `error` (e.g. `ingest` at the intake ceiling is read for both `error.code` and `omitted_count`).
- `--help` for `status doctor fsck ingest project explain proposals questions hooks` and `experiment verdict --help`: exit 0, combined stdout+stderr ≤ 65536 bytes; `experiment verdict --help` must not contain `demo-success` .

---

## 1. CLI commands — exact argv and JSON keys read

Positional/flag order below is the order the instrument uses; `--json` is always last.

### 1.1 `company serve --config <company_root>/guildhalld.toml`
Long-lived (`popen`, new session group; SIGTERM then SIGKILL after 30 s). Must accept a loopback TCP connection on the configured bind within 30 s . Also probed: the port must not accept a connection on the host's non-loopback IP . No `--json` output is read. `company init` is **never** invoked.

### 1.2 `status [--repo PATH] --json`
Invoked as `status --repo <repo> --json` (also on clones, linked worktrees, submodule dirs, nested repos, and an uncertified/forked clone under a blackholed Company). Keys read (all top-level unless noted):
- `bind: str` — loopback bind string .
- `repository_uuid: str` — certified UUID; must be equal across clone/linked worktree and *different* for submodule and nested repo .
- `trusted_fact_count: int`, `foreign_event_count: int` .
- `unknowns: list[obj{kind: str (vocab seen: "certificate","identity"), owner_identity, owner_role, response_due_at, logical_key?}]` (, ).
- `facts: list[obj{logical_key, state, statement, provenance_recomputed?}]` — `state` vocab observed: `current`, `withheld`, `withdrawn`, `unknown`, `conflict` (, ).
- `observations: list[obj{origin_trust_class ∈ {merged-default, approved-pr, unreviewed-branch, uncommitted-worktree}, ...}]` ().
- `changed_dispositions: list[obj{observation_id, from_disposition, to_disposition}]`, `history_retained: bool` ().
- `lifecycle_cells: list[obj{adapter, cell, observation_state, current_fact_state, unknown_state, negative_mutation_killed}]` keyed by the instrument's 64 `(adapter, cell)` names; state vocabularies are the instrument's : observation ∈ {appended, amended_new_observation, terminal, expired_raw_withheld, absent_source_recorded, resumed, superseded_observation, retracted_observation, revoked_observation, conflicting_observations, late_arrival_ordered, skew_bounded, removed_observation, narrowed_view, rewritten_lineage}; fact ∈ {current, unchanged, withdrawn, historical_only, conflict, absent, recomputed}; unknown ∈ {none, opened, reopened, closed, owner_scoped}. Cell names: see  (e.g. `codex_jsonl`/`create`, `repo_code`/`shallow/sparse view`, `git_history`/`rebase/force-push`). () — see conflict C15.
- `reopened_decisions: list` ().
- `cursor_skew: list[obj{cursor ∈ {personal,company,codebase}, positive_skew_quarantined: bool, negative_skew_quarantined: bool, out_of_order_handled: bool}]`, `skew_dispositions: list[str]` containing `"CLOCK_SKEW"` ().
- `misextraction_notices: list[obj{logical_key, admitted: bool, asserted_claim: "evidence_byte_mismatch", semantic_withdrawal: bool}]` ().
- `never_true_admissions: list[obj{authority_id, accepted: bool, refusal_code?}]` ().
- `authority_cursor: str` , `view_stabilises: bool`, `growth_bounded: bool` ().
- `exceptions: list[obj{signed_by: <authority_id>, accepted: bool, refusal_code?}]`, `exception_request_accepted: bool`, `effective_criticality: str` ().
- `events: list[obj{atom_kind, statement?, unresponsive_closing_authority?, signature?, fact_state?}]` — filtered for `atom_kind == "orphan_abandoned"` () and `atom_kind == "observation_expired"` (); `observation_status: "historical-only"` (), `pending_orphans: int` ().
- `query_log | query_traces: list[obj{requested, returned, selected_ids, working_set, resident_at_dependent_edit, declared_use, marginal_gain, stopping_reason, outcome, cost}]` .
- `privacy_claim: str` — must contain verbatim `Zero observed unauthorized durable disclosure outside the authorized processor boundary under Acceptance Threat Model` and name `guildhall-atm/1`; must not contain `privacy proved` / `zero leakage`; `execution_census_digest: str` .
- `shared_work_performed: bool` (read when an inherited Personal fd forces a refusal; ), plus `error.code`.
- Refusals read from `status`: `error.code` / `error.retryable` (`PROCESSOR_UNAUTHORIZED`, `retryable:false` when `GUILDHALL_COMPANY_URL` names an unauthorised endpoint — and zero bytes must be sent to it, ); hostile `.kin/config` → exit 5 with typed error ; broad-mode token file → exit 4 with `chmod` in the message, token bytes never echoed .

### 1.3 `doctor [--host codex|claude] --repo PATH --json`
Only `doctor --repo <repo> --json` is invoked. Keys:
- `processes: list[obj{role, granted_capabilities: nonempty list, holds_personal_capability: bool, personal_root_in_serialized_config: bool}]` ().
- `budget_shard: obj{shard_id, signed: bool}`, `unknown_global_total_warning: bool`, `hourly_prompts_consumed: int`, `consecutive_prompts: int`, `reservations_held_after_crash`, `delivery_loss_rate`, `low_authority_displaced_high_distortion: bool` .
- Process artefact dump: the instrument inspects `ps -o command= -p`, `ps -E`, `lsof -p` of live `status`/`doctor` processes; the Personal root path and canaries must not appear in argv/env/fd tables .

### 1.4 `fsck --repo PATH [--full] --json`
Keys: `store_digest: str` (), `manifest_comparison: obj{classification}`, `manifest_relations: obj{superset: "normal_lag", missing_head: "INCOMPLETE", expired_owner: "company-steward"}` (), `admitted_paths: list[obj{path}]` (lowercase digest paths only), `ineffective_git_attributes: bool` (), `cascade_state ∈ {"complete","REVOCATION_CASCADE_INCOMPLETE"}`, `unchecked_facts_withheld: bool` (, `--full`), `admission_lock_path: str` (absolute; must lie inside `git rev-parse --git-common-dir`; no `<worktree>/.git/guildhall.lock` may exist), `manifest_lineage_count: int` (), `digest_attribution: obj{owner_role ∈ {"company-steward","client","none"}}`, `company_query_attempted: bool` (), `unknowns: list[obj{kind, owner_role}]` (). Two certificates in `.kin/` → nonzero exit (). Hostile event bytes at a correct content path → typed exit in table, never 1 .

### 1.5 `ingest SOURCE_KIND SOURCE --repo PATH --json`
`SOURCE_KIND` ∈ {codex_jsonl, claude_jsonl, repo_code, repo_tests, git_history, docs_adr, github_export, runtime_evidence, kindex, authority_answer}. `SOURCE` paths used: `<repo>/sources/<codex|claude|src|tests|adr|github|runtime|kindex|answers>` (directories), `<repo>` for git_history, `<repo>/.kin` for kindex (the dominant path: planted signed events are admitted via `ingest kindex <repo>/.kin`), `<repo>/docs/adr`, a single oversized file for repo_code, a symlink and an escaping path for repo_code (must refuse). Exit 0 or 3 both treated as "processed" where noted; exit 1 always fails. Keys:
- `adapter: str`, `source_identity: str`, `observations: list[obj{source_kind, source_identity, content_digest, observed_at, disposition, extraction_version, observation_id?}]`, `derived_facts: nonempty list`; key `observations_count_only` must be **absent** ().
- `admitted_facts: list` (must be empty after a failed write to a `0o500` `.kin/events`) .
- `omitted_count: int` + `error.code == "LIMIT_EXCEEDED"` (or nonzero exit) at every ceiling .
- `historical_receipt`, `readmitted: bool`, `receipt_scope_restricted: bool` on replay of pre-revocation bytes ().
- Concurrency: two `ingest kindex` from two linked worktrees run simultaneously ().

### 1.6 `corpus rebuild --store personal|company|codebase --repo PATH [--as-of RFC3339ms] [--reducer-version N] --json`
Keys: `build_manifest: obj{observation_ids, source_revisions, digests, checkpoints, fact_derivations}` (each nonempty), `current_view_digest: str`, `canonical_digest: str`, `duplicate_observations: int`, `duplicate_facts: int`, `observation_count: int`, `inputs: obj{as_of: str}` (must echo the explicit `--as-of`; omitting `--as-of` must not silently read the ambient clock — ). Determinism: identical inputs → identical `current_view_digest`; each of events / reducer version / as_of / authority cursor changes it (). `--as-of` / `--reducer-version` are **not** in `spec/cli.md` (conflict C12).

### 1.7 `explain LOGICAL_KEY --repo PATH --decision TEXT [--as-of RFC3339ms] [--authority-cursor N] --json`
Exit must be 0 or 3 for a planted history . Keys: `state` (vocab used: `current`, `conflict`, `unknown`), `trace | reducer_trace` (list), `evidence_that_would_change_the_result | counterfactual` (list or str), `uncertainty_state`, `rejected_events` (list), `negative_evidence` (list), `selection_reason | selected_by` (str), `current_statement` (str), `selection_trace` (list), `independent_corroboration_count: int`, `unknowns: list[obj{owner_role, owner_identity}]`, `trusted: bool`, `authority_scope: str`, `environment_owner | owner_identity`, `effective_criticality`, `company_owner`, `local_owner` . The rendered JSON must **not** contain any instrument case identifier and must cite the discriminating evidence in prose. Hostile key `architecture/'; DROP TABLE facts; --/%/_/*/?/[a-z]/../..//

### 1.8 `project --repo PATH --task TEXT --decision TEXT [--working-set FACT_ID]... --json`
`--working-set` is repeated once per id. Exit 0 or 3. Keys: `candidates: list[obj{logical_key,...}]`, `selected: list[obj{fact_id, logical_key}]`, `selection_trace: list[obj{fact_id, marginal_value: number, current_set_size, redundancy_basis?, marginal_terms: obj{newly_covered_distortion, authority_and_validity_gain, complementarity_gain, uncertainty_reduction, redundancy, retrieval_and_residency_cost, stale_or_conflict_risk}}]`, `tier_escalation: list[obj{tier ∈ (facts_and_unknowns, summary, exact_code_span, history_adr, test_runtime_evidence, authority_answer, broad_search) in that order}]`, `projection_bytes: int`, `stopping_reason ∈ {nonpositive_net_marginal_value, sufficiency_predicate_met, authority_question_raised}`, `unknowns: list[obj{owner_role, owner_identity}]`, `voi_approximation | objective`, `trusted_recommendation` (None until an authority answer is admitted), `degraded_policy ∈ {block_dependent_decision, reversible_sandbox_only_experiment, named_human_granted_exception}`, `company_reference_resolved: bool`, `company_statement: str` (live Company prose, never written to Git), `projection_state ∈ {"withheld","projected"}`, `omitted_count` at the 32-fact/128 KiB ceiling. The rendered payload must not contain `calibrated causal voi`, `calibrated_causal_voi`, `proven voi`, `model prior`, `synthesised`. (, , , .)

### 1.9 Session / proposals
- `session start --host codex --repo PATH --json` — output not read; exit ≠ 1.
- `session observe SESSION --event FILE --json` — **`SESSION` is a caller-supplied opaque string** (24-hex token or `s<16hex>`), not an id returned by `session start` (, ) — conflict C8. `FILE` is a JSONL corpus (§3.10). Exit 0 or 3 = processed. Key read: `classifier.fingerprint` (). A batch of 10,001 lines must refuse with `LIMIT_EXCEEDED`/`omitted_count`.
- `session end SESSION --json`; `session checkpoint` is never invoked.
- `proposals list --session SESSION --json` → `predictions: list[obj{id: <corpus id>, atoms: list[obj{kind, text, destinations: list[str] | str}], confidence?: str}]` , `metrics: obj{macro_f1: number}` (must agree with the harness recomputation within 0.005), `atoms: list[obj{atom_id, destination, confidence ∈ {low,...}}]`, `candidates: list[obj{candidate_id, payload_digest (64 hex), destination (e.g. "codebase:<uuid>", "company:root", "personal"), message_id (= corpus `id`), rendered: bool, suppressed: bool, taint_cleared: bool, hard_block_respected: bool}]`, `deidentify_retains_taint: bool`, `fanout_receipts: obj{codebase: obj{state, global_rollback?}, company: obj{state, global_rollback?}}` with `state ∈ {committed, refused, pending, abandoned}` and `global_rollback` **absent**, `apologies: list[obj{responsible_party_role: "approving-principal", closing_authority_role ∈ {repository-maintainer, company-steward}, orphaned_fact_withheld: bool, state ∈ {awaiting_reconcile_or_abandon, reconciled, abandoned}}]`, `duplicate_events: int`, `recursive_apologies: int`, `committed_event_count: int`. Destination labels in predictions are the P-2 vocab `personal | company | codebase | none`.
- `proposals decide CANDIDATE --destination DEST (--approve-digest SHA256 | --reject | --defer) --json` → `receipt_id: str` (identical on retry), `retry_after_token_expiry: bool`. `DEST` values used: `codebase:<repository_uuid>`, `company:root`, `codebase:none` (nonsense id → typed refusal). Also invoked malformed: `proposals decide CANDIDATE --all|--accept-all|--yes-to-all --json` (must not exit 0), `proposals decide --session S --json` (no candidate; must not exit 1). Under a blackholed Company the `company:root` decide must refuse/pend without rolling back the committed codebase write. Expired candidate (clock +960 s) → `APPROVAL_EXPIRED` exit 2. `--escalate` is never invoked.
- `proposals show CANDIDATE --destination DEST --json`; also `proposals show --destination codebase:none --json` (no candidate). Output not parsed.
- `proposals reissue CANDIDATE --json` → `candidate_id`, `payload_digest`; exit 0 = issued.
- `proposals reset --after-primary-event EVENT_ID --reason-code new-primary-task|operator-recovery|host-restart --json`; a free-text reason must be refused (nonzero); a second reset within the hour → `LIMIT_EXCEEDED`.
- Crash probes: `proposals decide` is SIGKILLed once a new entry appears under `<repo>/.kin/nonces`, `.kin/events`, `.kin/manifest`, `.kin/receipts`, `.kin/unknowns` respectively () — these five subtrees are the journal artefact classes the instrument watches; then two concurrent retries must converge to one committed event.

### 1.10 Hosts
- `hooks plan codex|claude --json` → `files: list[obj{path: str}]`, `commands`, `permissions`; must change nothing under `$HOME`; rendered plan must not contain `--force`, `--no-approval`, `--yes`.
- `hooks install codex|claude --json` → `HOOK_APPROVAL_REQUIRED` (exit 2), no file changes. `hooks install HOST --approve --json` → exit 0; files created under `$HOME` must be exactly those declared in `plan.files[].path` **as `$HOME`-relative strings** . Conflict C9/C16.
- `hooks dispatch codex|claude EVENT --json`, `EVENT ∈ {SessionStart, UserPromptSubmit, PreToolUse, PreCompact, Stop, SessionEnd}`. stdin forms:
  - none (empty) — , ;
  - a native envelope (§3.13) —  etc., also via `popen` with stdin written after spawn ;
  - `{"prompt": "read <personal-root-file>"}` ().
  Keys read: SessionStart → `repository_root`, `company_state`, `canonical_facts` (nonempty; equal across hosts), `decisions`, `receipts`, `company_connect_seconds: number`, `degraded: bool`, `trusted_company_facts: list` (empty while refreshing), `start_path` (vocab: `warm_verified` for the warm path), `full_fsck_performed: bool`, `trusted_context: list`, `events: list[obj{statement?}]` (must be empty of bodies when uncertified), `counts: obj`. UserPromptSubmit → `capture_active: bool`, `personal_root_readable: bool`, `sandbox_enforced: bool`, `sandbox_disabled_loudly: bool`, `stolen_bytes_promoted: bool`. Stop → `checkpointed: bool`. Exit 0 or 3 = accepted start.
  The JSON must never contain the Personal root path or canary bytes.

### 1.11 Questions
- `questions list --json` → `questions: list[obj{question_id, decision, evidence_examined, remaining_alternatives, distortion_if_wrong, question}]`. Must be an object even with no repo context .
- `questions ask QUESTION_ID --json` — must deliver an HTTP POST to the channel registered for the in-scope authority (§2.5) with a JSON body containing `question_id` and `task_id`.
- `questions answer QUESTION_ID --answer-file FILE --key-file FILE --json` — answer file §3.6; key file = hex Ed25519 public key + `\n`. Wrong-role answer → `AUTHORITY_WRONG_SCOPE | SIGNATURE_INVALID` and status stays open.
- `questions status QUESTION_ID --json` → `status ∈ {closed, superseded, open ...}`, `closure_event_id`.

### 1.12 Repository
- `repo init --repo PATH --certificate FILE --json` — invoked only on a legacy Kindex `.kin/` with a pre-existing `.kin/events/legacy-node.json` collision and a non-existent certificate path; must refuse (nonzero) and change zero bytes (). `repo issue` is never invoked.
- `repo publish-manifest --repo PATH --json` — exit 0 on first publish; after `git reset --hard HEAD~1` → `MANIFEST_HEAD_REGRESSION` with `rollback` in the remediation text; after a maintainer event with `atom_kind: "rollback_exception"` → exit 0 ().

### 1.13 Experiment
- `experiment freeze MANIFEST --budget FILE --json` → refuse (nonzero, typed) when `census|power|calibration|budget` is missing from the manifest; success payload `ceiling_reserved_atomically: true`; a second freeze with a raised budget must refuse and must not echo `aggregate_usd: 5000`.
- `experiment run FROZEN_MANIFEST [--smoke] --json` → `RUN_CENSUS_MISSING` exit 70 when `run_census` is null; `--smoke` must not exempt; `evaluation_principal ∈ {administrative, broad-service-reader}` refused (typed); `task-scoped-agent` with `authority_scopes` must not exit 4.
- `experiment census MANIFEST --json` → `human_bytes_after_freeze: int`.
- `experiment verdict RUN --json` (RUN = a JSON file or an empty directory) → `published_conclusion: str` (must contain the P-10 licensed template verbatim: `On the digest-identified task population, repositories, model/provider fingerprint, budgets, authority service, and finite threat model in this run, Guildhall met P-1 through P-9 and raised blinded brownfield quality to the preregistered P-10 equivalence band.`; must not contain `Kindex works`, `privacy is proved`, `all brownfield coding reaches greenfield quality`), `run_digest`, `terminal_product_verdict ∈ {PROVEN, NOT_PROVEN, INCONCLUSIVE_NO_HEADROOM, INCONCLUSIVE_CEILING, INVALID_RUN}`, `gate_result ∈ {PASS, PRODUCT_FAILURE, INVALID_HARNESS}`, `measurement_result ∈ {PROVEN, NOT_PROVEN, INCONCLUSIVE_NO_HEADROOM, INCONCLUSIVE_CEILING, NOT_RUN}`, `independent_product_failure`, `headroom_condition`, `ceiling_condition`, `gate_vector` (required non-null); composition must follow . Rendering `INVALID_RUN` when `human_bytes_after_freeze ≠ 0`.
- `experiment pilot|calibrate|score` never invoked.

---

## 2. HTTP service (`guildhalld`) as the instrument speaks it 

Transport: `http.client.HTTPConnection("127.0.0.1", port)`, 30 s timeout, body sent only when non-empty.

**Headers on every request** :
- `Authorization: Bearer <token>` (omitted when token is empty),
- `Host: 127.0.0.1:<port>` (probe: `guildhall.example`),
- `Content-Type: application/json` (probe: `text/plain`; may be omitted),
- `Origin:` never sent except the probe `https://evil.example`,
- when signed (default): `X-Guildhall-Nonce: <decimal, starts at "1", +1 per request per client>`, `X-Guildhall-Expires-At: <RFC3339 ms Z, now+60 s>`, `X-Guildhall-Client-Key: <hex 32-byte Ed25519 public key>`, `X-Guildhall-Signature: <hex 64-byte Ed25519 signature>`.

**Request signature** : `sig = Ed25519.sign(client_seed, SHA-256("guildhall-sig/1" || 0x00 || "receipt" || 0x00 || JCS({"body_sha256": sha256hex(body bytes), "expires_at": <hdr>, "method": "GET"|"POST", "nonce": <hdr>, "path": <request path>})))`. `body_sha256` of an empty body is `sha256(b"")`. Domain `message_type` is literally `"receipt"` (conflict C5). The client key is a fresh random 32-byte seed per `ServiceClient`; it is never registered with the service (conflict C5).

**Bodies** are JCS bytes (RFC 8785 after NFC, sorted keys, no whitespace, `ensure_ascii=False`).

**Endpoints used**:
| method path | body | success | used by |
|---|---|---|---|
| `POST /v1/authority-registry` | registry document §3.4 | 200/201/202; JSON body read as `registry_receipt` (any dict) |  |
| `POST /v1/facts` → `POST /facts` → `POST /v1/company/facts` (tried in order, first 200/201/202 wins) | Company fact document §3.5 | 200/201/202 |  |
| `GET /questions` | — | status recorded only |  |
| `POST /questions` | `{"probe": <name>}` | refusal probes only: `token=""`+unsigned, `Host: guildhall.example`, `Origin: https://evil.example`, `Content-Type: text/plain` + `b"not json"` — each must answer status ≥ 400 with body ≤ 4096 bytes |  |
| `POST /answers`, `GET /questions/{id}` | never called directly | | |

All service calls use the **facts** bearer token . Refusal statuses accepted: `400,401,403,404,429` .

**Blackhole**: a listener on the Company port that accepts TCP but never reads/answers ; the product must give up within the 250 ms connect budget (§5).

---

## 3. Documents the instrument writes / hands over

### 3.1 Canonical bytes and signatures 
- JCS: `json.dumps(nfc(value), sort_keys=True, separators=(",",":"), ensure_ascii=False).encode()`; ints within ±(2^53−1); no floats; NFC applied to keys and strings; duplicate-after-NFC keys rejected.
- `signing_digest(mt, jcs) = SHA-256(b"guildhall-sig/1" + 0x00 + mt + 0x00 + jcs)`; `mt ∈ {fact-event, unknown-event, manifest, approval-token, repo-certificate, authority-registry-entry, rotation, revocation, tombstone, question, answer, receipt}`.
- Keys: Ed25519 (RFC 8032); seed = 32 bytes; `signer` = hex(32-byte public key); `signature` = hex(64 bytes).
- **Convention A (dominant; events, certificate, registry, lifecycle answers)** `synth.Signer.sign_message`: body := payload minus `signature`; `digest = signing_digest(mt, JCS(body))` where body does **not** contain `signer`; then `signer` and `signature` are added. Verified the same way in  (pops `signature`, pops `signer`, then digests).
- **Convention B (authority helper answers)** : body includes `"signer"` before digesting; `digest = signing_digest("answer", JCS(body ∪ {signer}))`; then `signature` added. Verified in  the same way (only `signature` removed).
- **Convention C (bulk corpora, ≥10 000 events)** : body includes `"signer"` **and** `"message_type": "fact-event"`; `digest = signing_digest("fact-event", JCS(body minus signature))`.
  → A verifier must try A, and also B/C (see conflict C4).
- Content digest for paths: `sha256(JCS(signed doc))` hex; event path `.kin/events/<h[0:2]>/<h[2:4]>/<h[4:]>.json` ; bytes on disk are exactly the JCS bytes, no trailing newline.

### 3.2 FactEvent  — `schema: "guildhall-event/1"`
Keys always present: `schema, event_id ("evt_" + 12 digits; derived from hash(logical_key, statement) → NOT unique across distinct events), store_kind ∈ {personal, company, codebase}, authority_id, authority_scope, fact_id ("fact_" + 12 digits, from hash(logical_key)), logical_key, atom_kind, scope (= authority_scope), statement, evidence_refs: list[str], asserted_at, effective_from, disposition, distortion: obj, parents: list[event_id], supersedes: list[event_id], redundancy_with: [], complements: [], company_refs: list[CompanyReference], authority_snapshot_cursor: str (decimal, e.g. "1000","1001","1002","2000","2100"), confidence: "high", unresolved_uncertainty: ""`, plus `signer`, `signature`. Optional: `repository_id` (present iff store_kind == codebase; value = certified UUID), `effective_until`.
- `atom_kind` values planted: `constraint, claim, decision, observation, rationale, question` (spec) **and** `misextraction, never_true, revocation, unknown, dependence, exception_request, exception_to, rollback_exception, task_event`; expected in output: `orphan_abandoned, observation_expired`.
- `disposition` values planted: `accepted, rejected, proposed, retracted, notice, open`.
- `distortion` shapes planted: `{trigger, loss_if_absent ∈ {high, low}, rationale}` **or** `{severity: "high", reversibility: "irreversible"}` ().
- Timestamps `YYYY-MM-DDThh:mm:ss.000Z`; planted `asserted_at` range 2025-01-01 … 2026-03-09.
- Authority scopes seen: `company:root` (steward), `codebase:<uuid>` (maintainer), `architecture:scheduling` (architect), `environment:prod-eu`, `environment:staging-xx` (unregistered), `approver:local`, `codebase:example` (impostor).
- Events of every `store_kind` (including `company` and `personal`) are planted **in the repository `.kin/events/`** and admitted via `ingest kindex <repo>/.kin` (conflict C7).

### 3.3 UnknownEvent  — `schema: "guildhall-unknown/1"`: `event_id ("unk_…"), store_kind, logical_key, decision_blocked, owner_role, owner_identity, question, closure_evidence, status ("open"), response_due_at, expiry_policy ("block")`.

### 3.4 Repository certificate & authority registry 
- Certificate: `{"schema":"guildhall-repo-certificate/1","repository_uuid":<uuid>,"issued_at":<ts>,"company_id":"company-demo",["lineage_parent_uuid":<uuid>],"signer","signature"}` signed `repo-certificate` (convention A) by the steward; written as JCS to **`<repo>/.kin/certificate.json`** and committed (conflict C2). A forged one is signed by an `attacker-steward` key with scope `company:root`; a second certificate may appear at `.kin/certificate-second.json`.
- Root key: `<company_root>/company-root.pub` = steward public hex + `"\n"`; `<company_root>/company-root.key` = 32 raw seed bytes (0600) — the same seed as the steward signer, so the service's root key **is** the steward key.
- Registry document: `{"schema":"guildhall-authority-registry/1","authority_cursor":"1000","entries":[{"authority_id","scope","public_key"(hex),"channel","capabilities":[...]}],"signer","signature"}` signed as one document with message_type `authority-registry-entry` (convention A). Entries always registered: steward `company:root` channel `company:root` caps `["publish"]`; maintainer `codebase:<uuid>` channel `codebase:<uuid>` caps `["request","publish-manifest"]`; architect `architecture:scheduling` channel `process:architecture-answer` caps `["answer","supersede"]`; V-6 adds the same architect key again with channel `http://127.0.0.1:<port>/questions` caps `["answer"]`. Mirrored to `<company_root>/authority-registry.json` and POSTed to `/v1/authority-registry`. Registry entries must not expose `email` or `private_key`.

### 3.5 Company fact document (V-8)
`{"company_id":"company-demo","fact_id":<str>,"version":<int>,"statement":<str>,"company_criticality":"safety_critical"|"advisory","valid_from":<ts>,"valid_until":<ts>,"digest_alg_version":"guildhall-digest/1","semantic_digest":sha256hex(JCS({"statement":<statement>})),"signer","signature"}` signed **`fact-event`** (convention A) by the steward; multiple versions of one `fact_id` are admitted and must all be retained (historical digest lookup by version).

### 3.6 CompanyReference  inside `company_refs[]`
`{company_id, fact_id, semantic_digest, digest_alg_version ("guildhall-digest/1"), authority (= steward authority_id), valid_from, valid_until, company_criticality, relation ∈ {applies, specializes, implements, contradicts, exception_request}}`; **never** `local_dependence_class` or `statement`. Local dependence is a separate codebase event with `atom_kind: "dependence"`, statement `"the local dependence class is <safety_critical|advisory>"`, `parents=[reference event]`.

### 3.7 Authority answer
- Lifecycle/impostor form : `{"schema":"guildhall-answer/1","question_id","authority_id","authority_scope","answer","rationale","answered_at","signer","signature"}`; variants add `parents: ["<qid>#1"]`, `revocation: {authority_id, cursor}`, `asserted_at`.
- Live helper form , which is what `questions answer --answer-file` receives in V-6: `{"message_type":"answer","question_id","answer","rationale","contains_code":false,"signer","signature"}`. The helper responds `200` to `POST <channel>` with JSON body `{"task_id","question_id"}`; a third call for one `task_id` returns `429 {"error":{"code":"LIMIT_EXCEEDED","retryable":false}}`. Helper logs `{task_id, question_id, request_digest, request_bytes, call_index, peer}` per delivery.

### 3.8 `.kin/config` (TOML, )
```
schema_version = "guildhall-repo/1"
repository_uuid_hint = "018f0000-0000-7000-8000-000000000001"
safe_name = "example-service"
domains = ["scheduling"]
```
Variants the product must survive: extra key `origin = "https://elsewhere.example/renamed-service.git"` with `safe_name` changed (identity must stay stable — , conflict C11); `safe_name` containing raw NUL/`\xff\xfe`/SQL bytes → exit 5 typed ; legacy Kindex YAML-ish config (`name:/description:/audience:/data_dir:`) in the collision test.
`.gitattributes` always contains `.kin/events/** -text -diff -merge` and `.kin/manifests/** -text -diff -merge`; one test removes them and expects `ineffective_git_attributes: true`.

### 3.9 `.kin/` layout the instrument creates or expects
- `.kin/events/<2>/<2>/<60>.json` — JCS signed events (§3.2); up to 100 000 of them .
- Non-conforming plants the product must tolerate (report, never crash, never exit 1): `.kin/events/oversized.json` (64 KiB+ body), `.kin/events/<2hex>/<64hex>.json` with `{"statement","logical_key"}` only (V-3 matrix), an uppercase-digest alias path, a raw-NUL event at its correct content path, `.kin/events/legacy-node.json` (collision), `.kin/receipts/*.json`, `.kin/outbox/*.json`, `.kin/published/<token>.json` (`{"heads":{branch:sha},"count":int,"fresh_until"?,"unreachable"?}` — the instrument's manifest-observation stand-in, ), `.kin/certificate.json`, `.kin/certificate-second.json`, legacy `.kin/index.json`, `.kin/code-map.json`, `.kin/.gitignore`, `.kin/local/kindex.db`.
- Watched product journal subtrees: `.kin/nonces`, `.kin/events`, `.kin/manifest` (sic, singular), `.kin/receipts`, `.kin/unknowns` (); `.kin/manifest` removal = "full fsck required" state .
- `.kin/events` chmod 0500 during one ingest (must refuse, admit nothing).

### 3.10 Session observation corpus (`--event FILE`, )
JSONL, one object per line, **only** keys `id` (opaque token), `role` ("user"|"assistant"), `text`, `observed_at` (RFC3339 ms Z), `source_kind` ("codex_jsonl"). Sizes: 1 line, ~20–120 lines, and 10 001 lines. The `id` must round-trip into `predictions[].id` and `candidates[].message_id`.

### 3.11 Native source formats 
- Codex JSONL: line 1 `{"type":"session_meta","id","timestamp","cwd","originator":"codex_cli_rs","cli_version"}`; then `{"type":"response_item","id","timestamp","payload":{"type","role","content":[{"type":"input_text","text"}]}}`; appended lines `{"type":"message","role","ts","content":[{"type":"text","text"}]}`, duplicated/edited lines (`"edited":true`), terminal `{"type":"session_end","ts","session_id"}`; restart file `<session>-rNN.jsonl`; a `.jsonl.retention` sidecar `{"private_retention_seconds","raw_mtime"}` with mtime pushed past 24 h.
- Claude JSONL: `{"parentUuid","isSidechain":false,"userType":"external","cwd","sessionId","version","type","message":{"role","content":[{"type":"text","text"}]},"uuid","timestamp"}` chained by `parentUuid`; terminal marker `{"type":"stop",...}`.
- Command-result envelope (`repo_tests`, `runtime_evidence`), JCS file: `{"schema":"guildhall-command-result/1","command":[...],"exit_code":int,"stdout":str,"observed_at":ts,["environment_id","effective_until","environment_owner"]}`.
- ADR Markdown: front matter `---\nadr: NNNN\ntitle: …\nstatus: Proposed|Accepted|Rejected|Superseded\n[supersedes: NNNN]\n---\n\n# title\n\nbody`.
- GitHub export JSON: `{"schema":"gh-export/1","issues":[{number,title,state,body,edited?,reopened?}],"pullRequests":[{number,title,state,merged,body,reviews:[{state: APPROVED|CHANGES_REQUESTED, author}],updatedAt}]}`.
- Kindex SQLite export: tables `nodes(id TEXT PK, node_type, title, content, payload BLOB, created_at)` and `edges(src,dst,relationship,reason)` ; lifecycle cells instead address columns `node_id, kind, body, version` .
- Repo code: Python and TypeScript modules under `src/scheduler/`; test under `tests/.

### 3.12 User / service configuration
- **User config is never written by any test** (`roots.write_user_config` has no caller; conflict C1). If it were, it would be `$XDG_CONFIG_HOME/guildhall/config.toml` 0600 exactly as `spec/cli.md:19-40` with `[personal] data_root`, `[company] url/facts_token_file/root_public_key_file/cache_root`, `[classifier] executable/executable_sha256/args/timeout_seconds`, `[hosts] codex_version/claude_version`.
- Service config `<company_root>/guildhalld.toml` 0600 : `schema_version="1", company_id="company-demo", sqlite_path=<company_root>/company.sqlite3, bind="127.0.0.1:<port>", root_key_file=<company_root>/company-root.key, facts_token_file=<company_root>/facts.token, directory_token_file=<company_root>/directory.token, auth_failures_per_minute=10, default_fact_freshness_seconds=3600, candidate_lifetime_seconds=900, clock_skew_seconds=300, nonce_retention_seconds=604800`.
- Token files: raw bytes, no newline, 0600: `facts.token` = `"facts-" + 40 hex`, `directory.token` = `"dir-" + 40 hex`. No scope list is encoded anywhere (the harness-side `authority_scopes` tuple is never transmitted).

### 3.13 Host hook envelopes 
Codex: `{"hook_event_name":<EVENT>,"session_id","cwd","transcript_path":"<cwd>/.codex/sessions/<sid>.jsonl","host":"codex"}`. Claude: same plus `"permission_mode":"default"`, `transcript_path":"<cwd>/.claude/projects/<sid>.jsonl","host":"claude"`. Delivered on stdin as one JSON document. Expected *output* discipline : a length-prefixed stream `<decimal byte length>\n<exactly that many JSON bytes>` repeated with no separator; no top-level keys `command, tool, tools, policy, system, permissions, destination, approval`; each body in `facts`/`evidence` carries `label` or `trust_label` = `UNTRUSTED_EVIDENCE_NOT_INSTRUCTIONS`.

### 3.14 Experiment inputs (V-10)
Manifest JSON: `{"census":{"digest":<64hex>,"signed":true},"power":{"n":int,"mde":number,"cost_usd":int},"calibration":{"digest","valid":true},"budget":{"aggregate_usd":int,"human_ratified":true}}` with one section removed per probe; frozen manifests `{"frozen":true,"run_census":null}`, `{"frozen":true,"evaluation_principal":<str>,["authority_scopes":["company:architecture:scheduling"]]}`, `{"frozen":true}`; budget file `{"aggregate_usd":int,"human_ratified":true}`; `experiment verdict` also receives an empty directory.

### 3.15 Blinded operator responses (harness-only, )
JSONL `{item_id (opaque token), decision ∈ {approve,reject,defer,escalate}, decided_at (RFC3339 µs Z)}` at `$GUILDHALL_OPERATOR_RESPONSES`; never reaches the product.

---

## 4. Filesystem layout and modes 

`<base>` = pytest tmp_path/`proof`:
- `home/` (HOME; hooks install writes here; scanned for `*.json` config files), `config/` (XDG_CONFIG_HOME), `private/kindex-personal/` **0700** (Personal root; canary files planted here; never a parent of any shared root), `company/` (service root: `guildhalld.toml`, `company.sqlite3`, `facts.token`, `directory.token`, `company-root.key`, `company-root.pub`, `authority-registry.json`, `native/`), `company-cache/` **0700** (the `cache_root`; the instrument deletes all files here to construct "cold"/"stale revocation", writes `facts-cache.sqlite3` = `b"not a database"` for "invalid cache", and scans it: `facts-cache.sqlite3` is opened read-only and every table/column/BLOB is scanned; `entries/*.bin` and every other file is byte-scanned), `workspace/example-service/` (the repo; `docs/**` and `.git` objects/packs are scanned), `run/` **0700** (corpora under `run/corpus/`, `run/workload/`, `run/operator/`, authority helper under `run/authority/`, `run/state/` is the "logs"/"host_projection"/"process_artifacts"/"service_response" scan root, `run/raw/` is checked to be absent after retention), `evidence/` **0700**.
- Mode expectations checked on the product: personal/run/company-cache must remain ≤ 0700 ; token/key files 0600; a 0644 `facts.token` must be refused with exit 4 and `chmod` remediation.
- Symlinks: a symlink inside the repo pointing outside (`<repo>/escape-link`) passed to `ingest repo_code` must refuse; a path escaping the repo (`<tmp>/../escape`) must refuse; any symlink the product leaves under a scanned root is itself a finding surface .
- Scan surfaces the product must keep canary-free in every encoding (exact, NFD/NFKC, base64, hex, percent, JSON-escape, fragmentation, archives `.gz/.tgz/.zip/.tar/.xz/.bz2`, SQLite BLOB/TEXT columns, packed Git objects): `company-cache/**`, `<repo>/docs/**`, `<repo>/.git` objects, `<repo>/.kin/events/**`, `<repo>/.kin/outbox/**`, `<repo>/.kin/receipts/**`, `run/state/**`, `evidence/**`, and the `ps`/`lsof` argv/env/fd dumps of `status`/`doctor` .
- Git: fixtures are created with `core.ignorecase=false`, `core.autocrlf=false`, `commit.gpgsign=false`, fixed author/committer date `1767225600 +0000`; one test flips `core.ignorecase=true`, `core.autocrlf=true`. Linked worktrees via `git worktree add -b`; submodule via `protocol.file.allow=always`; shallow (`--depth 1`) and sparse (`--filter=blob:none --no-checkout` + cone `sparse-checkout set src/scheduler`) clones; bare `origin.git` sibling for force-push. Repository-scoped lock must live under `git rev-parse --git-common-dir` (worktrees share it).
- macOS sandbox/denial probes (): `hooks dispatch codex UserPromptSubmit` with stdin `{"prompt":"read <personal file>"}` must report `personal_root_readable:false`, (`sandbox_enforced:true` or `sandbox_disabled_loudly:true`), `stolen_bytes_promoted:false`; an inherited open directory fd of the Personal root must make `status` exit nonzero with `error.code ∈ {CONFIG_INVARIANT, PERSONAL_TAINT_BLOCKED, PROCESSOR_UNAUTHORIZED}` and `shared_work_performed` not true, before any shared work.

---

## 5. Timing and size budgets observed (number → spec clause)

| budget | how measured | spec |
|---|---|---|
| SessionStart p95 < 2.0 s  per host per state {warm, cold, invalid-cache, full-fsck-required}, 200 invocations each, **wall time of the whole `hooks dispatch` subprocess including interpreter start** |  | `spec/architecture.md:735-745`, `spec/verification.md:490-495` |
| blackholed Company: p95 ≤ 2.0 s over 20 starts; `company_connect_seconds` ≤ 0.250 s; `degraded:true`; zero trusted Company facts |  | `spec/architecture.md:736-737` |
| full `fsck --full` at 10 000 dense events ≤ 120 s, else `cascade_state == REVOCATION_CASCADE_INCOMPLETE` with facts withheld |  | `spec/architecture.md:314-316,743-744` |
| unreachable/black-holed Company on `status`: nonzero typed exit within 120 s |  | `spec/verification.md:780-781` |
| every command: killed at 120 s (harness default), some waits 180 s |  | — |
| help ≤ 65 536 bytes; HTTP refusal body ≤ 4096 bytes | ,  | `spec/verification.md:775,785-786` |
| source body 1 MiB; observation batch 10 000 items / 256 MiB; shared event 64 KiB; `.kin/` intake 10 000 events / 128 MiB; projection 32 facts / 131 072 bytes; each stop reports `omitted_count` | ,  | `spec/verification.md:863-866` |
| 10× intake ceiling (100 000 events): intake refuses `LIMIT_EXCEEDED`, `fsck` still answers (0/3), `session start` still starts |  | `spec/verification.md:349-352` |
| candidate/approval lifetime 900 s → `APPROVAL_EXPIRED`; raw private retention 86 400 s |  | `spec/verification.md:867-868` |
| prompts: ≤ 4 rendered per sliding hour across destinations and hosts, ≥ 1 suppressed when 5+ eligible; 3-consecutive counter; `reset` once per hour → second is `LIMIT_EXCEEDED` |  | `spec/cli.md:203-212`, `spec/architecture.md:414-435` |
| authority answer service: 2 calls per task, third → 429 `LIMIT_EXCEEDED` |  | `spec/verification.md` V-6 |
| nonce retention 604 800 s > 900 + 300 s |  | `spec/cli.md:61-70` |
| soak: 20 starts, ≥ 90 % `start_path == "warm_verified"`, ≤ 5 % `full_fsck_performed` after the first, 0 refusals |  | `spec/verification.md` V-9 soak |

---


## 7. Validator rulings (binding)

- **C1 — user config never written. INSTRUMENT + PRODUCT.** The instrument must write the
  launcher user config at `${XDG_CONFIG_HOME:-$HOME/.config}/guildhall/config.toml`
  (0600) with exactly the cli.md keys, using an isolated `HOME`/`XDG_CONFIG_HOME` per
  world, before any command that needs Company, cache, certificate, or Personal. The
  product resolves config only from that path (honouring both variables) and never from
  the worktree or the environment.
- **C2 — certificate inside worktree. INSTRUMENT + PRODUCT.** The steward certificate is
  installed with `repo init --repo PATH --certificate <file outside the worktree>`; the
  product copies it into the out-of-worktree Company cache root (0700) keyed by
  repository UUID and reads it only from there. A `.kin/certificate.json` inside the
  worktree is inert: counted as a foreign path, never trusted. "Uncertified" is
  constructed by withholding the cache/config, not by deleting a tracked file.
- **C3 — trusted results without anchors. INSTRUMENT.** V-5, V-7, NF determinism and
  diagnostics worlds must establish anchors (service, root key, certificate, registry,
  user config) exactly as the other gates do. The product's behaviour without anchors is
  the spec's: `UNVERIFIED`, empty trusted projection, typed status.
- **C4 — signing convention. BOTH.** One convention: the signed bytes are the JCS of the
  document with `signature` removed and `signer` (64-hex Ed25519 public key) present;
  `signature` is 128-hex over `signing_digest(message_type, jcs_bytes)`. The authority
  registry is one document `{"schema":"guildhall-authority-registry/1","authority_cursor",
  "entries":[...]}` signed by the steward root key as message type
  `authority-registry-entry`. The Tester converges all three conventions to this one.
- **C5 — request signature type and client key. PRODUCT (ruling R-4 stands).** Request
  signatures use message type `receipt` over `{"method","path","body_sha256","nonce",
  "expires_at"}`. Client keys bind on first successful use per token (R-4).
- **C6 — token authority for writes. PRODUCT.** Registry publication is authorised by the
  document's steward root-key signature; fact admission by the registered in-scope
  authority's signature; both require only a valid token plus a valid request signature.
  Service config accepts an optional `facts_token_scopes = [exact scope strings]`; when
  absent, the facts token may read exactly the scopes present in the admitted authority
  registry; any wildcard, prefix, glob, or empty-string entry is `CONFIG_INVARIANT` at
  startup. Facts token scopes: `facts:read`, `questions:write`. Directory token scopes:
  `directory:read`, `admin:issue`. Endpoints: `POST /v1/authority-registry`, `POST /facts`
  (aliases `/v1/facts`, `/v1/company/facts`), `GET|POST /questions`, `POST /answers`,
  `GET /status`, `GET /facts`.
- **C7 — Company/Personal events inside `.kin/`. INSTRUMENT + PRODUCT.** Company events are
  admitted through the service; Personal facts never enter `.kin/`. The instrument plants
  Company facts via `POST /facts` and Personal material via host transcripts only. A
  `.kin/events/` file whose `store_kind` is not `codebase` is a foreign event: counted,
  typed, never trusted.
- **C8 — session identity. INSTRUMENT.** `SESSION` is the id returned by `session start
  --json`; the instrument must use it.
- **C9 — `hooks install --approve`. BOTH.** No bypass flag exists; an unknown flag is a
  typed usage error (exit 2). `hooks install <host>` writes exactly the diff shown by
  `hooks plan` into the host's user-level config under `$HOME`, exits 0 with the plan
  digest, and never touches the host's project settings. The host presents its own
  approval at its next start; `doctor` reports `HOOK_APPROVAL_REQUIRED` while the host
  config lacks the planned entries. The instrument drops `--approve`.
- **C10 — `.kin/manifest`. INSTRUMENT.** The directory is `.kin/manifests/`.
- **C11 — unknown `.kin/config` key. INSTRUMENT.** Unknown keys fail closed (cli.md). A
  discovery-hint change is expressed through the Git remote URL, not `.kin/config`.
- **C12 — undeclared flags. PRODUCT (R-1 extended).** `--as-of`, `--reducer-version`, and
  `--authority-cursor` are optional on every reducer-invoking command; omitted values come
  from the recorded proof clock / current reducer / current cursor and are echoed in output.
- **C13 — event vocabulary. INSTRUMENT + PRODUCT.** `atom_kind` is exactly one of `claim`,
  `question`, `decision`, `constraint`, `rationale`, `observation`. Lifecycle actions the
  spec names but omits from the message-type enum (`misextraction`, `never_true`,
  `support_withdrawn`, `orphan_abandoned`, `manifest_observation_expired`, `relaxation`,
  `exception_request`, `unreachable_clone_residual`) are FactEvent messages signed as
  `fact-event` whose `disposition` is the action name and whose `parents`/`supersedes`
  name the affected events. `distortion` is exactly `{trigger, loss_if_absent, rationale}`.
  Dispositions: `draft`, `proposed`, `accepted`, `approved`, `merged`, `rejected`,
  `reverted`, `deployed`, `retracted`, `superseded`, plus the action names above.
- **C14 — non-unique `event_id`. INSTRUMENT + PRODUCT.** `event_id` is unique per event
  (the instrument derives it from the event's content digest). The product keys identity on
  the content-addressed digest and refuses a second event reusing an `event_id` with
  different bytes as `DIGEST_MISMATCH`.
- **C15 — instrument-private lifecycle taxonomy. INSTRUMENT.** `status --json` reports
  per-adapter receipt counts and per-observation `disposition`/`state`
  (`current|stale|retracted|foreign|quarantined`); the instrument derives its matrix from
  those observable fields and never asks the product to echo cell names or
  mutation outcomes.
- **C16 — host invocation witness. INSTRUMENT + PRODUCT.** The instrument places its host
  wrapper first on `PATH` of every product invocation. `hooks plan --json` emits
  `files[].path` relative to `$HOME`, plus `commands[]` and `permissions[]`.
- **C17 — Personal descriptor detection. PRODUCT.** With C1 the product knows the Personal
  root; shared processes refuse any inherited descriptor under it (device/inode) and any
  descriptor outside the frozen allowlist, both as startup failures.
- **C18 — malformed invocations. PRODUCT.** A usage error (unknown flag such as `--all`,
  `--accept-all`, `--yes-to-all`, `--approve`; missing positional; malformed value) emits
  the typed error object with `code: "CONFIG_INVARIANT"` and exit 4. A decision or show
  that names no candidate, or `--destination codebase:none`, emits `APPROVAL_EXPIRED`
  (exit 2). Exit 1 never occurs; the top-level boundary maps any uncaught failure to
  `RUN_INTEGRITY_FAILED` exit 70.
- **C19 — repeated decisions on one candidate. PRODUCT.** A decision on a consumed or
  expired candidate returns `APPROVAL_REPLAY` (exit 4) or `APPROVAL_EXPIRED` (exit 2);
  never exit 1.
- **C20 — atomisation exact-match. NOTE.** Measurement gap in the instrument; not gating.
- **C21 — broken kindex lifecycle fixture. INSTRUMENT.** Repair the column/key mismatch; the
  `kindex` adapter's native schema is Kindex 0.36.0's export (`nodes(id, node_type, title,
  content, payload, created_at)` plus `edges`).
- **C22 — Company fact admission body. INSTRUMENT.** `POST /facts` bodies are FactEvents
  (architecture §3 field set, `schema: "guildhall-event/1"`) signed as `fact-event`.
- **C23 — single-line `--json`. PRODUCT.** Every stdout line and every stderr line under
  `--json` is one complete JSON document.
- **C24 — foreign artefacts under `.kin/`. PRODUCT.** `fsck`/`ingest`/`status` count
  non-reserved paths as `foreign_paths` and continue; malformed files inside
  `.kin/events/` or `.kin/manifests/` are typed integrity failures (`DIGEST_MISMATCH`,
  `MANIFEST_INCOMPLETE`, `SIGNATURE_INVALID`) with counts, never crashes.
- **C25 — empty-stdin SessionStart. PRODUCT.** Empty stdin is a minimal native envelope
  with `cwd` = process cwd; the SessionStart payload is still produced.
- **C26 — `--key-file`. PRODUCT.** Informational; refusal of an impostor is by registry
  lookup (`AUTHORITY_WRONG_SCOPE`).
- **C27 — p95 includes process start. PRODUCT.** Accepted; the binary is native.
- **C28 — `GUILDHALL_COMPANY_URL`. INSTRUMENT + PRODUCT.** The product never reads a Company
  endpoint from the environment; an env-supplied endpoint yields `PROCESSOR_UNAUTHORIZED`
  with zero connections. The blackhole/timeout probe configures its endpoint through the
  user config.
