# Product Specification — three-store Kindex proof

Status: **candidate for review and exact-byte ratification**

Authority: [`source-request.md`](source-request.md), especially `SRC-7`.

## Product claim

A developer opens a brownfield repository in a fresh Codex or Claude session. The
system immediately composes current, authorized Company knowledge with the current
repository's `.kin/` knowledge, continues observing the coding conversation and
repository evidence, asks the appropriate human authority when a load-bearing fact
cannot be resolved, and offers minimized knowledge atoms for the physically distinct
Personal, Company, and Codebase stores. The projected working set changes the
developer agent's implementation decisions enough to reach the quality of a matched
fully informed condition without leaking seeded private material. “Greenfield
quality” is the founder's desired quality bar; the experimentally valid comparator
is an `oracle-spec` arm operating on the same brownfield commit, not a repository
without legacy constraints.

The proof is the measured end-to-end outcome. Components, schemas, and passing local
tests are supporting evidence only.

Concrete store meanings: **Personal** is the principal's private conversational
memory; **Company** is organization-wide direction owned by a steward or named
authority; **Codebase** is repository-scoped knowledge whose approved signed events
travel with that repository under `.kin/`.

## Actors and authority

- The **principal** owns Personal knowledge and the raw session transcript.
- A **Company steward** may admit, supersede, dispute, or revoke Company facts.
- A **scoped authority** such as Chief Architect may answer an Unknown within the
  scope recorded in the Company authority registry. An answer has no authority
  outside that scope.
- A **Codebase maintainer** may approve repository facts for one stable repository
  identity. A Git branch, timestamp, classifier, coding agent, or Factory role is
  not that authority.
- The **classifier/extractor** proposes atoms and destinations but cannot publish.
- The **projector** chooses among already admitted facts but cannot widen admission.
- Codex and Claude host adapters present the same protocol and possess no knowledge
  publication authority.
- An **Oracle Curator**, isolated from Kinbase's schemas, retrieval design, and all
  candidate outputs, inventories the historical task population and extracts neutral
  fact-only judging artifacts from repository evidence and accepted post-change
  ground truth. The role has no product or verdict authority.
- An implementation-blind **Detector Reviewer** owns threat-corpus selection and
  challenges the Tester-authored privacy instrument before implementation is joined.
- The Factory roles retain their own authority boundaries from `SRC-6`.

## Required behaviors

### P-1 — heterogeneous, provenance-preserving ingestion

The running system ingests at least these independently implemented source classes:

1. Codex rollout/session JSONL;
2. Claude Code session JSONL;
3. repository source and interface/type declarations;
4. tests and executable verification results;
5. Git commits, diffs, branches, and merge/rejection status;
6. repository documentation and ADRs;
7. GitHub issue and pull-request exports, including review/disposition state;
8. runtime/configuration evidence supplied as files or command-result envelopes;
9. existing Kindex export/SQLite facts and repository `.kin/` events;
10. signed human-authority answers.

Every observation retains source class, stable source identity, content digest,
observed time, asserted/effective time when present, repository revision or remote
object when applicable, disposition, and extraction version. Incremental re-ingest
is idempotent. A changed or removed source produces a new observation and explicit
staleness/retraction state; it does not silently mutate historical evidence.

Acceptance requires one real end-to-end corpus build using at least seven source
classes, including both host transcript formats, Git history, code, tests, `.kin/`,
and one of GitHub or runtime/configuration evidence. Recorded fixtures may make the
run reproducible, but adapters must also execute against their native formats.

### P-2 — atomization, classification, and independent fan-out

One message or source item may produce zero or more minimal atoms. Each atom carries
one claim, question, decision, constraint, rationale, or observation; scope;
confidence; provenance; unresolved uncertainty; sensitivity/taint; and zero or more
proposed destinations. Destinations are `personal`, `company`, `codebase:<repo-id>`,
or `none`. Mixed text must split rather than force one label on the whole message.

Classification has zero write authority. Shared proposals are destination-specific,
minimized, de-identified where possible, and require separate exact-byte approval.
One source may fan out to multiple stores, but no cross-store transaction, shared
private lineage token, or accept-all operation exists. Partial success is reported
per destination and never rolls back an already durable independent write.

If a fan-out commits in one destination and terminally fails in another, the
approving principal owns the divergence. The committed destination receives an
apology Unknown referencing the refusal receipt, and the orphaned fact is withheld
from trusted projection until reconciled. If its closing authority does not act by
the signed deadline, the destination service must emit an `orphan_abandoned` terminal
event naming that authority and keep the claim untrusted; an orphan cannot remain in
an ownerless pending state forever. A retry of an already committed exact
event returns the original commit receipt even after token expiry; it cannot create a
second event or pretend the first commit did not happen.

The held-out routing corpus contains at least 120 natural messages, at least 40
mixed-scope messages, ambiguous non-facts, temporary suggestions, codebase facts,
Company architecture, and at least 30 seeded private/sensitive canaries. Required
macro-F1 across destination labels is 0.90 and each shared-destination precision is
at least 0.95 across the preregistered 95% lower bound of at least five pinned live-
model runs. Macro-F1 uses a message-stratified bootstrap; shared precision uses a
Wilson interval over pooled frozen predictions. Classifier sensitive-data recall is reported but is not a security
boundary. The deterministic taint/capability/scanner gate must allow zero seeded
canaries to reach a shared candidate or surface and fails closed on scanner error. A
low-confidence shared label is demoted to `none`/Unknown rather than guessed. These
thresholds judge routing utility and seeded defenses; they do not claim general
private-information detection or authorize publication.

Taint is non-clearable provenance, not one undifferentiated deny bit. `secret`,
credential, configured-canary, and forbidden-identifier observations are hard-blocked
from every shared candidate—even when a model paraphrases them and the output string
scanner would miss. Ordinary `personal-session` and `company-confidential` provenance
is approval-gating: it can yield minimized destination candidates only through
eligibility, scanning, and exact-byte human approval, while the taint remains on the
private audit record. The scanner is deterministic defense in depth; human approval
authorizes only the displayed bytes and never “clears” provenance.

Hard-block assignment is deterministic only for registered canaries/identifiers,
credential formats, explicit secret fields, and configured source classes. Model-
inferred sensitivity may add a hard block or abstention but never supplies the proof
boundary. Material outside those enumerated detectors remains approval-gated and its
measured classifier/scanner recall is reported; the finite threat-model qualifier is
mandatory because the proof does not establish detection of arbitrary private meaning.

### P-3 — physically separate products and disclosure boundary

Personal, Company, and Codebase use physically distinct store handles and roots.
No unified database with audience labels is allowed. Coding projection may read
authorized Company and the current Codebase plus ephemeral SessionInput; it may not
mount or query Personal. The promotion process that writes Company or Codebase is
constructed without a Personal-store read capability and receives only a minimized
candidate envelope. Shared projector/writer processes run under a supported OS policy
that denies the Personal root; if the startup denial probe cannot establish that
boundary, all shared reads/writes disable rather than degrade to same-UID convention.
The probe and launcher also enumerate/attest open descriptors; a shared process that
inherits any Personal-root descriptor fails even if pathname denial succeeds.

Raw transcript bytes, transcript paths/digests, stable source correlation IDs,
personal identifiers, secrets, configured canaries, or reversible mappings may not
appear in Company, `.kin/`, shared outbox, receipts, logs, caches, or projections.
De-identification is a proposal, not proof of safety; explicit approval binds exactly
one destination payload, principal, nonce, digest, and short validity interval.

Acceptance includes exhaustive byte scans of every persistent/shared surface and
adversarial replay, retarget, substitution, symlink/path traversal, malicious `.kin`
trust-root, prompt-injection, indirect-identifier, and partial-failure probes. One
seeded private canary or deterministic lineage on any unauthorized shared surface is
an immediate proof failure under the exact ratified finite
[`threat-model.md`](threat-model.md). The proof must always state that qualifier and
may not market the result as universal privacy.

### P-4 — maintained corpora, not append-only clutter

The system builds current views from immutable observations and explicit authority
events. It supports deduplication, semantic identity, typed redundancy and conflict
edges, validity intervals, branch/revision binding, supersession, retraction,
revocation, expiration of transient evidence, derived-view rebuild, and garbage
collection of private ephemeral inputs under a declared retention clock.

Concurrent Codebase events are unioned by identity. Timestamps and file order never
silently choose among incompatible heads. Company facts may be superseded only by an
authorized Company actor in scope. A stale or disputed fact is worse than a missing
fact: it is withheld from trusted projection and produces an owned Unknown.

Acceptance proves restart-safe idempotence, deterministic rebuild, branch union,
conflict survival, supersession and retraction, history rewrite/force-push handling,
out-of-order arrival and bounded clock skew, rejection of last-writer-wins, and
bounded storage behavior over a repeated incremental-ingestion simulation. Retiring
an observation recomputes every derived fact that cited it: the fact withdraws when
its final admissible support disappears and remains current only when an independently
admissible support still establishes it.

### P-5 — appropriate recency and resistance to bad shifts

Recency is evidence, never authority by itself. The current-view reducer considers:

- authority and scope;
- explicit validity and supersession;
- source disposition (draft, approved, merged, rejected, reverted, deployed);
- independence and convergence of evidence;
- repository revision and branch reachability;
- whether an item is an incident workaround, experiment, proposal, or durable rule;
- conflict with tests, runtime evidence, or higher-authority decisions.

The proof corpus includes temporal cases where: a newer rejected PR contradicts a
current ADR; many recent conversational repetitions share one prior; an old rule is
explicitly superseded by the right authority; a temporary workaround expires; live
configuration contradicts an old code default; and code drift conflicts with current
Company architecture. Expected results must demonstrate neither newest-wins nor
oldest/highest-authority-wins blindly. Every decision emits an inspectable evidence
trace and uncertainty state.

### P-6 — authority-seeking is an executed behavior

Unknowns are first-class graph nodes with scope, decision blocked, distortion cost,
owner role/identity, exact question, evidence required to close it, creation time,
and status. The Company authority registry resolves a question type and scope to an
actual named authority and supported channel. When expected value of another corpus
read is below the cost but a high-distortion Unknown remains, the system must send or
queue the targeted question and withhold the dependent trusted recommendation.

The proof must execute at least one architectural ambiguity through the Chief
Architect path: detect it, address the registered authority, ingest a signed answer,
close/supersede the Unknown, rebuild the view, and materially change the projected
guidance or decision. A fixture-only function that formats a question without an
authority round trip does not pass.

The live-human round trip is proved here, not smuggled into the causal comparison.
During P-10, every arm receives the same frozen answer service built only from
pre-change authoritative evidence, with identical query cost and logging. Question
use is reported as its own stratum. No benchmark answer may be improvised after a
candidate run begins.

Offline or unavailable authority does not become permission. The result explicitly
chooses one declared policy: block the dependent decision, permit a reversible
sandbox-only experiment, or proceed under a named human-granted exception. Expired
safety-critical Company facts block; ordinary stale advisory facts degrade loudly.

### P-7 — decision-conditional projection and sufficiency

Query accepts the task, decision to bound, eligible stores, current working-set fact
IDs, and cost budget. The projector selects a set, not independently weighted nodes.
It uses conditional distortion cost (expected loss if a fact is absent when the
dependent decision fires), typed redundancy/complementarity, authority/validity, and
evidence cost. Each candidate's marginal gain is recomputed against the current set.

The retrieval loop escalates from constraint/Unknown through summary, exact span,
history, tests/runtime trace, and broader search, stopping when estimated value of
the next retrieval is no greater than its cost or when an explicit sufficiency
predicate is met. The system records requested, returned, resident-at-dependent-edit,
used, marginal gain, stopping reason, question, and task outcome. It must demonstrate
that redundant high-similarity facts do not crowd out a distinct high-distortion
constraint and that adding the same fact to a warm working set has near-zero marginal
value.

The implementation may use an explicit, inspectable approximation to VOI; it may not
claim calibrated causal VOI without the experiment. Query logs are the future
compiler specification; repo-wide precompression is outside this proof.

### P-8 — Company architecture referenced from Codebase

A `.kin/` Codebase fact may refer to a Company fact by stable fact ID, semantic
digest/version, authority, validity, and Company-owned criticality, with a typed
relationship such as `applies`, `specializes`, `implements`, `contradicts`, or
`exception_request`. A separate maintainer-owned local dependence class records what
losing the reference costs this repository; projection applies the stricter class.
The reference does not copy Company prose or grant Company authority. Resolution
uses the current authorized Company view and distinguishes changed Company content,
client canonicalization failure, and Company unavailability instead of assigning all
digest mismatches to the steward.

Only a Company steward can authorize an exception to Company architecture. A
Codebase maintainer or Factory role may request one but cannot mint it. The proof
includes a global architectural rule, a repo specialization, a contradiction, and
an approved Company exception, and verifies their behavior from a fresh clone.

### P-9 — ordinary Codex and Claude lifecycle

Codex and Claude use a shared data-only lifecycle:

`session-start -> observe -> propose -> approve/reject -> project -> record-use -> session-end`

Fresh sessions discover the repository root and `.kin/`, resolve Company access from
an out-of-repo user configuration, prime authorized Codebase+Company context, and
surface one actionable permission/installation prompt if required. Neither silently
installs or bypasses host hook approval. Both continue observing during the session,
create questions when needed, and flush approved/codebase-germane notes before end or
compaction. Host framing may differ; canonical facts, decisions, and receipts may not.

Acceptance runs real Codex and Claude hook/adapter entry points in isolated temporary
homes, verifies fresh-start priming and end/compact capture, and proves identical
semantic payloads for matched conversations. A mocked host-name switch does not pass.

Approval fatigue is product-critical. In the proof workload, the system may surface
at most four total reserved shared-destination approval opportunities per composite
`(principal_id, host_instance_id)` budget shard in
a sliding 60-minute window and no more than three consecutively without returning the
user to their primary task. Destinations share that four-slot ceiling and may have
stricter sublimits; two concurrent Codex/Claude sessions on the same host instance
share the serialized shard. The host instance owns and signs its shard observation,
and `doctor` shows consumed/reserved counts plus an explicit warning that no global
cross-machine total is known. The proof makes no cross-machine prompt-budget claim. A
20-item blinded operator exercise must achieve at least 95% correct approve/reject
decisions with median decision time at most 30 seconds. Exceeding the prompt ceiling
suppresses new shared prompts until the sliding window clears; a reset clears only
the consecutive counter after a new task event and never the hourly ceiling. Pending
ideas remain private until candidate expiry and can be regenerated later only under
the bounded content/source-change rules. Reserved/rendered/suppressed/delivery-loss
rates are reported. The system never reveals an accept-all path. Failing either
usability bound is `NOT_PROVEN` even if routing and privacy tests pass.

The fatigue control may not starve useful maintenance. In a preregistered 100-
observation workload with 20 independently gold-labeled durable shared facts, the
distortion/authority queue must place at least 18 of those facts into a human decision
slot within five simulated sliding-hour windows, admit at least 17 correct facts after
decisions, and surface no more than four total prompts in any window. Low-authority
source churn and byte-only reissues cannot displace a higher-distortion eligible fact.
Failing this corpus-growth adequacy gate is `NOT_PROVEN`.

### P-10 — material brownfield outcome improvement

The preregistered evaluation uses held-out, nontrivial historical brownfield tasks
from at least two real repositories. Each task binds disparate versioned evidence, a
held-out functional oracle, an architecture/constraint rubric, and authoritative
pre-change decisions. Accepted patches and hidden tests may establish the judging
oracle but are excluded from every agent context, including the fully informed arm.

At least twelve excluded pilot tasks spanning at least three repositories, with at
least three seeds each, estimate task-by-arm covariance, within-task/model variance,
and fully loaded cost. Before any pilot outcome is visible, the founder ratifies a
hard aggregate call/token/dollar ceiling and the rule that it cannot be raised for
this run. Pilot effect estimates stay sealed; only cost and conservative variance/
covariance feed the fixed power calculation. The harness then freezes the power-
derived task/seed count and minimum detectable effects.
The pilot must also place the lower 95% bound of `oracle-spec` quality at or above
0.90. Failure stops before measurement as `INCONCLUSIVE_CEILING`; it may trigger a
new founder-ratified comparator design, never task filtering or predicate tightening
against observed scores.

The Oracle Curator receives a date-bounded census of every merged change in the two
declared repositories and no Kinbase schema, retrieval design, candidate, or arm
output. A ratified program applies the structural pre-outcome predicate using only
repository history: the change has a reproducible parent revision, issue/request,
held-out post-change functional oracle, at least three pre-change evidence classes,
and at least two independently owned pre-change sources containing nonredundant
load-bearing facts absent from the issue/direct edit surface, each of whose removal
flips a frozen counterfactual judge. No single pre-change artifact may specify the
complete fact-only oracle or solution; `SINGLE_ARTIFACT_SPEC` is a published exclusion
code, not a result-dependent judgment. The Curator publishes
the full examined/eligible/excluded census with reason codes, extracts each eligible
task's neutral fact-only oracle and load-bearing labels, and seals them before any
pilot or candidate execution. Every oracle sentence must cite a pre-change source;
no accepted-patch line, solution step, hidden-test assertion, or identifier introduced
only by the change may appear. The accepted change is judging evidence, never agent
context. No Kinbase result or baseline score controls eligibility.

Task-conditioned corpus curation is forbidden. Only after V-1 through V-9 pass and the
adapter/reducer digest freezes, but before the Oracle Curator receives
eligibility inputs or the public task seed is drawn, a schema-blind Corpus Builder
runs the frozen adapters/reducer over every candidate parent revision in the complete
date-bounded census, using only sources that existed by that revision, and seals the
content-addressed Company/Codebase snapshot map. The Builder sees no issues, accepted
patches, hidden tests, eligibility labels, load-bearing labels, arm outputs, or scores.
The task-independent static-prior control is also frozen at this point. A corpus or
prior authored, pruned, or regenerated after task knowledge exists is evaluation
contamination and makes the run `INVALID_RUN`.
An adapter/reducer defect found before the Builder learns task material discards the
entire snapshot map and reruns every census parent under the new digest. If the Builder
or replacement has learned issues, labels, draw, or outcomes, recovery requires a new
run with a fresh blind Builder; it cannot selectively reseal drawn tasks.

After the eligible census is frozen, the harness draws tasks without replacement by
a preregistered public seed. The floor is eight eligible tasks from at least two
repositories and three measurement seeds per arm; it is not a claim that eight is
powered. The task is the analysis unit and seeds are averaged within task. The
conservative fixed simulation uses upper 90% variance/covariance bounds and freezes
the maximum N required for at least 80% power on every co-primary quality, baseline/
null/static/store-ablation lift, top-k superiority, oracle equivalence, residency,
authorization-restricted-stratum quality/lift/equivalence, and false-completion gate,
plus at least 80% expected joint pass probability. If the
population, power, or founder-
ratified budget cannot supply that N, no measurement arm dispatches and the run is
terminal `NOT_PROVEN` with `UNFUNDED_OR_UNDERPOWERED` diagnostic, never a smaller or
partial claimed proof. Task and arm artifacts are frozen before outcomes are
inspected.

For the same coding model, settings, repository commit, issue text, tools,
wall/tool/token budget, frozen `as_of`, Company authority cursor, authority-answer
service, and measurement seeds, compare:

- `baseline`: issue plus ordinary repository tools;
- `null-system`: the full Kinbase host adapter, hooks, observation path, tool schema,
  permission policy, timing envelope, and telemetry, but an empty corpus and selector;
  projection returns no facts and the authority endpoint returns only the typed
  `NO_KNOWLEDGE_AVAILABLE` result. It is the control for benefit caused by integration
  scaffolding rather than knowledge;
- `static-prior`: baseline plus one task-independent, repository-agnostic conventions
  document of at most 2 KiB, frozen before task eligibility or draw, with no stores,
  retrieval, maintenance, temporal reduction, or authority loop;
- `distractor`: token-matched irrelevant same-repository evidence, retained as the
  context-volume falsifier but not a competent-retrieval comparator;
- `topk-raw`: token-matched plausibly relevant raw chunks from ordinary repo search;
- `topk-maintained`: the same maintained fact corpus as the full system, selected by
  independent scalar similarity/relevance without set, temporal, or authority logic;
- `authority-only`: baseline context with no maintained corpus or projector, required
  to consult the identical frozen authority-answer service for the preregistered one
  or two fact-only questions for that task;
- `codebase-only`: full-system machinery with Company facts, Company references, and
  authority answers withheld, leaving only admitted Codebase facts;
- `company-only`: full-system machinery with Codebase facts withheld, leaving admitted
  Company facts and frozen authority answers;
- `full-system`: maintained corpus, Unknown/question loop, and decision-conditional
  set selector;
- `oracle-spec`: exactly the preregistered load-bearing pre-change authoritative
  facts, rendered without answer prose, accepted patch, or hidden tests.

The `oracle-spec` and `authority-only` bytes count against the same context budget.
No live person participates in V-10: the schema-blind Oracle Curator freezes the
pre-change signed authority answers before candidates, and every arm sees the same
tool schema, latency envelope, and per-call cost. Eligible arms reach the frozen
service; `null-system` receives the frozen empty result. The full system may ask at
most two fact-only questions per task and receives no code, patch, or hidden-test
advice. Question count, reply tokens, and outcome contribution are reported; the
service refuses the third call. The separate V-6 execution proves the live-human
round trip.

After the measurement manifest freezes, no new human-authored byte may enter any arm
prompt, tool response, policy, candidate, or score input. The harness records a
`human_bytes_after_freeze` endpoint whose required value is zero. The prerecorded
authority instrument is not an exception: its exact bytes already belong to the
frozen manifest. Launch controls use closed reason codes and cannot carry operator
annotations. Any post-freeze human byte is `INVALID_RUN`.

Candidate trees are frozen, content-addressed, assigned opaque random IDs, and scored
before arm identity is revealed. Non-mechanical rubric levels are ordinal 0–4 and use
quadratic-weighted Cohen's kappa. Two implementation-blind human domain annotators
first seal gold labels on an excluded calibration set with kappa at least 0.80. Both
measurement scorers are automated graders from different model families/providers;
each must reach kappa at least 0.80 and pass-boundary accuracy at least 0.90 against
that gold. Their immutable model fingerprints, decoding settings, system/rubric
prompts, parsers, and calibration-set digest are frozen in the experiment manifest.
They then seal two independent measurement scores; reliability is
computed before unblinding. Kappa below 0.80 makes the harness invalid in either
direction, and a qualitative component whose scores straddle a pass boundary uses
the lower score rather than favorable adjudication. The Validator—not the coding
agent—runs hidden tests and records functional success, architecture conformance,
invariant preservation, internal-API reuse, duplication, false completion,
tools/tokens/cost, authority calls, constraint presence, edit-time residency,
resident precision, and working-set size.

Before arm unblinding, each scorer also receives the eleven neutral arm definitions
and seals one guessed arm per candidate plus confidence. Accuracy above both chance
(1/11) by 0.15 and an exact-binomial p<0.05 makes subjective blinding compromised and
the run invalid; scorer agreement never cures correlated arm inference. Mechanical
hidden-test observations remain separately reported but cannot alone rescue the
architecture-quality claim.
Each scorer also guesses the binary fact-bearing/non-fact-bearing family; balanced accuracy
above 0.65 with exact-binomial p<0.05 independently invalidates subjective blinding.

The pilot freezes the co-primary power calculation specified in Verification within
the ratified aggregate budget. The primary aggregation first means each
arm over measurement seeds within task, then means paired task differences. The
lower 95% bound must clear absolute-quality and positive-improvement thresholds; the
entire 95% interval on `oracle-spec - full-system` must lie within the equivalence
band [-0.05, 0.05]. Per-task values and the fraction with positive lift remain
visible.

All eleven arms are randomized and interleaved by task/seed block. Every task/seed
block uses one frozen `as_of` and Company authority cursor across all arms. The
content-addressed arm manifest binds the model artifact/snapshot, decoding settings,
system prompt, tool schema and permissions, policy bundle, host adapter, retriever,
index and corpus snapshots, task inputs, worktree commit, `as_of`, authority cursor
and replies, budgets, and seed, plus both automated graders' model fingerprints,
decoding settings, prompts, parsers, calibration set, blinded-packet schema, gold-
annotator identities/receipts, and adjudicated gold digest. One
differing unbound field or runtime drift is
`INVALID_RUN`; it cannot be explained away after unblinding. Proof measurement
requires an immutable local/open-weight artifact digest or a provider-guaranteed
immutable snapshot fingerprint for the entire run; a stable marketing model name is
insufficient. Every response records the observed digest/fingerprint. A mismatched
attestation found before admission may consume only a preregistered replacement
reserve; drift detected after a prompt/model request is admitted invalidates the run
and cannot replace that outcome. Reserve count is frozen at 10% of planned blocks
(rounded up); exhaustion makes the run `INVALID_RUN`. A provider without an immutable
fingerprint may be used for excluded pilots but cannot support the terminal proof
claim.

The concept is proven only if, over eligible measurement tasks:

- `oracle-spec` composite is at least 0.90, establishing an adequate ceiling;
- `full-system` composite is at least 0.90 and no more than 0.05 below `oracle-spec`;
- `full-system` closes at least 70% of the paired `oracle-spec - baseline` quality
  gap and improves over baseline by at least 0.15 absolute;
- `full-system` improves over `null-system` by at least 0.15 absolute, proving that
  maintained knowledge rather than host/hook scaffolding caused the gain;
- `full-system` beats `static-prior` by at least 0.10 absolute, proving that a single
  generic conventions injection does not explain the result;
- `full-system` beats both `topk-raw` and `topk-maintained` by at least 0.10 absolute;
- on the preregistered Company-unique and Codebase-unique task strata respectively,
  `full-system` beats `codebase-only` and `company-only` by at least 0.10 absolute;
- at least 80% of dependent edits have the load-bearing fact resident at a mean of
  at most 12 facts per projection and resident precision of at least 0.25;
- false-completion rate is no worse than `oracle-spec` plus 0.05;
- P-2 and P-3 routing/privacy gates pass with zero observed critical disclosures in
  the frozen census under the qualified digest-identified threat model.

`authority-only` is a mechanism-attribution control, not a hidden success gate. If it
matches `full-system` within 0.05, a passing report must say that direct
authority consultation, not the maintained corpus, explains the measured gain; if
the full system matches its quality with fewer authority calls, that efficiency is
reported but cannot be renamed a corpus-selection effect.

`null-system` is a co-primary falsifier, not a diagnostic footnote. If it matches the
full system closely enough that the lower 95% paired bound does not clear 0.15, the
concept is `NOT_PROVEN` even when both beat baseline: the result is attributable to
the integration/harness shape rather than maintained knowledge.

The two store-ablation arms are co-primary contribution tests. The drawn task set is
stratified by pre-change source lineage so at least one third has a load-bearing
Company fact unavailable from Codebase, at least one third has a load-bearing Codebase
fact unavailable from Company, and at least one task requires complementary facts
from both. Failure of the relevant paired 0.10 gate means the claimed two-store coding
composition is `NOT_PROVEN`. Personal has no coding-query ablation because exposing it
to a coding arm would violate P-3; its capture, retention, classification, and approved
promotion contribution are proven separately by P-1 through P-3 and P-9.

Every task binds a realistic least-privilege evaluation principal and exact Company
authority scopes before outcomes; administrative or broad service-reader identities
are forbidden. At least one third of selected tasks form an authorization-restricted
stratum where 20–40% of otherwise eligible Company facts are denied by count and byte
volume, and at least one load-bearing fact is initially denied but resolvable only by
that task's frozen scoped-authority answer path. Denial density, refused IDs, question
path, and authorized result are recorded without exposing denied prose. On that
stratum, `full-system` must independently reach 0.90, remain oracle-equivalent, and
clear the 0.15 baseline/null lifts. Otherwise the safe ACL-enforced operating mode is
`NOT_PROVEN` even if an open-access stratum passes.

Result entry is mechanical. `INCONCLUSIVE_NO_HEADROOM` applies only when the aggregate
baseline mean is greater than 0.85, making the required 0.15 absolute lift
mathematically impossible on the bounded [0,1] composite; no task is excluded.
`INCONCLUSIVE_CEILING` applies when `oracle-spec` is below 0.90 or when the lower 95%
bound on `full-system - oracle-spec` exceeds 0.05, showing the supposed ceiling is not
a valid ceiling. Mechanical contamination between judging-only oracle/test artifacts
and candidate context is `INVALID_RUN`; an actual Personal/sensitive disclosure is a
P-3 product failure and therefore `NOT_PROVEN`, never a chance to reroll.
Every other confidence interval crossing a threshold is `NOT_PROVEN`, not a license
to tune. One superseding run is allowed only for a documented pre-unblinding harness
defect, the same pool, and preregistered reserve seeds, and requires founder approval;
the failed run remains. Disappointing product results do not authorize task,
threshold, prompt, or seed changes. The report publishes negative and inconclusive
results and all exclusions.

Before unblinding, a fresh outcome-blind Run Integrity Auditor sees only the manifest,
launch ledger, environment attestations, and integrity telemetry and seals every
manifest-derived invalidity decision. It cannot see candidates, scores, arm mapping,
or aggregates. An invalidity claim first raised after outcome access cannot remove an
admitted launch, change a denominator, or authorize replacement.

The 70% oracle-gap-closure quantity remains a required descriptive bound but is not
presented as independent corroboration: given the 0.15 baseline lift and 0.05 oracle
equivalence gates it is arithmetically redundant. Removing that double-count prevents
the report from inflating the number of independent hurdles.

Every invocation that can generate or score a candidate against a ratified
measurement task/seed appends a signed run-census record before launch. It consumes
that scheduled seed and is part of the reported run; “smoke,” “debug,” or “harness
validation” is not an exemption. Harness development uses synthetic or excluded
pilot tasks only. Analysis is intention-to-treat: after an arm launch is admitted,
timeouts, model/agent errors, degraded or empty projections, fail-closed revocation,
tool failures, and missing patches stay in the denominator under the frozen failure
scoring rule; a missing candidate scores zero composite, and a declared-done failure
also counts as false completion. Only a preregistered infrastructure defect detected
before the prompt/model request crosses the launch gate may consume a reserve. No
post-admission result is dropped or replaced. The final report contains the complete
execution census.

The exact claim licensed by `PROVEN` is: “On the digest-identified task population,
repositories, model/provider fingerprint, budgets, authority service, and finite
threat model in this run, Kinbase met P-1 through P-9 and raised blinded brownfield
quality to the preregistered P-10 equivalence band.” It does not license the
unqualified statements “Kindex works,” “privacy is proved,” or “all brownfield coding
reaches greenfield quality.”

`NOT_PROVEN` rejects Kinbase's current product/value thesis and sends any mechanism
redesign back to the founder. It does not reopen the independently ratified safety
rule that Personal, Company, and Codebase must remain physically distinct. P-10
tests this complete design's causal usefulness, not the unsafe unified-store
alternative.

## Nice-to-haves intentionally absent

The proof need not include a web UI, mobile UI, multi-region deployment, production
SSO/SCIM, billing, enterprise tenancy, arbitrary scale, every source provider,
automatic merge/promotion, learned causal VOI, or a corpus compiler. It must expose
clean interfaces for them. These omissions may affect polish and deployment; none
removes a required behavior P-1 through P-10.

## Terminal falsifiers

The proof fails on any of the following: a required source class is only a stub;
corpus maintenance is an append-only demo; recency alone selects direction; a
load-bearing Unknown is guessed instead of addressed to authority; Codebase grants
itself a Company exception; Personal/sensitive data reaches a shared surface; a host
adapter is mocked rather than executed; selection is scalar top-k under another
name; the brownfield comparison is unmatched or self-judged; green tests are reported
as the proof; or P-10 misses its preregistered thresholds.
