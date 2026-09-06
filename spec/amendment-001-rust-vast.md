# Candidate Amendment 001 — Rust implementation and self-hosted GLM-5.3 Coder

Status: **candidate; not authority; no Coder dispatch permitted from these bytes**

This is an append-only amendment candidate to manifest
`ac8a13d184397fef574e173b81466ff43e6b3f91f89804c7ee797cc404a622db`.
It supersedes only the clauses named below. Every Product behavior, threat,
failure disposition, proof gate, role boundary, and source statement not named
here remains byte-for-byte binding. Ratification creates a new run generation;
it does not rewrite the original manifest or retroactively admit any artifact.

## 0. Stakes

**Expensive-to-revert**, with an **irreversible disclosure edge**. Replacing the
implementation language and Coder runtime is recoverable only through a new build,
new independent evidence, and coordinated reratification. Once a repository byte
is transmitted to a marketplace host, that disclosure cannot be proven erased even
if the instance is destroyed. Therefore public model staging may precede
ratification, but no byte sourced from the Guildhall repository, its
specifications, its lane artifacts, a Personal/Company/Codebase store, a test or
oracle, a secret, or customer data may reach the Vast host before this amendment
is exactly ratified. Synthetic probe text and generic Codex harness metadata are
the only pre-ratification request content allowed.

The founder previously classified the three-store physical-boundary decision as a
Type 1, expensive-to-revert decision because clone leakage cannot be reliably
erased. This amendment retains that classification and treats external transmission
as the harder irreversible edge.

## 1. Problem statement

The ratified design names Python 3.12 and an Ollama-hosted GLM-5.3 Coder. The
Ollama route repeatedly replayed an approximately 200K-token context without
reported cache hits, exhausted purchased usage, and terminated seven times without
an admissible Coder commit. The current 29-module, 9,378-line Python tree remains
uncommitted and unadmitted. The founder selected Rust as the desired product
implementation and authorized a Vast-hosted GLM-5.3 route so the proof can complete
without preserving Python or the failed provider merely because work already exists.

## 2. Proposed approach

### 2.1 Product implementation

Replace the first sentence of `spec/architecture.md` section 1 with:

> The implementation is a Rust 1.98.1 workspace, edition 2024, producing one
> `guildhall` CLI binary and its local loopback HTTP service. It uses one canonical
> event/projection protocol but never one universal graph.

The workspace is deliberately one deployable package with internal modules, not a
service or crate per noun. It preserves the ratified process and capability
boundaries:

- distinct, non-convertible `PersonalStore`, `CompanyStore`, and `CodebaseStore`
  handles; no universal store handle and no audience-selecting open operation;
- the host process owns Personal capture and launches shared projection/publication
  as a separately sandboxed child mode with only staged minimum capabilities;
- the Company loopback service owns Company admission and its SQLite transaction;
- Codebase writes remain repository-owned content-addressed `.kin/` events,
  manifests, journals, and receipts under the Git common-directory lock;
- Kindex integration remains through public CLI/library contracts, never direct
  writes to Kindex SQLite internals;
- the existing CLI names, JSON envelopes, error codes, exit codes, and observable
  Product behavior remain unchanged unless this amendment explicitly says otherwise.

The implementation pins Rust with `rust-toolchain.toml`, sets
`#![forbid(unsafe_code)]` in first-party crates, and records a locked dependency
graph. SQLite, Ed25519, SHA-256, canonical serialization, filesystem locking,
loopback HTTP, and CLI parsing use maintained Rust crates behind Guildhall-owned
interfaces so dependency choice cannot redefine a protocol or trust boundary.
Production paths contain no Python interpreter or Python package dependency.

Replace `spec/verification.md`'s Python-package nonfunctional gate with:

> The pinned Rust workspace builds from a clean environment with `--locked`; the
> release binary and every command have bounded help. Formatting, Clippy with
> warnings denied, unit/integration tests, dependency-license policy, vulnerability
> audit, and first-party unsafe-code denial are recorded. The final artifact records
> its source commit, Cargo.lock digest, compiler version, target, and binary digest.

### 2.2 Coder model and harness

Replace the Coder role line in `spec/verification.md` with:

> **Coder (GLM-5.3, official open-weight FP8 checkpoint, through a local Codex
> harness and a Vast-hosted vLLM Responses endpoint):** reads the newly ratified
> product, architecture, threat model, verification strategy, this amendment, and
> its build lane; authors Rust implementation and implementation docs only; cannot
> read Tester work or judge success.

The exact initial runtime is:

- model repository `zai-org/GLM-5.3` at Git revision
  `aca966e4e02791568aa6a4ced368624b3d897f42`;
- official native-FP8 model files (approximately 755.7 GB), with the resolved
  Hugging Face LFS pointer/object manifest retained as the immutable artifact
  receipt;
- `vllm/vllm-openai:v0.28.0`, manifest digest
  `sha256:61fc8a896b0a4fbbbdc063bc4b0dbc25ce98e02b5050c24aeb7830ac02039b14`;
- one verified 8xH200 Vast instance, exact instance/machine/driver/GPU facts bound
  in the launch receipt rather than this reusable architecture amendment;
- tensor parallel size 8, 262,144-token maximum context, one logical Coder request
  stream, prefix caching enabled with SHA-256/CBOR keys, GLM-4.7 tool parser, and
  GLM-4.5 reasoning parser;
- BF16 KV cache on H200 unless a synthetic pre-dispatch capacity probe proves it
  cannot sustain the bound context. Any FP8-KV fallback is a separately recorded
  configuration change because it may alter quality;
- local Codex tool execution in the isolated Coder repository. The Vast host runs
  inference only and receives no repository clone, filesystem mount, credentials,
  tests, Kindex graph, or coordination channel;
- the inference API is reachable only through a local SSH tunnel. No inference port
  is publicly mapped; request-body and access logging are disabled.
- recovery state remains local: the real Coder run is a non-ephemeral Codex thread,
  and both its native session journal and every completed operator-facing Codex JSON
  event are `fsync`ed on the workstation before the event is forwarded to the
  operator console. The final response, thread ID, current Git HEAD, and worktree
  status digest are also recorded locally. The Coder
  makes a local Git checkpoint after each independently coherent implementation
  slice and never carries more than fifteen minutes of material changed state
  without a checkpoint. On endpoint loss, the Validator restores the same pinned
  serving configuration and resumes the same local Codex thread. At most the
  in-flight model generation may be lost;
- vLLM prefix caching remains enabled for efficiency, but it is volatile GPU state,
  is neither a result journal nor recovery evidence, and may disappear with the
  instance. No repository-bearing prompt, response, or result cache is persisted on
  the Vast host.

The old Python tree may be read only by the new GLM-5.3 Coder as same-role,
unadmitted historical work. It is not authority, not evidence of conformance, and
must not be present in the candidate product commit except as explicitly labeled
historical evidence outside the production package. The new run must say
`GLM-5.3 composite execution: Ollama/Python attempt -> Vast/Rust attempt`; it may not
claim one uninterrupted thread or one unchanged runtime.

### 2.3 Orchestration and independent testing

Agy remains the resident non-authoring Orchestrator with only `block` and `no-op`
effects. Codex root remains Validator. Claude remains the implementation-blind
Tester. No Tester file, finding, assertion, fixture, or hidden expectation enters the
Coder prompt or repository. The Tester may receive this ratified amendment and adapt
only language-dependent build/launch plumbing while remaining blind to Rust code;
all behavioral expectations remain sourced from the ratified Product and
Architecture. A fresh Detector Review is still required before combination.

### 2.4 Provider and custody boundary

Add to `spec/threat-model.md`'s model-provider boundary:

> For the amended Coder generation, Vast.ai account 413964 and the exact launch-
> receipt host are the named model-compute processor for only the Coder projection
> of the synthetic Guildhall proving repository. The host operator can technically
> access host files and memory; container isolation is not a confidentiality proof.
> Personal-store history, Company bodies, customer data, credentials, test/oracle
> bytes, and unrelated repositories remain prohibited. Codex runs locally and sends
> only its prompt plus selected Coder-lane tool results through an encrypted SSH
> tunnel. vLLM request/access logging is disabled. The host stores public model
> artifacts only. On completion or abandonment, the instance is destroyed rather
> than merely stopped; the destroy receipt is retained. Vast's deletion assertion is
> operational evidence, not proof that a provider never retained bytes.

### 2.5 Budget and lifecycle

The founder authorized USD 300 of available Vast credit for this route. The initial
instance rate, including 1 TB temporary container storage, is at most USD 34.01 per
hour. The Validator warns the founder no later than USD 210 consumed, and must stop
new Coder turns at USD 285 consumed unless the founder explicitly raises the ceiling.
Public-weight download, runtime smoke tests, and failed admitted Coder turns count
against the ceiling. Stopping preserves chargeable storage; terminal cleanup destroys
the instance and retains only local launch, model-manifest, usage, and destruction
receipts.

## 3. Failure modes

1. The 755.7 GB checkpoint or image does not finish staging, the host disappears, or
   an H200 fails. No Coder dispatch occurs; preserve the infrastructure receipt and
   select a replacement only under the same pinned artifact/runtime class.
2. vLLM's Responses or tool-call behavior is not compatible with the local Codex
   harness. A synthetic, repository-free tool round trip must fail before dispatch;
   changing harnesses requires a reviewed binding update.
3. BF16 KV cache cannot hold 262K context. The pre-dispatch capacity probe fails;
   FP8 KV is not silently substituted.
4. Rust translation preserves shapes but drops behavior, recreates one universal
   store, weakens canonical bytes, or treats type safety as authority. Existing
   behavior/security gates remain unchanged and independently decide the artifact.
5. The Tester instrument embeds Python-specific implementation knowledge. The
   instrument is amended implementation-blind from this authority or rejected; the
   Coder never receives the failing detail.
6. The Rust build spends the remaining credit before a commit. The Coder must make
   small coherent local commits/checkpoints; the Validator stops new turns at the
   ceiling and reports incomplete work rather than purchasing or claiming success.
7. Non-synthetic or repository-derived prompt/tool output reaches the unratified
   host, any request reaches a public inference port, or repository-bearing request
   content reaches provider logs or host storage. This is negative V-3 evidence and
   blocks the run; later deletion cannot retroactively authorize it.
8. The old Python artifact contaminates attribution or remains in the shipped
   product. The candidate is rejected until provenance and production footprint are
   exact.
9. A Vast or tunnel failure loses completed Coder events or forces a fresh thread
   whose prior work must be reconstructed from memory. Dispatch is blocked unless a
   synthetic interruption proves that completed tool/results events survive locally
   and the same thread resumes after the endpoint returns.

## 4. Constraints

- All P-1 through P-10 behavior, V-1 through V-10 verification, threat catalog,
  source authority, exact error dispositions, and privacy boundaries remain binding.
- Rust and Vast do not reduce scope; the proof must still do the complete thing.
- No repository byte reaches Vast before exact founder and Validator ratification.
- Model revision, image digest, launch parameters, provider/account, spend, and
  response fingerprints are immutable run inputs.
- Agy remains resident and non-authoring; Coder, Tester, and Validator roles remain
  separated.
- The Rust Coder cannot read tests or Tester findings. The Tester cannot read Rust
  implementation.
- Local tool execution and all writes remain in the isolated Coder repository.
- No Personal or customer data may be used in infrastructure or compatibility
  probes.
- Completed Coder events and coherent worktree progress must survive model-host or
  tunnel loss without any remote prompt/result persistence.
- A passing build, translation completion, or model-server health check is not a
  product or proof milestone.

## 5. Assumptions

1. **Load-bearing:** the pinned FP8 checkpoint on 8xH200 can sustain one 262K-context
   Coder stream with BF16 KV cache.
2. **Load-bearing:** vLLM 0.28.0's Responses API and GLM tool parser support the
   Codex tool loop without corrupting tool calls or reasoning messages.
3. **Load-bearing:** the remaining USD 300 ceiling is enough to stage, qualify, and
   produce a coherent Rust candidate. Failure is an honest capacity result, not
   permission to change the model or omit functionality.
4. **Load-bearing:** the Tester suite's behavioral oracle can be made language-neutral
   without reading implementation; otherwise independent comparison requires a fresh
   Tester generation.
5. The old Python product is useful same-role translation evidence but carries no
   hidden Tester information and no authority beyond the specs.
6. Vast's destroy operation removes the instance's container storage as documented;
   this is not treated as a guarantee about host memory, telemetry, or operator
   access.

Assumptions 1 and 2 are resolved with public/synthetic probes before repository
transmission. Assumption 4 is resolved by Validator/Detector inspection without
showing results to the Coder. Assumption 3 remains a measured run constraint.

## 6. Limitations

- Rust does not prove memory safety of dependencies, policy correctness, privacy,
  or product value. It narrows first-party memory-unsafety and deployment variance.
- A verified Vast host is still a third-party marketplace custody boundary; this
  amendment does not claim confidential-computing, remote attestation, or host-
  operator exclusion.
- The 262K Coder context is below the model's advertised maximum. The proof needs a
  coherent build, not a maximum-context serving benchmark.
- No production data migration exists because no Python Guildhall product or user
  corpus has been admitted. Migration tooling remains outside this amendment.
- Existing Tester rights-grant and Detector-Review blockers remain; Rust/Vast does
  not waive them.

## 7. Alternatives considered

1. Continue Python through Ollama: rejected because it preserves an undesired
   implementation and repeats the measured uncached-cost/payment failure.
2. Keep Python but self-host GLM-5.3: rejected because provider cost was not the
   founder's only change; Rust is the selected product direction.
3. Use an experimental NVFP4/GGUF quantization on cheaper GPUs: rejected for the
   first proof because it changes model fidelity and introduces another uncalibrated
   variable. The official native-FP8 checkpoint on supported 8xH200 hardware is the
   reference route.
4. Run a different Coder model: rejected because GLM-5.3 remains an explicit role
   requirement and cross-family substitution would change the proof claim.
5. Clone the repository onto Vast and run the whole agent remotely: rejected because
   it expands provider custody from selected prompt/tool bytes to the entire repo,
   credentials, tools, and durable working state.
6. Rewrite the old manifest/spec files in place: rejected because append-only
   supersession preserves what each prior artifact and receipt actually authorized.

## 8. Open questions and resolution gates

1. Does the synthetic Codex/vLLM tool-loop probe pass with exact streamed Responses
   semantics? Resolve before any repository prompt.
2. Does BF16 KV sustain the bound 262K context on this node? Resolve with a synthetic
   long-prefix probe; record memory and prefix-cache reuse.
3. Does the local journal retain each completed synthetic tool/result event across
   a forced tunnel interruption, and can Codex resume the same non-ephemeral thread
   after reconnection? Resolve before any repository prompt.
4. Can the existing Tester artifact remain behaviorally valid after only an
   implementation-blind launcher amendment? Resolve before its admission; otherwise
   dispatch a fresh Tester under the amended manifest.
5. Does the first Rust Coder checkpoint indicate that USD 300 is enough? Report
   elapsed time, remaining credit, and coherent capability coverage at the USD 210
   warning threshold; the founder alone may raise the ceiling.
6. The named-human auxiliary-corpus rights grant remains separately unresolved and
   still blocks Detector admission.

---

Per architecture-review protocol: if you identify a flaw, ground it in a cited
invariant, design principle, or worked example. Ungrounded assertions are not
adversarial review — they are disagreement. Enumerate distinct critiques as numbered
items so each can be resolved individually.
