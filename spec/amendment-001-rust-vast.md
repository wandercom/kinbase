# Candidate Amendment 001 — Rust implementation and self-hosted GLM-5.3 Coder

Status: **candidate; not authority; no Coder dispatch permitted from these bytes**

## Reader summary

This candidate makes four changes to one still-unproven Kinbase generation:

1. implement the complete P-1 through P-10 Product in Rust rather than Python;
2. run the isolated GLM-5.3 Coder through local Codex against the pinned Vast/vLLM
   processor rather than Ollama cloud;
3. add explicit custody, egress, recovery, checkpoint, and dollar controls for that
   processor; and
4. tighten the P-5/P-10 and V-5/V-10 falsifiers supplied during founder review so
   abstention, direct authority consultation, context volume, or a weak functional
   result cannot masquerade as maintained-corpus value.

It does **not** narrow P-1 through P-10 behavior, collapse the three physical stores,
reuse the old Tester, permit Coder access to tests, or turn an implementation commit
into proof. The Product-observable changes are the Rust executable/installation
surface, the explicit Linux-only external-classifier surface with fail-closed macOS
denial already implied by the base descriptor-execution rule, the harder P-5
substantive-answer behavior, and the expanded P-10 terminal claim criteria and
controls. Everything else is a Factory/runtime control or an unchanged obligation.

The gate dependency graph and evidence table are section 8. Before execution, the
Validator renders their exact stop conditions and ordered commands into a one-page
operator card, cross-checks every row against the final bundle, and binds its digest in
the run ledger; the card is derived procedure, not authority and cannot relax a gate.
Before authoring, the Validator materializes
and checks the effective authority bundle, the founder ratifies its exact digest with
this amendment's exact digest, and G-1 through G-4 pass. A Coder handoff is only G-6;
`PROVEN` remains possible only after G-11. Terms used here inherit
[`glossary.md`](glossary.md), except that the following four inline definitions are
the controlling amendment meanings if the supplement differs: a **lane** is one role's isolated
filesystem/process authority, a **run generation** is one immutable authority and
configuration binding, **admitted** means accepted by the named gate rather than
merely created, and a **positive control** is a deliberately forbidden input that
must be rejected for the detector to qualify. The pre-ratification G-1 semantic
receipt quotes those four glossary entries, states agreement or conflict, and treats
this bootstrap precedence as a founder-resolved residual rather than circular proof.

This is an append-only amendment candidate to the post-rename manifest
`12dd4c18aaca12c29cc816ca4a5161b5e011814f021879897b88b0e6e85168dd`.
It supersedes only the clauses named below. Every Product behavior, threat,
failure disposition, proof gate, role boundary, and source statement not named
here remains byte-for-byte binding. Ratification creates a new run generation;
it does not rewrite the original manifest or retroactively admit any artifact.

The base authority is the tuple of artifact digests already frozen by that manifest
and its founder and Validator receipts. Overlay operations are IDs `O-01` onward in
declaration order. An operation's quoted bytes are decoded mechanically by removing
exactly one leading `> ` from each nonblank blockquote line (and the sole `>` from a
blank quoted line), retaining every other byte and LF; no Unicode, whitespace,
newline, or Markdown normalization occurs. The amendment and every other bundle member must
be UTF-8 without BOM and contain LF only; any CR byte is a parse error. Every decoded
block has exactly one trailing LF because the materializer synthesizes it after the
last quoted line. Consequently every insertion anchor ends at a line boundary; a new
block beginning with content creates the immediately following line, while a leading
blank quoted line deliberately creates an extra LF. Each decoded **old** block or
**insert-after** anchor must occur exactly once in the raw UTF-8 bytes of the named,
manifest-bound **base** file. Matching never searches this amendment or the output
of an earlier operation. Declaration order assigns immutable ordinals;
materialization sorts all operations by `(raw write-start offset, declaration
ordinal)`. Same-offset insertions emit in ordinal order, while any same-offset
insertion/replacement mixture is rejected. A replacement advances the cursor to its
raw end; any later operation whose start is below that cursor—including an insertion
whose anchor end lies inside the replacement—is overlap and is rejected. Exactly
adjacent ranges are permitted and emit in this stated total order. Overlapping ranges,
a new block that would alter another operation's base range, or zero/multiple matches
is `AUTHORITY_MISMATCH:<operation-id>`.
An insertion writes its decoded new bytes at the anchor's end offset with no implicit
separator; any required blank line is the leading decoded `>` line visibly carried by
that new block. No operation searches or offsets against another operation's output.

Blockquote decoding is total: a line equal to `>` decodes to an empty line; a line
beginning with the exact bytes `> ` loses only those two bytes; every other line that
begins `>` is a parse error. A quoted line ending in SP or TAB is also a parse error.
Each declared heading must occur exactly once as a complete raw line in its named base
file, and each operation must resolve beneath that exact nearest preceding ATX heading;
the source block itself may contain no ATX heading line. A declared section extent is
the byte range from the end of that heading line to the start of the next ATX heading
of the same or higher level, or EOF. The complete source range must lie inside that
extent. Both receipts record the section start/end and the raw bytes immediately
before/after the write range. Path, heading, section containment, operation ID, or
heading-occurrence disagreement is
`AUTHORITY_MISMATCH:<operation-id>`:

| Operation | Base path | Exact containing heading |
|---|---|---|
| O-01 | spec/architecture.md | ## 1. One protocol, three bounded products |
| O-02 | spec/architecture.md | ## 1. One protocol, three bounded products |
| O-03 | spec/architecture.md | ## 4. Source adapter contract |
| O-04 | spec/verification.md | ## Nonfunctional proof gates |
| O-05 | spec/verification.md | ## Role separation |
| O-06 | spec/threat-model.md | ## Model-provider boundary |
| O-07 | spec/product.md | ### P-5 — appropriate recency and resistance to bad shifts |
| O-08 | spec/verification.md | ### V-5 — temporal discernment (`P-5`, Critical) |
| O-09 | spec/product.md | ### P-10 — material brownfield outcome improvement |
| O-10 | spec/product.md | ### P-10 — material brownfield outcome improvement |
| O-11 | spec/product.md | ### P-10 — material brownfield outcome improvement |
| O-12 | spec/verification.md | #### Task freeze |
| O-13 | spec/verification.md | #### Scoring and falsification |
| O-14 | spec/verification.md | #### Scoring and falsification |
| O-15 | spec/verification.md | ## Evidence packet |

The materializer records the resolved heading bytes, heading offset, and digest in
each operation receipt. It rejects any new block containing another operation's
complete old/anchor bytes, even though matching is base-only, so generated prose
cannot impersonate a second operation in the effective diff. After splicing, it also
recounts every operation's complete source bytes and containing-heading line across
the complete raw bytes of the entire effective artifact, including occurrences that
cross a splice seam. A replacement source must occur zero times, an
insertion anchor must occur exactly once, and every containing heading must still
occur exactly once. Both separately produced receipts record those post-materialization
counts; any other count is `AUTHORITY_MISMATCH:<operation-id>`. This proves the
current effective output did not shadow a declared anchor. It does not pretend to
predict or reserve prose that a future amendment may choose as a new anchor; that
future generation must repeat the same raw-base and post-materialization checks.

The base manifest omitted two Markdown-referenced operational artifacts. Ratification
of this amendment admits their exact current bytes as subordinate supplemental
authority; a digest mismatch is `AUTHORITY_MISMATCH`:

| Supplemental path | SHA-256 |
|---|---|
| spec/glossary.md | `af16a83f814de4c82c91097b59cbba3a07e14a29993aaab8e2338485f257b6cd` |
| spec/leak-runbook.md | `49399f892e7a5c3a6222133a3826c97538322ee4493a3f09bf3edc175352648e` |

The bundle members are the rows of this table; its derived row count is nine:

| Bundle member | Derivation |
|---|---|
| spec/source-request.md | manifest-bound effective base |
| spec/product.md | manifest-bound base plus overlays |
| spec/architecture.md | manifest-bound base plus overlays |
| spec/threat-model.md | manifest-bound base plus overlays |
| spec/verification.md | manifest-bound base plus overlays |
| spec/cli.md | manifest-bound effective base |
| spec/amendment-001-rust-vast.md | exact ratified amendment bytes |
| spec/glossary.md | digest-bound supplement |
| spec/leak-runbook.md | digest-bound supplement |

Both materializers independently scan the raw UTF-8 of every bundle document for every
non-overlapping occurrence of the literal regular expression
`]\(([^)#]+\.md)(?:#[^)]+)?\)`, including occurrences inside code fences or inline
code and blockquotes; there is no CommonMark interpretation step, and those raw
contexts are intentionally included because the amendment itself is a bundle member.
A local target's captured raw bytes must be NFC UTF-8, match
`[A-Za-z0-9._/-]+\.md`, contain no empty, `.` or `..` segment, percent escape,
backslash, absolute prefix, C0, or C1 byte, and then resolve by byte-concatenating the
referring document directory and those already validated segments. Filesystem
canonicalization is forbidden. The resulting path must be byte-equal to one bundle-
member path under `spec/`. Reference-style or autolink local `.md` links are
noncanonical and rejected rather than silently omitted from the census. Paths merely
named in backticks do not match and remain observations; an inline local Markdown link
outside `spec/` fails. External URL links are observations, not authority. Every fixed member is
scanned once; cycles add no work and no member, so no depth limit is needed. Both
receipts list the ordered link census. This is the mechanical transitive-authority
completeness check, not a claim about rendered Markdown semantics.

Before founder ratification, the Validator dry-runs the complete overlay and emits
an application receipt for every operation containing the base-file digest, raw byte
start/end, old/anchor span digest, new span digest, occurrence count, and declaration
ordinal. It materializes each complete effective base artifact once, includes these
exact amendment bytes plus the two digest-bound supplemental artifacts, and freezes
all nine in a
read-only, content-addressed candidate bundle. Authority paths must be at most 255
UTF-8 bytes, be NFC UTF-8,
match `spec/[A-Za-z0-9._/-]+`, contain no empty, `.` or `..` segment, and contain no
TAB, LF, CR, NUL, C0, or C1 byte. The bundle-root preimage is the exact bytes
`kinbase-authority-bundle-v1<LF>artifact-count<TAB><decimal-count><LF>` followed by rows
`authority-path<TAB>artifact-sha256<LF>` sorted by raw UTF-8 path bytes; its SHA-256
is the bundle root. Decimal count has no sign or leading zero and must equal the row
count; it must also equal the row count derived from the bundle-member table. The first materializer
structurally parses the amendment blocks, resolves unique raw anchors, and emits the
offset/hash plan. A structurally separate implementation independently parses these
amendment bytes, resolves every source span and containing heading against the raw
manifest-bound bases, constructs its own plan, and performs its own splice. Resolved
plans, complete bundles, and roots must be byte-equal. Agy separately reviews the
full effective diff, operation census, and at least 200 raw-base bytes on either side
of every resolved span, then reads the complete rendered effective Product,
Architecture, Threat Model, Verification, CLI, glossary, and leak runbook. A
Validator-authored semantic-delta receipt states for O-01 through O-15 what obligation
becomes harder, easier, or unchanged. The same receipt enumerates every glossary term
used as a load-bearing predicate by Product, Architecture, Threat Model, Verification,
or CLI and states whether its definition narrows, widens, or leaves the naive reading
unchanged; any narrowing/widening is quoted and dispositioned under precedence. It
also compares the complete glossary and leak runbook against every higher-precedence
obligation, not only digest/link collisions. Agy challenges that complete receipt and
binds its digest. It emits
a recorded `no-op` or `block` disposition bound to
the effective-diff digest; `no-op` means no intervention was required, not that Agy
owns or ratifies the design. The two programs may share a Validator author, so their
agreement falsifies inconsistent parsing/splicing but is not independent human
requirements interpretation. No mechanical control proves a semantically correct
requirement; Agy supplies adversarial review, and founder ratification after receiving
the rendered effective bundle and semantic receipt remains the human requirements
decision. Materializer plan/bundle inequality, absent Agy disposition, or Agy
`block` prevents ratification. The founder
ratifies the amendment digest **and** that bundle root; the Validator then ratifies
the same pair in a new content-addressed run binding. Downstream roles read only the
six materialized effective base artifacts, bundled amendment, glossary, and leak
runbook by digest;
reading a superseded base file or rerunning the overlay inside an author lane is
`AUTHORITY_MISMATCH`. The overlay remains derivation evidence, while the Validator-
owned materialized bundle is the single run authority.

Before either materializer can contribute to G-1, both pass the same frozen negative/
positive corpus covering `>`, `> >`, trailing SP/TAB, CRLF, lone CR, UTF-8 BOM,
NFC/NFD authority paths, empty/one-LF blocks, a source containing an ATX heading, a
source crossing its declared section extent, insertion boundary bytes, duplicate
headings, same-offset operations, adjacent and insertion-inside-replacement layouts,
splice-seam anchor reconstruction, canonical/`.`/`..`/percent/absolute link targets,
and local reference/autolink rejection. Expected bytes or rejection codes freeze in the
corpus before the final candidate receipt. Agreement is only parser/splice evidence;
the shared-author residual remains explicit and Agy/founder semantic review does not
inherit a mechanical `independent` label.

Authority precedence is source request, effective Product, effective Architecture,
effective Threat Model, effective Verification, effective CLI, amendment controls
that do not replace base text, supplemental leak runbook and glossary, then the
generated run manifest. Each explicit overlay
becomes part of its named effective artifact. The amendment's remaining controls may
add constraints but may never weaken a higher-precedence artifact; any contradiction
is `AUTHORITY_MISMATCH`. The final
candidate freeze point is the commit that contains this amendment, the overlay
receipt, the materialized candidate bundle, and review disposition. Its amendment
SHA-256 and effective bundle root are bound into every run and experiment manifest.

## 0. Stakes

**Expensive-to-revert**, with an **irreversible disclosure edge**. Replacing the
implementation language and Coder runtime is recoverable only through a new build,
new independent evidence, and coordinated reratification. Once a repository byte
is transmitted to a marketplace host, that disclosure cannot be proven erased even
if the instance is destroyed. Therefore public model staging may precede
ratification, but no byte sourced from the Kinbase repository, its
specifications, its lane artifacts, a Personal/Company/Codebase store, a test or
oracle, a secret, or customer data may reach the Vast host before this amendment
is exactly ratified. Only the exhaustive, byte-manifested synthetic probe envelope
defined below may cross before ratification.

The founder previously classified the three-store physical-boundary decision as a
Type 1, expensive-to-revert decision because clone leakage cannot be reliably
erased. This amendment retains that classification and treats external transmission
as the harder irreversible edge.

The already staged host is ineligible under the prospective egress proof, so the
route's sole funded cold-restart allowance is necessarily consumed by the required
pre-disclosure rehost. The first repository-bearing send therefore crosses the
irreversible specification-disclosure edge with **no post-disclosure restart
allowance**: one later host/provider/network preemption ends this funded attempt and
leaves only local unadmitted prior art. Founder ratification accepts that first-order
availability risk; only a separately funded and ratified allowance could change it.

Pre-ratification inference is allowed only from an isolated scratch directory with
no Kinbase ancestry, a fixed synthetic prompt and fixed synthetic tool schema
whose exact bytes are listed and digested in the qualification receipt, a scrubbed
environment, and no inherited repository descriptor. A local deny-by-default egress
proxy accepts only those digests while ratification state is absent. It records the
digest and byte count of every outbound body before forwarding, and a positive
control containing a locally generated forbidden marker must be denied. Failure to
establish the proxy, scratch sandbox, descriptor denial, complete local request
receipt, or positive control disables inference. "Generic harness metadata" is not
an allowlist.

This control is prospective and cannot retroactively qualify the synthetic probes
already sent to instance `50012413` before Q-0 existed. The local Codex transcript
preserves request-construction commands, but no trusted local component captured each
canonical wire body before transmission and the server's request-body logger was not
enabled. Provider-instance logs are not accepted as evidence about what the provider
received. The byte-complete census therefore cannot be produced: instance `50012413`
is permanently ineligible for repository-bearing traffic and must be destroyed before
a replacement is staged. G-3 records that deterministic disposition rather than
offering a later reconstruction escape. A fresh instance may be staged only after
Q-0 and its append-only request observer are active from the first network request.
Fresh-host staging consumes actual route budget and the existing restart allowance;
it does not create new money or inherit the old qualification pass.

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

In `spec/architecture.md` section 1 replace this exact old block:

> The implementation is a Python 3.12 package with a CLI and local HTTP service. It
> uses one canonical event/projection protocol but never one universal graph.

with this exact new block:

> The implementation is a Rust 1.98.1 workspace, edition 2024, producing one
> `kinbase` executable with CLI and local-loopback-service modes. It uses one
> canonical event/projection protocol but never one universal graph.

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
- Kindex integration remains through public CLI subprocess contracts, never direct
  writes to Kindex SQLite internals;
- the materialized CLI names, JSON envelopes, error codes, exit codes, and Product
  obligations remain authority unless this amendment explicitly changes them. No
  compatibility claim is made against the unadmitted Python tree.

"One executable" is a packaging property, not a collapsed trust domain. Personal,
shared projector/writer, Company service, external-classifier launcher, and
acceptance coding modes are separate OS processes with mode-specific configuration,
descriptor allowlists, filesystem policy, and startup denial probes. The parent
passes capabilities rather than store paths or a serializable all-store config.
Shared projection/publication retains the inherited macOS-sandbox or Linux-
Landlock/bubblewrap, descriptor-enumeration, close-on-exec, and startup-denial
obligations. External-classifier execution is narrower: it is a Linux-only Product
surface for this generation. Target-specific compilation must omit the external-
classifier module, command, configuration variant, and launcher from the macOS
artifact. The closed macOS schema rejects a manifest or invocation containing an
unknown field or subcommand with its one generic
`UNSUPPORTED_UNPROVEN_PLATFORM` disposition before classifier bytes, process creation,
or network access; the parser neither recognizes nor names the Linux-only classifier
input, and the shared generic error code does not introduce the omitted surface. G-9
supplies a hostile Linux-only input externally and requires that generic denial, not a
classifier-specific branch. macOS may use only an in-process deterministic
or replay classifier. A macOS Factory Coder sandbox is a separate build-time boundary
and cannot be cited as Product external-classifier evidence.

The executable's process/capability topology is normative:

| Process mode | Read capabilities | Write capabilities | Network |
|---|---|---|---|
| Personal host/capture | one Personal store; one-shot staged input/result descriptors | one Personal store; private session journal | no Company/Codebase endpoint |
| classifier launcher | one exact staged message/config descriptor | one exact result descriptor | only the manifest-authorized classifier processor, or none for local mode |
| shared projector | one approved staged-candidate descriptor; scoped policy/key material | one destination-neutral proposal descriptor | none |
| Company service/writer | one Company store and Company authority state | that same Company store only | authenticated loopback service only |
| Codebase writer | certified repository plus its Git-common-dir lock | that repository's reserved `.kin/` paths only | none |
| coding projector | one scoped Company view plus one certified Codebase view | private decision trace only; neither source store | authenticated Company read endpoint only |
| acceptance coding agent | its assigned benchmark worktree and admitted projection | its assigned candidate worktree only | its manifest-bound model/tool endpoints only |

No mode accepts a serialized path/config that can be converted into another row's
capability. The host transfers only already-open, allowlisted descriptors or an
authenticated narrow endpoint; startup rejects every additional inherited descriptor.

The falsifiable boundary is capability flow, not the absence of a component name.
Personal workers never hold a Company/Codebase destination write capability; shared
writers/projectors never hold a Personal path, descriptor, config, or handle; a
destination writer holds exactly one destination; the coding projector may hold only
scoped read capabilities for one Company view and one certified Codebase and cannot
write either. V-3 audits live descriptors/capabilities and runs marked-flow controls:
a Personal marker must never reach any shared byte; an unauthorized Company marker
must never reach `.kin/`; and a Codebase event must never mint/supersede a Company
fact. Those controls, non-convertible handle types, and denied cross-domain writes are
the proof of separation. A caller that reconstitutes universal read/write authority
fails even if no module is named "router."

All first-party Rust crates set `#![forbid(unsafe_code)]`. Maintained, version- and
checksum-pinned syscall crates may encapsulate platform `fstat`, descriptor closing,
`fexecve`/`execveat`, Landlock, and macOS sandbox primitives behind narrow
Kinbase-owned interfaces. The dependency source/function inventory and audit are
part of the build receipt; a dependency may not define protocol bytes, trust policy,
or authority. If the platform boundary cannot be met through audited safe APIs, the
Coder returns `FACTORY_QUESTION` and stops. It may not weaken the boundary, add
first-party unsafe code, or substitute same-UID convention without a new reviewed
amendment.

The offline survey in
`evidence/factory-run/rust-boundary-feasibility-002.md` identifies safe public APIs in
`nix 0.31.2`, `rustix 1.1.4`, and `landlock 0.4.7` for the Linux path; it is feasibility
evidence, not dependency admission. Because the surveyed descriptor-backed execution
API is not available on macOS, the live external-classifier acceptance proof runs on
a Linux host with Landlock hard-requirement enforcement. G-9 also runs the macOS
artifact-omission/negative gate and proves the shipped macOS binary contains no
external-classifier module, command, configuration variant, launcher, or identifier
string and cannot accept a hostile Linux-only invocation. The terminal claim therefore names Linux as the only
proven external-classifier platform rather than silently carrying an unexercised
macOS implementation. The macOS workstation may host the sandboxed Factory Coder,
but that does not satisfy the Linux Product proof gate.

Rust is pinned by `rust-toolchain.toml` to 1.98.1. The Validator observation in
`evidence/factory-run/rust-toolchain-observation-001.md` records the official channel
manifest retrieval and local-toolchain limitation. The official channel manifest
`channel-rust-1.98.1.toml` has SHA-256
`a7c8774a5fd8441c997d94c029776cbc5eb111e9d72ab5d256fa69866644347e`;
the run receipt additionally records the exact target component archive checksums,
`rustc -Vv`, Cargo version, host target, `Cargo.lock` digest, and vendored-source
digest. Dependency acquisition is a separately logged bootstrap step. Every proof
build thereafter runs offline with `--locked`. The Kinbase workspace and binary
contain no Python interpreter or Python package dependency; the separately installed,
manifest-pinned `kin` compatibility executable remains an external process and may
itself be implemented in Python.

Before staging a billable Coder host, the Validator installs the manifest-selected
1.98.1 components into a run-specific toolchain root, verifies every downloaded
archive against that manifest, compiles and runs an edition-2024 hello-world once,
then repeats the build offline with `--locked` and records `rustc -Vv`, Cargo, target,
archive, and output digests. A missing/mismatched toolchain is
`AUTHORITY_MISMATCH` before Vast spend, not a G-9 discovery. This preflight verifies
toolchain existence only; it is not Kinbase Product evidence.

In `spec/architecture.md` section 1 replace this exact old block:

> The existing Kindex package is integrated behind `PersonalKindexAdapter` and
> `CodebaseKindexAdapter`; Kinbase does not fork its generic graph/search code.
> Adapters use public Store/export/import surfaces or subprocess JSON contracts. Any
> missing public seam is isolated in the adapter and recorded rather than answered by
> writing Kindex SQLite tables directly.

with this exact new block:

> The existing Kindex package is integrated behind `PersonalKindexAdapter` and
> `CodebaseKindexAdapter`; Kinbase does not fork its generic graph/search code.
> In the Rust implementation those adapters invoke the absolute, startup-verified,
> manifest-pinned `kin` executable through its public JSON/JSONL subprocess contracts.
> They do not embed Python, import Kindex internals, or write Kindex SQLite tables.
> Kinbase's Company store and signed `.kin/` protocol remain native Rust-owned
> components. Any missing public Kindex seam is isolated in an adapter and recorded.

In `spec/architecture.md` section 4 replace this exact old bullet:

> - `repo_code`: language-agnostic files plus Python/TypeScript declarations;

with this exact new bullet:

> - `repo_code`: language-agnostic files plus Rust/Python/TypeScript declarations;

In `spec/verification.md` replace this exact old nonfunctional gate:

> - Python package installs in a clean environment and commands have bounded help.

with this exact new gate:

> - The pinned Rust workspace builds from a clean environment with `--locked`; the
>   proof build is offline after the declared dependency-bootstrap receipt; the release
>   executable and every command have bounded help. Formatting, Clippy with warnings
>   denied, unit/integration tests, dependency-license policy, vulnerability audit, and
>   first-party unsafe-code denial are recorded. The final artifact records its source
>   commit, `Cargo.lock` and vendored-source digests, compiler/channel-manifest and
>   target-component checksums, compiler version, target, and binary digest.

### 2.2 Coder model and harness

In `spec/verification.md` replace this exact old role block:

> - **Coder (GLM-5.3 via Ollama-launched Codex):** reads ratified product,
>   architecture, verification strategy, and its build lane; authors implementation
>   and implementation docs only; cannot read Tester work or judge success.

with this exact new role block:

> - **Coder (GLM-5.3, official open-weight FP8 checkpoint, through a local Codex
>   harness and a Vast-hosted vLLM Responses endpoint):** reads the effective
>   Product, Architecture, Acceptance Threat Model, Verification, CLI, this
>   amendment, and its isolated build lane; authors Rust implementation and
>   implementation docs only; cannot read Tester work, test/oracle bytes, review
>   findings about Tester output, or judge success.

Coder and Tester derive the invocation contract only from the materialized CLI:
subcommands/options, descriptor passing, stdout/stderr records, and exit codes are
shared authority, not implementation lore. G-1 must map every mode either to that
exact CLI surface or to a named internal mode whose complete wire/exit contract is
added by ratified authority before either lane starts. An independently invented
launch convention is `AUTHORITY_MISMATCH`, not a G-9 implementation failure.

The exact initial runtime is below. Model repository revision, resolved LFS object
manifest, image digests, H200 inventory, and BF16 capacity were observed and are
retained in `evidence/factory-run/vast-glm53-qualification-001.md`; that receipt is
infrastructure evidence only and does not inherit across a changed host/configuration.

- model repository `zai-org/GLM-5.3` at Git revision
  `aca966e4e02791568aa6a4ced368624b3d897f42`;
- official native-FP8 model files (approximately 755.7 GB), with the resolved
  Hugging Face LFS pointer/object manifest retained as the immutable artifact
  receipt;
- `vllm/vllm-openai:v0.28.0`, manifest digest
  `sha256:61fc8a896b0a4fbbbdc063bc4b0dbc25ce98e02b5050c24aeb7830ac02039b14`;
- one 8xH200 Vast host. The run binding names the exact instance, machine, host,
  GPU inventory, driver/CUDA report, image architecture digest, SSH public-host-key
  fingerprints, start time, and account. A replacement must retain GPU model/count,
  exact image/model/configuration digests, and rerun every capacity, parser, tunnel,
  egress, and recovery probe; driver or host change is never inherited evidence;
- the authenticated observation in
  `evidence/factory-run/vast-instance-risk-observation-003.md` records
  `is_bid=false` and provider field `reliability2=0.9992037` for this instance. That is
  evidence against bid-price preemption, not an SLA or a five-hour completion
  probability; host/provider/network failure remains possible and the attempt is not
  guaranteed;
- tensor parallel size 8, 262,144-token maximum context, one logical Coder request
  stream, prefix caching enabled with SHA-256/CBOR keys, GLM-4.7 tool parser, and
  GLM-4.5 reasoning parser;
- the parser names are compatibility settings, not evidence that GLM-5.3 semantics
  match earlier models. Before dispatch, synthetic probes must cover streamed text,
  required single-tool selection, tool-output replay, reasoning-bearing output,
  malformed tool arguments, and an endpoint interruption. One maximal round-trip
  probe exercises every frozen tool-schema field, maximum supported nesting, and all
  optional keys, then requires byte-equal canonical arguments after parse/re-encode;
  another requires exact reasoning/answer boundary reconstruction. A parser/config
  change requires the complete probe set again and a new configuration digest;
- BF16 KV cache on H200 unless a synthetic pre-dispatch capacity probe proves it
  cannot sustain the bound context. Any FP8-KV fallback is a separately recorded
  configuration change because it may alter quality;
- local Codex tool execution in a run-specific OS sandbox: a literal macOS
  `sandbox-exec` profile on the current workstation, or bubblewrap plus Landlock on a
  replacement Linux workstation, selected and digested before G-4. On Linux,
  Landlock is the filesystem control only: the run binding records kernel release,
  Landlock ABI, and every required access right, and startup refuses any best-effort
  downgrade. Sole network egress is enforced independently by a bubblewrap-unshared
  network namespace containing only loopback and the admission-proxy listener, plus a
  seccomp profile that denies UDP, raw, `AF_PACKET`, `AF_NETLINK`, and all unneeded
  socket families. G-4 attempts IPv4/IPv6 external TCP, UDP/DNS, raw, packet, and
  netlink traffic and requires denial before repository access. Its only writable
  roots are the Rust Coder worktree, run-specific Codex home, and explicit temporary
  directory. `CARGO_TARGET_DIR`, Cargo registry/cache, and every disposable build root
  are separate mounts beneath that temporary root and never descendants of the source
  worktree; dependency sources intended to ship are source and remain inside the cap.
  Its read roots are those three, the read-only materialized authority
  bundle, pinned toolchain/dependency cache, and explicit system libraries/executables.
  The Validator checkpoint/ledger roots are outside both its read and write policy.
  It receives no Personal or Company root/socket, Tester/Detector/Oracle path,
  unrelated repository, general user home, cloud credential, or direct IP network
  capability beyond one run-specific loopback admission-proxy listener whose address,
  port, executable identity, and configuration digest are bound. That proxy can
  connect only to a separately sandboxed observer relay and has no route or descriptor
  to SSH. The observer can accept only that proxy and connect only to the pinned SSH
  listener; SSH accepts application bytes only from the observer. These processes
  share no code or writable state. Sole-egress is an invariant: the Coder sandbox has
  no other network namespace, socket, inherited tunnel descriptor, DNS path, or
  provider-side agent. The admission proxy and SSH wrapper terminate HTTP/1.1 request
  framing rather than treating a persistent stream as body boundaries. They fully
  buffer one request, require one canonical `Content-Length`, reject every
  `Transfer-Encoding`, pipelined request, HTTP/2 request, request-side streaming, and
  over-bound body, and open one upstream request per admitted body; response streaming
  may return only after that request admission. G-4 rejects chunked, pipelined,
  conflicting/duplicate-length, oversized, and request-streaming controls.

  The observer owns the exact post-admission **prepared** body digest/count/byte-count
  list. It fsyncs the next chained `prepared` row before issuing a one-use token and
  releasing that body. The token is an HMAC over
  `(run_generation, sequence, predecessor_digest, body_sha256, body_byte_count)` under
  a run key readable only by observer and SSH wrapper. The wrapper buffers and hashes
  the exact body it will forward and verifies every committed field. Before the first
  request byte reaches the local SSH socket it appends and fsyncs a `spent` row; every
  restart treats that sequence as spent whether or not a response or complete socket
  write exists. After the complete request has been handed to the local SSH socket it
  appends and fsyncs `forwarded`. A `spent` row without `forwarded`, or interruption
  during the write, is permanently **potentially sent** and is never replayed or
  narrowed by missing provider evidence. The wrapper owns the local-forwarded list;
  Vast owns actual provider receipt, which Kinbase cannot observe. Prepared, spent,
  forwarded, and diagnostic SSH counts must follow that prefix order; any unexpected
  delta halts and expands the potentially-sent notice superset rather than being forced
  to equality. Observer/journal failure therefore holds the body before SSH rather
  than creating an unrecorded send. A hold has a 30-second
  maximum. Timeout or observer volume exhaustion discards the held body, cancels the
  model turn, runs local journal reconciliation, destroys the instance, emits
  `UNFUNDED_BY_OBSERVER_STALL`, and appends a Validator-owned apology with burned wall
  time/dollars. G-4 injects blocking `fsync` and full-volume failures and proves no held
  body is replayed. It also kills the wrapper after spend-fsync/before socket write and
  after partial/full socket write/before response, restarts it, and proves the token is
  unusable and the prepared/spent/forwarded/potentially-sent sets reconcile or fail
  closed. This is the existing indeterminate terminal branch, not a fourth
  reconciliation answer. Independent SSH connection/byte counters are
  diagnostic cross-checks, not alternative body authority; G-4 freezes setup, rekey,
  keepalive, retransmission, window-update, and framing classes plus a byte envelope
  from sustained synthetic traffic. A delta inside that envelope is recorded; an
  observer/wrapper token mismatch or network delta outside it halts traffic before
  bounded reconciliation, may only increase suspected custody, and defaults notice
  scope to the policy-authorized superset. Application retries are new counted custody
  events, while transport retransmission is not a second HTTP body. G-4 injects one
  duplicate request and proves that the observer records both bodies, and also proves
  the frozen envelope has no false hold over the sustained control. An extra network
  descriptor or packet path destroys the route. Before every launch,
  probes attempt an outside-root write, symlink escape, `..` traversal, forbidden
  read, inherited-descriptor read, and direct network connection; every attempt must
  be denied and recorded. An out-of-process observer, unwritable by Codex and the
  admission gate, independently chains each relayed request digest and byte count.
  A separately sandboxed and logged dependency-bootstrap process may perform GET-only
  access to manifest-authorized Rust registry endpoints. For each dependency change,
  the Coder first emits `Cargo.toml` and `Cargo.lock` without network; the Validator
  binds their digests and checks the dependency allowlist, then a dedicated disposable
  network namespace fetches only lockfile-named URLs and verifies every lockfile
  checksum. It emits its complete endpoint/artifact census, is destroyed, and its
  cache is remounted read-only before the Coder/build namespace exists. G-4 proves
  this lifecycle on a synthetic lock. A mid-run remount or any other readable-set
  expansion requires the quiescence lease and termination of every Coder/tool process;
  the complete mount/descriptor census and authorized-send superset are rebound and
  the entire pre-launch denial battery—including outside-root write, intermediate and
  final symlink escape, traversal, forbidden read, inherited descriptor, direct
  IPv4/IPv6/UDP/raw/packet/netlink traffic, and DNS—is rerun before a new Coder process
  exists. The rebound receipt is appended to the ledger. The ledger preserves the union of every interval's
  readable set, so a later narrow census cannot erase earlier readable history.
  Pinned dependency-cache bytes carry public provenance and are authorized processor
  input, never silently relabeled repository facts; G-4 plants a public-cache marker
  and verifies that classification. Every anticipated dependency proposal, review,
  fetch, audit, remount, and resulting rebuild occupies one or more named VOI-plan
  slices; its running wall time and provider cost consume `warm_authoring`. Each
  maximum-30-minute capacity unit is counted separately. An unplanned dependency
  transition consumes an unallocated remaining unit or closes admission and returns
  `UNFUNDED`; dependency work has no hidden time or restart reserve. An
  untrusted model tool call cannot widen these kernel-enforced capabilities;
- the Vast host runs inference only and receives no repository clone, filesystem
  mount, credential, tests, Kindex graph, or coordination channel. The inference API
  is reachable only through a local SSH tunnel whose host key is pinned from the
  Validator's first-contact ceremony alongside the TLS-authenticated Vast API
  endpoint/instance/machine observation. The run records the provenance limitation:
  this is key continuity plus control-plane correlation, not remote attestation.
  Vast's published SSH flow itself asks the user to accept a first-seen fingerprint
  and supplies no separate host-key attestation
  (`docs.vast.ai/guides/instances/connect/ssh`, observed 2026-09-05 and retained as
  `evidence/factory-run/vast-ssh-source-observation-001.md`).
  The key is therefore a post-contact substitution detector, not protection against a
  first-contact MITM and not the root that authorizes repository disclosure. Every
  transmitted byte is disclosed to the named Vast processor regardless of SSH. The
  Validator records a second fingerprint observation over an independent network
  path when available; its absence remains an explicit identity residual rather than
  a fabricated attestation. Changed identity fails closed. No inference port is
  publicly mapped;
- every outbound model request passes a local admission gate before transmission.
  Physical capability confinement is the confidentiality root: the Coder cannot read
  a Personal store, an unauthorized Company body, a Tester/Detector/Oracle asset, a
  secret root, or another repository. “Lineage” is transitive bookkeeping over the
  Validator-owned prompt manifest and each tool call's kernel-observed read set; the
  Coder worktree is not blanket-safe merely because it is writable. Model-authored
  text has unbounded/self-asserted lineage and receives no trusted label. In the live
  Coder lane, the mount/descriptor census proves `readable-by-Coder` is a subset of
  `authorized-to-send-to-Vast`; anything forbidden to send is structurally unreadable,
  not entrusted to a scanner. After the
  capability check, the gate rejects forbidden taint/source IDs and byte-scans as
  defense in depth. It records request digest, byte count, authorized purpose,
  source-event IDs/read-set digest, and decision before forwarding; the independent
  observer records the forwarded body separately. Failure or ambiguity holds the body
  locally. Direct-marker and copy-through controls run in a separate qualification
  mount where a synthetic readable source is deliberately labeled forbidden; both
  must fail, then that mount and marker are destroyed before the live lane exists.
  The G-4 receipt records and enforces
  `marker_created_at < marker_destroyed_at < live_lane_created_at` plus the marker,
  mount, and live-lane configuration digests; a missing or reordered event blocks.
  They test accidental-inclusion defense and capability-census failure handling, not
  permission to retain a forbidden readable file. Everything the live Coder can read,
  including model-authored transformations of it, is potentially disclosed to Vast.
  This gate cannot hide authorized repository bytes from Vast or defend against a
  model intentionally retransmitting bytes it was allowed to read;
- the exact vLLM argv, allowlisted environment-variable names and non-secret value
  digests, and filesystem inventory are recorded. Secret values never enter a
  receipt. Request and access logging, swap, CPU offload, and persistent prefix/request
  caches are disabled.
  These settings reduce accidental inference-server persistence; they do not protect
  against the host operator and are not evidence of provider erasure;
- prefix caching is permitted inside the explicitly authorized Vast processor
  boundary after ratification because it materially reduces repeated-prefill cost.
  The Validator owns only the configuration assertion that persistent request/prefix
  caches are disabled and binds the exact argv/environment/inventory evidence. The
  in-process prefix state itself is provider-owned derived data with no Kinbase
  lifecycle authority. Repo-derived prefix state is provider-accessible custody, not an erasure, privacy,
  durability, or recovery claim. The custody-memory record names this exposure class,
  the corresponding request digest list, and observer-owned input byte counts. Any
  token count is a Validator-derived estimate bound to the exact tokenizer/model-
  configuration digest and carries the residual that provider internals are not
  observed; it is never presented as a provider fact. Any indication that the provider
  persisted or transferred prefix state across process/instance boundaries is
  `UNRESOLVED_CUSTODY` under the same maximal notice-superset rule. Once
  a repository-bearing request crosses, operator-initiated stop-with-disk-retained is
  forbidden: completion, abandonment, or a review pause destroys the instance.
  Provider preemption remains an unreconciled custody event;
- recovery authority remains local. The Validator freezes a closed tool registry;
  each operation has a strict JSON schema, mutability class, maximum duration, and
  deterministic postcondition/reconciliation command. Parsing rejects duplicate or
  unknown keys, invalid UTF-8, noncanonical numbers, path traversal, symlink escape,
  C0/C1 or bidi-control path bytes, non-NFC Unicode paths, and values outside schema
  before dispatch; the model cannot label an operation idempotent. Path resolution
  starts from one pinned worktree-root descriptor and never calls string
  `realpath`/`canonicalize`. Linux uses `openat2` with `RESOLVE_BENEATH` and
  `RESOLVE_NO_SYMLINKS`; the portable fallback walks every intermediate component with
  descriptor-relative `openat(O_NOFOLLOW|O_DIRECTORY)` and performs the final `*at`
  operation with no-follow semantics. Validation and execution retain that same
  descriptor chain, so a pathname or symlink swap cannot change the validated object.
  G-4 races both an intermediate-component and final-component swap and requires
  denial; a final-component-only probe cannot satisfy the gate.
  Before a tool starts, the Validator-owned journal writer—outside Coder, tool, proxy,
  and observer write capability—holds the admission mutex and `fsync`s canonical-CBOR,
  length-framed call ID, pre-normalization and validated arguments, registry-owned
  capability class, pre-state digest, and predecessor digest. While still holding that
  mutex, it `fsync`s the `started` record **before any child process exists**. Only then
  may the launcher fork/exec a child with the registry-owned write capability. Thus no
  forked child can possess a source-write descriptor in a pre-state-without-`started`
  window. A spawn failure is still a started call and runs its discriminating
  postcondition/reconciliation before the mutex can admit a checkpoint or later call.
  G-4 injects a spawn failure and an immediate noncooperating write attempt and proves
  no unjournaled source effect. It proves every
  postcondition against both effect-present and effect-absent states. The journal
  then `fsync`s the exact result and post-state digest before forwarding either the
  result or any later model event. Every read verifies framing and the digest chain.
  The chain proves crash/corruption and Coder/tool tampering under this capability
  boundary; it does not authenticate a malicious Validator, compromised kernel, or
  root, which remain outside the claim. A host-side generation without a
  complete local event is **inadmissible** and cannot become recovery evidence; no
  claim is made that provider-side computation did not occur. Only a registry-declared
  read-only/idempotent call may be replayed. An interrupted mutating call is never
  automatically repeated and follows its frozen postcondition runbook first. The final
  response, thread ID, current Git HEAD, and worktree status digest are recorded
  locally;
- a Validator-owned monotonic watchdog completes or terminates each checkpoint cycle
  before fifteen minutes have elapsed from the prior admitted checkpoint. The fixed
  schedule is `checkpoint_start_interval_seconds = 300`,
  `active_call_drain_deadline_seconds = 60`,
  `reconciliation_deadline_seconds = 120`,
  `lease_acquisition_deadline_seconds = 30`, and
  `snapshot_deadline_seconds = 360`; their sum is 870 seconds. At 300 seconds the
  coordinator revokes release of every new local tool and source-mutating child. Any
  active local call is canceled or reaches its frozen boundary within 60 seconds;
  any possibly mutating call then receives at most 120 seconds for its declared
  postcondition reconciliation. A remote model request may remain in flight, but no
  tool it proposes can be released during the cycle. Failure of any phase kills the
  gated source writer, closes all model/tool admission, marks the uncheckpointed tree
  a crash artifact, and terminates the route no later than second 870. The last prior
  admitted checkpoint remains the only recoverable source state; no empirical timing
  estimate can extend a phase or turn termination into a checkpoint.

  `checkpoint_start_interval_seconds` is a one-shot deadline reset only by an admitted
  checkpoint, not a recurring ticker: while a cycle is active, no second cycle is
  queued or started. The absolute 900-second deadline continues from the last admitted
  checkpoint. The snapshot phase's 360 seconds includes both journal-head reads,
  private-index construction, object/ref writes, both complete tree digests, receipt
  fsync, and the admission transition; no unpriced bookkeeping lives in the 30-second
  margin. Every local tool is killable as one process group at the 60-second drain
  boundary, and no child retains a source-write descriptor after that kill. G-4 runs a
  worst-case active-call cycle through second 870 and proves one termination/admission
  decision with no overlapping trigger.

  A snapshot requires a held quiescence lease from the same admission coordinator
  that permits journal pre-state writes. Lease grant and child release use one
  Validator-owned mutex: grant atomically rejects with
  `CHECKPOINT_DEFERRED:<call-id>` when any journal call has `started` without `result`,
  and a child cannot be released to mutate while a snapshot lease is held. Only the
  gated launcher has source-write capability; compiler/build children see source
  read-only and write disposable roots. The watchdog reads the journal head, uses a
  private temporary Git index plus a Validator-owned `GIT_OBJECT_DIRECTORY` outside
  Coder read/write policy to create a content-addressed checkpoint ref there without
  staging or rewriting the Coder's index; the Coder object database may be mounted only
  as a read-only alternate for this operation. It reads the journal head again and
  computes the source-worktree tree digest twice consecutively. It admits
  the checkpoint only when the journal head is unchanged, no call remains outstanding,
  and both tree digests match, then records the lease and bracketing sequence numbers
  before release. A changed head/tree or outstanding call is never recovery evidence.

  The live-source envelope is every filesystem entry below the source-worktree root
  other than the separately mounted Git metadata; there is no ignored-but-uncounted
  `target/`, cache, log, or temporary subtree. Only the gated writer may change that
  set. G-4 qualifies the exact maximum live-source envelope of 20,000 paths and
  1,073,741,824 content bytes. It builds a synthetic tree at both caps and runs at
  least 30 complete held-lease cycles, each of which must satisfy every fixed phase
  deadline and the 870-second total. Those observations establish feasibility for the
  tested tree; their maximum or empirical p99 is diagnostic only and is not represented
  as a bound on the next checkpoint. Before every mutation, while holding the same
  admission mutex, the gated writer computes
  the resulting path count and content-byte count and rejects an operation that could
  exceed either cap. Expanding either cap requires a new founder/Validator-ratified
  amendment and fresh G-4 qualification, not a larger planned estimate. Longer builds
  write only the separately mounted disposable build/cache roots and cannot modify
  source. G-4 writes at least 2 GiB beneath `CARGO_TARGET_DIR` during a checkpoint and
  proves that neither the capped path/byte census nor source-tree digest changes; it
  also runs the representative locked dependency build to prove intended vendored
  source fits the cap. After an admitted checkpoint, G-4 runs Coder-lane `git gc
  --prune=now --aggressive` plus reflog expiry and proves the Validator-owned checkpoint
  remains fully resolvable from its separate object/ref store. Every admitted
  checkpoint records the empty outstanding-call set; retained prior-art manifests
  include terminal journal state, and a capture with any outstanding call is a crash
  artifact that cannot be resumed. G-4 also holds the lease and proves a source write
  is denied. The Coder commits every independently coherent slice;
- coherent Coder commits and quiescent checkpoint refs are recoverable work products,
  not proof milestones. If this route becomes `UNFUNDED`, the last complete series is
  retained with its authority/configuration/host lineage as **unadmitted prior art**
  in a Validator-custodied, mode-0700 content-addressed manifest outside author lanes.
  Its 30-day clock starts at the Validator's `UNFUNDED`/incomplete disposition record,
  not checkpoint creation. At day 21 the Validator notifies the founder with the
  manifest digest and exact extension text. It expires at day 30 unless the founder
  signs one exact extension or a new generation admits it sooner; expiry destroys the
  private refs/worktree and records the manifest digest. A false-`UNFUNDED` correction
  found before expiry names every affected prior-art manifest and restarts its clock
  from the correction record. If correction arrives after destruction, the Validator's
  apology records the irrecoverable artifact loss, cause, and owner rather than
  pretending money-only repair. A later generation may mount it only through the contamination
  scan and new exact amendment in section 2.3. No partial series may satisfy G-6 or a
  Product gate;
- recovery qualification interrupts the tunnel during response forwarding and during
  a local mutating-tool call, then requires the same local Codex thread to resume with
  neither a silently dropped nor duplicated completed event. Endpoint loss may waste
  the in-flight generation and one cold prefill, whose measured time/cost count
  against the run; it does not justify reconstructing completed work from memory.
  Reconciliation has a bounded three-way result: the frozen postcondition proves the
  effect committed exactly once and the journal completes it; proves no effect and a
  new call ID may be deliberately issued; or remains indeterminate and the Coder run
  stops, the host is destroyed, and the last quiescent checkpoint is retained as
  unauthoritative prior art. The reserve is not spent inventing a fourth answer.

The journal, checkpoint refs, and worktree remain workstation-local and never egress
for durability. If a separately funded replacement host later resumes the local Codex
thread, the newly reconstructed model-request body crosses Q-1 as a new observed Vast
custody event; the local journal itself is neither uploaded nor treated as secret from
the model bytes it causes Codex to replay.

A Vast preemption during authoring does not create or discard an experiment trial.
After any preemption, restart is admitted only if
`cold_load + runtime_qualification + remaining_warm_authoring +
max_in_flight_turn + charge_reserve + operational_contingency <=
authorization_remaining`. At current rates and
the proposed USD 400 ceiling reserves **one** cold restart; G-3 consumes it to
replace the disqualified pre-ratification host, so no post-disclosure restart remains. The
restart allowance is consumed by its first cold-load/qualification attempt regardless
of outcome and cannot be replenished by a lower later price. A second preemption
terminates this funded Coder attempt, destroys any surviving instance, and retains
only the last local quiescent checkpoint as unadmitted prior art. Every restart still
must make the live inequality true under a newly recorded admission decision.
Otherwise, resumption requires new founder funding/authorization; a
replacement host receives a new launch record and passes the full configuration/
runtime gates, and the candidate lineage lists every host segment. V-10 later follows
its own frozen model/provider/runtime manifest:
a measurement-time host or unbound runtime change has the existing `INVALID_RUN`
disposition and is never pooled by calling two hosts equivalent after outcomes.

The initial Rust run **omits the old Python lane entirely**. G-5 passes for this
generation only when the Coder sandbox mount/descriptor census proves that lane,
its Git objects, agent/session metadata, and adjacent evidence paths absent, and a
denial probe cannot name or open them. The Validator and sandbox launcher own this
exclusion; a prompt instruction is not enforcement.

Allowing historical implementation into a later generation requires a new exact
founder/Validator-ratified amendment. Before that Coder receives any earlier
implementation, the Validator must scan the entire old Python lane, including
untracked files, Git objects reachable from its branch, agent/session metadata, and
adjacent evidence paths, for Tester, Detector, hidden-oracle, or acceptance-result
contamination. The Validator freezes a content-addressed, Validator-owned read-only
manifest of every permitted path and digest outside the new Coder worktree; anything
not enumerated is inaccessible. A positive control proves denial. A hit or incomplete
scan blocks all historical code rather than asking the Coder to ignore selected lines.

The omitted Python snapshot remains unauthoritative prior art from a separately
served, quantization-unresolved GLM-5.3-labeled attempt. The missing Ollama model
artifact and quantization digest are recorded as unknown; it is not called the same
model instance or same author. No prior file may enter the Rust product commit,
evidence packet, or proof claim. Instead, one structured run-binding predecessor
record names the Python language, Ollama route, unresolved model artifact/
quantization, absence of an admitted commit, and the new Vast/vLLM/Rust revision and
FP8 manifest. Coder dispatch, candidate handoff, and final evidence packet reference
that record's digest rather than repeating a prose claim.

### 2.3 Orchestration and independent testing

Agy remains the resident non-authoring Orchestrator with only `block` and `no-op`
effects. Codex root remains Validator. Claude remains the implementation-blind
Tester. No Tester file, finding, assertion, fixture, or hidden expectation enters the
Coder prompt, historical-code snapshot, repository, model request, or tool result.
The Orchestrator receives the verbatim founder goal, effective authority digests,
budget observations, role states, blockers, and bounded activity deltas; it vets
trajectory and can return `block` or `no-op`, but cannot write, test, narrow scope,
ratify, or issue a verdict. Agy's own prose is not identity evidence. For every Agy
disposition the Validator hashes the invoked executable, captures the OS-observed
process/launcher arguments and configuration inputs, records the kernel-observed
destination and certificate, and retains the provider response's billing/request and
model identifiers when the provider supplies them. The resulting receipt compares
that externally observed executable/provider/model-family/endpoint/configuration
fingerprint with Coder, Tester, Simulacrum, Advocate, Detector Reviewer, and graders.
Any field that cannot be observed outside Agy is `UNVERIFIED`, conservatively overlaps
every family it could be, and contributes no diversity evidence. Every actual or
possible overlap is reported as a correlated-review residual; Agy is never labeled
independent, and its `no-op` never substitutes for the founder's exact semantic
decision or the two-family grading rule.

This amendment starts a fresh Factory generation. A newly bound Claude Tester works
from the effective authority in a clean test lane without reading Rust code or Coder
state. The old Tester artifact is retained as history but is not presumed valid,
patched only at its launcher seam, or admitted into the new run. The new Tester must
derive and seal the complete V-1 through V-10 instrument, including Rust-neutral
launch behavior and every new gate in this amendment. A new implementation-blind
Detector Reviewer then reviews the exact new Tester commit and independently freezes
the attack-catalog/auxiliary-corpus artifacts before combination.

Claude is the test author, not the functional scorer. Held-out functional outcomes
are mechanical observations from Validator-run tests; the two calibrated automated
graders score only the frozen non-mechanical rubric under the existing distinct-
family/provider and reliability/blinding gates. Seeds, decoding, prompts, rubric,
parsers, calibration digests, repeat-agreement evidence, and model fingerprints are
frozen before measurement. Any family overlap with Coder, Tester, or another grader
is reported as a residual and cannot replace the two-family rule. A pre-combination
leakage control compares Coder-visible bytes with hidden test/oracle-only markers;
any test-only wording/fixture match invalidates the lane. Shared vocabulary entailed
by the ratified Product is reported but is not misclassified as hidden-test leakage.

No V-10 pilot, Corpus Builder snapshot map, static prior, Oracle Curator census/draw,
gold calibration set, measurement manifest, or Product result is admitted for this
generation. The Validator's
`evidence/factory-run/pre-outcome-null-census-001.md` receipt enumerates the searched
artifact classes and every old aborted-generation object that remains, and binds this
claim before ratification at SHA-256
`0106b3664e156bd745c831369100f0298598135440ee720324c88f191eb95f0e`.
The census covers V-10 pilot/run/result, Corpus Builder snapshot map, static prior,
Oracle Curator census/draw/replies, gold calibration, measurement manifest/candidate/
score, Product verdict, and fresh Tester/Detector paths; it separately names retained
aborted-Python evidence. All new-generation artifacts are created fresh in their
ratified order. Any old canary registry, auxiliary corpus, unstarted experiment
manifest, Tester admission, or Detector review belongs only to the aborted generation
and cannot be rebound by renaming its digest. The base specification receipts remain
historical authority inputs; infrastructure receipts remain operational observations
only. Every Product and recovery gate is rerun under the final Rust/runtime/effective-
authority digests.

The three egress controls protect different channels and never substitute for one
another:

| Control | Active phase/channel | Owner and ordering | Required positive control | Failure |
|---|---|---|---|---|
| `Q-0 synthetic-only proxy` | before G-1; qualification request to Vast | Validator; full canonical request allowlist plus bounded send counter, then out-of-process request observer | direct forbidden marker and replay-over-count denied | no inference; an actual unauthorized send permanently blocks this route |
| `Q-1 accidental-inclusion relay` | after G-1 through G-6; Codex request to Vast | OS read-capability confinement first, Validator-owned read-set/taint admission second, byte scanner third, capability-separated observer last | direct and qualification-mount copy-through forbidden markers denied | body held locally; no repository-bearing request |
| `Q-2 candidate holdback` | after G-8; candidate packet to either external grader | implementation-blind Tester instrument first, Detector Reviewer qualification second; independent of Q-1 | frozen protected-recovery and true-negative decoy suites | true recovery is Product failure/zero; false positive or unresolved disagreement is `INVALID_HARNESS` |

Q-0 binds method, path, a closed canonical header set, body, and a per-probe maximum
send count into each allowlisted digest; its monotonic counter is fsynced before
forwarding. The counter is a Validator-owned route-generation ledger row outside
scratch/proxy writable state, keyed by probe digest and predecessor-chained into the
Factory ledger. The separately permissioned local sentinel retains the current chain-
head digest outside the Validator ledger's filesystem; every proxy start requires
equality or treats the count as exhausted. It shares the workstation, root trust, and
human operator with the Validator, so this is crash/non-adversarial-operator-error
detection, not an independent security boundary and not protection from a malicious
Validator, root, or kernel. Recreating the scratch sandbox does not reset it, and qualification
drills both recreation and restoration of a valid older ledger snapshot after count
exhaustion; both replays must be denied. Observed replay above the frozen count
permanently blocks the route. An unreadable/missing/rollback-mismatched ledger blocks
only until the founder ratifies a new probe-digest set and count under a recorded
storage incident; it never restores the old allowance. Q-0 remains the only active
proxy through G-3 and is atomically retired at G-4 only after Q-1 qualifies; there is
no relay in the transition that can admit either class by default. Q-1 detects
accidental inclusion and operator error on the Factory Coder provider path; OS
capability confinement is its confidentiality boundary. Q-2 protects Product-generated candidate
egress during V-10. Sharing code is permitted only where the identical bytes and
configuration digest are independently admitted for both purposes; sharing a prior
pass or owner is forbidden.

No later gate upgrades Q-0 into an adversarially independent witness. G-1 uses it only
to prove that the manifested synthetic allowance was enforced before authority
ratification; G-3 uses the absence of a pre-send local observer to disqualify the old
host; and G-4 tests rollback/send-count behavior only against crash, scratch-directory
recreation, proxy defects, and non-malicious operator error under a trusted Validator,
OS, kernel, and local root. The provider host has no local ledger/sentinel write
capability. A malicious Validator, local root, or kernel could corrupt both records and
remains explicitly outside the proof threat model.

### 2.4 Provider and custody boundary

In `spec/threat-model.md`'s model-provider boundary insert after this exact anchor:

> Private-message classification therefore uses a local model, or the already
> authorized current host processor under the same data/retention scope; otherwise it
> abstains and creates a private Unknown. The acceptance packet records every outbound
> model-request digest and authorized-purpose receipt and plants positive controls in
> the egress detector. Transmission to an unnamed provider or outside the authorized
> byte/scope set is a V-3 product failure. Provider-side custody and compromise are not
> tested, so the permitted claim explicitly names the digest-identified authorized
> processor boundary.

this new text:

>
> For the amended Coder generation, Vast.ai account 413964 and the exact launch-
> receipt host are the named model-compute processor for only the Coder projection
> of the synthetic Kinbase proving repository. The host operator can technically
> access host files and memory; container isolation is not a confidentiality proof.
> Personal-store history, Company bodies, customer data, credentials, test/oracle
> bytes, and unrelated repositories remain prohibited. Codex runs locally and sends
> only its prompt plus selected Coder-lane tool results through an encrypted SSH
> tunnel after local lineage admission. vLLM request/access logging and persistent
> request/prefix caches are disabled to reduce accidental persistence; these controls
> do not exclude the host operator. The host's durable working set is limited to
> public model/runtime artifacts and operational server logs proven free of request
> bodies at inspection time. On completion or abandonment, the instance is destroyed
> rather than merely stopped. Vast's deletion assertion is operational evidence, not
> proof that a provider never retained bytes.

Run-control receipts do not enter an unproven Kinbase Company store. They live in
the Validator-owned, append-only Factory run ledger outside author lanes, contain no
raw protected payload, and are committed as sanitized evidence when safe. Each
record has stable identity `(run_generation, record_type, monotonic_sequence,
content_digest)`, names the Validator as recorder, names the external observation
source, binds its predecessor and effective-authority digest, and states whether it
is an observation, authorization, or proof gate. Git/content digests establish byte
integrity; no actor-authentication signature is claimed unless actually present.
Founder approvals are retained as verbatim conversation-derived receipts with that
limitation. These records cannot self-ratify Product facts.

The ledger contains launch, model-manifest, request-census, usage, stop/restart, and
destroy records. It also appends a permanent `provider_custody_memory` after the first
repository-bearing send. Policy owns its authorized byte-class and request inventory;
the capability-separated observer owns exact `prepared` request-body digests/counts/
byte counts; the SSH wrapper owns exact `spent` and locally `forwarded` inventories;
Vast owns the fact of actual provider receipt, which no Kinbase component can
observe. Proxy/SSH connection and byte counters are diagnostic cross-checks: an excess
raises suspected custody, while a deficit cannot delete any prepared, spent,
forwarded, or potentially-sent row. Retries are separate request rows, so no duplicate
tolerance hides an application send. The record keeps those owned inventories distinct and also names Vast account/instance/
host, prefix-state exposure, first/last transmission times, final destroy receipt
digest, founder processor authorization, Validator operator, first-contact identity
residual, and the unfalsifiable possibility of provider retention. It remains after a
successful destroy, is not stored in Personal, Company, or `.kin/`, and cannot be
used as evidence that bytes were erased.

That memory creates an obligation rather than posing as an apology. Until delegated
in a signed run record accepted by the named successor, the founder is the standing
post-run security custodian and owns disclosure response and the authoritative
rightsholder roster. A terminal handoff records both parties, acceptance time, contact
route, scope, and predecessor digest; silence or an expired/unreachable delegate
leaves ownership with the founder. The Validator maintains an append-only roster
outside Product stores. Every row binds identity, contact route, granted byte scope,
grant/revocation digest, source authority, `asserted_at`, `verified_at`, and predecessor.
G-8 requires a signed roster snapshot verified within 24 hours before the first
auxiliary-corpus send. Every custody-memory append binds the current snapshot digest;
a change or revocation appends rather than deletes history. Failure to refresh blocks
new auxiliary-corpus admission and expands possible notice scope to every historically
in-scope rightsholder rather than silently dropping a stale row. Possible notice scope
is the roster subset whose granted byte scope intersects the union of observer-
prepared, wrapper-spent, wrapper-forwarded, unexplained cross-check excess, and
policy-authorized-but-unprepared digests while reconciliation is incomplete. Each
adjacent-set delta has the Validator as resolution owner. Before key destruction, a
policy-authorized-but-unprepared row may close only when a local construction-side
receipt proves the request was never constructed and no downstream prepared, spent,
forwarded, or counter row exists; otherwise it remains indeterminate. A candidate
digest leaves that superset only before key destruction when every owned inventory,
wrapper-computed digest/count, and bounded transport envelope reconciles exactly under
a Validator closure record. At key destruction, the memory freezes the exact maximum possible
notice-set digest and cardinality; if reconciliation is incomplete, that maximum is
every historically in-scope rightsholder in the finite admitted corpus manifest.
After key destruction no later inference narrows it. Every `UNRESOLVED_CUSTODY`
notice says explicitly that inclusion follows maximal-superset construction and is not
evidence that the recipient's specific bytes were sent; that limitation is part of
the G-8 grant. The Validator appends an `overbroad_notice_acknowledgment` for each
recipient included without a wrapper-forwarded row, naming the unresolved inventory
that forced inclusion and the recipient-facing explanation. It never claims those
bytes were absent from provider custody.
A shared Company/Codebase leak also invokes the supplemental leak runbook's Company
security-steward and repository-owner duties. Those Product duties do not replace this
provider-custody owner; before a Company steward exists the founder remains responsible,
and an event spanning both boundaries carries both notification/revocation paths.
A credible provider
breach/host compromise, legal demand covering the processor, mismatch in the request
census, or founder request triggers a scoped incident review against the locally-
forwarded and potentially-sent digest superset and notice to the founder plus every named auxiliary-corpus
rightsholder whose bytes may be in scope, within the shorter of 24 hours and the
applicable legal/policy deadline. The memory is retained for the life of the proof
claim; correction is a new linked record, never an overwrite. A missed or materially
wrong notice receives a separately owned incident/apology record naming cause,
affected parties, repair, and closing authority.

Founder ratification of the exact amendment digest and effective bundle root is also
the explicit acceptance that authorized Kinbase repository prompt/tool bytes and
their derived prefix state enter Vast custody, that provider/operator access cannot be
excluded, that first-contact SSH identity has continuity but no independent
attestation, and that destroy does not prove erasure. It also accepts that a provider-
originated disclosure arriving after the required HMAC-key destruction is
`UNRESOLVED_CUSTODY` by construction: notification may be over-broad because absence
or presence can no longer be confirmed. Each auxiliary-corpus rightsholder receives
that confirmation-horizon disclosure in the G-8 rights grant and affirmatively elects
either the default destruction no later than 24 hours after terminal verdict or one
exact incident-confirmation hold expiring no later than the existing seven-day
cumulative maximum. No response selects the 24-hour default; neither choice waives an
erasure request or extends a cited legal deadline. Ratification authorizes
no Personal body, unauthorized Company body, test/oracle byte, credential, customer
data, or unrelated repository. The founder receipt must also state that this is an
irreversible specification disclosure whose one cold-restart allowance is consumed by
the mandatory G-3 rehost, leaving no post-disclosure restart, and that the attempt has
no calibrated completion probability; omission blocks G-1.

The first repository-bearing request exposes the complete nine-member effective
authority bundle to the named processor, including this amendment's account/host
binding, control topology, timeout values, polling cadences, reserve formulas, and
terminal conditions. No observer MAC key, nonce, current ledger/sentinel state,
credential, or secret value is a bundle member. The exact Q-2 decoy corpus, draw,
markers, and Detector artifact are not bundle members, do not exist until the
implementation-blind Tester/Detector sequence, and never enter a Coder or Vast-Coder
request; only the public construction and fail-closed adjudication rule is exposed.

Correctness does not depend on the processor being ignorant of published controls.
Checkpoint and local admission durations use the Validator workstation's monotonic
clock and local filesystem observations, not host/provider timestamps; a provider
cannot pad a local checkpoint measurement. A host can delay a response until the
local timeout cancels it, and a provider can delay settlement until the monotone lag
uncertainty closes admission. Neither delay is favorable evidence. Missing local
pre-send evidence, not provider logs, determines G-3 disqualification. The host can
therefore consume already authorized runtime or force an incomplete/fail-closed route,
but it cannot authorize a locally held body, forge the body-bound local MAC, expand
local readable capabilities, increase the local authorization ceiling, or produce a
`PROVEN` verdict. The 30-second observer hold and 90-second sentinel staleness limits
bound local continuation decisions; they are not confidentiality controls or a bound
on eventual provider liability. Founder ratification explicitly accepts this
disclosed-control availability and residual-cost risk.

### 2.5 Budget and lifecycle

The founder previously authorized USD 300 total route spend. Vast invoice ID
`3420078` records the founder's later USD 100 Stripe top-up at
`2026-09-06T03:30:02.746Z`. This candidate therefore proposes—not yet authorizes—a
`route_spend_cap` `C = USD 400`; only founder ratification of this exact amendment and
bundle activates the increase. Provider observations and two Validator derivations
remain distinct:

- `provider_balance_observations` and provider billing rows are Vast-issued facts,
  retained with provider timestamps/identifiers when present; they do not attribute a
  charge to this route by themselves. Vast alone owns settled provider charges;
- `validator_derived_provider_spend` is Validator-owned and derives route spend from
  successive provider observations plus separately recorded credits/non-route account
  activity. Its attribution assumes no unrecorded account activity and carries that
  residual; and
- `validator_elapsed_estimate` is Validator-owned, monotonically nondecreasing, and is
  the sum across immutable `(instance, host, billable-state)` segments. Each segment
  prices all of its elapsed time at the greatest rate observed for that segment/state,
  adds observed one-time/non-rate charges, and never resets accumulated route spend
  when a host or instance changes.

`budget_policy_value = max(validator_derived_provider_spend,
validator_elapsed_estimate)` is not another fact and has no owner. It is a policy
function evaluated fresh at each admission. The ledger persists the two inputs,
timestamps/rate samples, and resulting allow/deny decision, never the derived scalar
as authority or something to reconcile with Vast. The Validator owns only the
admission authorization, not provider spend. Define
`settlement_lag_exposure_usd = greatest_observed_billable_rate_usd_per_hour *
greatest_observed_positive_settlement_lag_seconds / 3600`. The rate is the monotone
maximum across every route segment from first instance creation through the current
admission evaluation. For a segment that can be attributed, lag seconds are measured
only on the Validator's monotonic clock from its locally recorded segment end to the
first locally received provider balance/invoice observation that settles that segment;
provider timestamps never supply elapsed duration. A delta that cannot be attributed
is an unresolved absolute account delta rather than a fabricated lag sample. Both
inputs and the derived USD value are recorded. Delayed settlement can only retain or
increase uncertainty and close admission; it can never free authorization. Each
admission row records
`authorization_uncertainty = max(USD 2.00, settlement_lag_exposure_usd,
sum of unresolved absolute account deltas) + unconfirmed_destroy_exposure_usd`,
where the final term is zero unless a destroy lacks a terminal receipt and then grows
at the greatest observed running rate until resolution, and
`authorization_remaining = C - budget_policy_value - authorization_uncertainty`.
The USD 2.00 floor is the explicit invoice-versus-estimate tolerance; polling cadence
is not mislabeled as one. No action treats the uncertainty band as available money.

Every reconciliation records the provider inputs, both derivations, timestamps, rate
samples, and the Validator-owned self-consistency signal
`estimator_divergence = validator_derived_provider_spend -
validator_elapsed_estimate`. It is not a provider-spend fact or cross-owner
reconciliation. A negative delta is
expected settlement lag and is recorded while the larger local estimate controls. A
positive delta beyond `max(USD 2.00, two minutes at the greatest observed running
rate)` closes new-turn admission because the Validator cannot safely authorize spend
while its own attributions disagree; it is not evidence that either estimate owns the
provider's bill. The Validator owns attribution and has at most two
minutes, charged to the reserve, to record the delta, lag classification, known credit/
account activity, and whether the envelope remains exceeded. Otherwise it stops before
disclosure or destroys after disclosure and emits
`UNFUNDED_BY_RECONCILIATION_STALL` plus a Validator-owned apology. A provider timestamp
that moves backward or balance that increases without a separately observed credit is
invalid for authorization; it creates an `unattributed_account_delta` row containing
direction, amount, observation digest, and the Validator as resolution owner with
founder escalation. The same two-minute attribution window applies; expiry appends
`UNRESOLVED_ACCOUNT_DELTA` and its Validator-owned apology, and the full absolute
amount remains in `authorization_uncertainty`. The monotonic local estimate controls
until resolved. A
later settled correction appends a linked record. If an overestimate ended a funded
route early, the Validator—not the provider—owns the false-`UNFUNDED` apology; if
settlement exceeds the estimate, the operator owns the overspend apology. Neither
record rewrites the observation.

Every `provider_custody_memory` also records both directions of every adjacent
request-set difference—authorized/prepared, prepared/spent, spent/forwarded, and
forwarded/diagnostic transport—each as a count plus digest of canonically sorted
request digests. A downstream row without its required upstream authorization is a
policy violation; any spent/forwarded/transport excess is an unauthorized-disclosure
incident. An upstream-only row never proves absence. The Validator owns each delta and
must within the two-minute attribution window either bind a local receipt proving the
request stopped at that exact stage or mark it indeterminate; an indeterminate row
remains in the potentially-sent notice superset through key destruction. These
directional deltas preserve each owner's fact rather than collapsing policy intent,
local preparation, local forwarding, and provider custody.

The route began at approximately USD 300.014 credit. At the review-window stop on
`2026-09-06T01:56:00Z`, Vast reported USD 246.4946 remaining, instance
`50012413` stopped with its 1 TB disk retained, running rate USD 34.0022/hour, and
stopped-storage rate USD 1.3707/hour. Thus staging and qualification had consumed at
least USD 53.52 and the balance represented about 7.25 gross full-rate hours before
later storage charges. These observations are capacity evidence, not a promise that
seven hours completes the Product.

At `2026-09-06T02:43:38Z`, the instance still reported
`actual_status=exited`/`intended_status=stopped` on the same machine/host and the
account reported USD 245.4015 remaining. At `2026-09-06T03:21:16Z`, the later
observation in `evidence/factory-run/vast-review-window-status-004.md` reported USD
244.5484. At `2026-09-06T03:41:03Z`, status 005 reported USD 344.0966 and the same
stopped host/rate. The provider invoice endpoint attributes USD 100 of that increase
to the Stripe credit named above; the approximately USD 0.4519 net difference agrees
with the previously observed stopped-storage rate over the interval. Under the
proposed cap and excluding the approximately USD 0.014 pre-route balance,
route-authorized remaining was about USD 344.08 at status 005. Every later minute
reduces it, and G-2 always samples live.

The later privacy-minimized observation at `2026-09-06T04:36:25Z` in
`evidence/factory-run/vast-account-control-observation-001.md` records provider fields
`billing_creditonly=1`, `autobill_amount=None`, and `autobill_threshold=None` with USD
342.8348 credit. G-2 requires those three control fields to remain credit-only/no-
autobill before every launch and closes admission on change. This is defense in depth,
not a provider SLA or liability bound: stopped storage, delayed settlement, and an
unconfirmed destroy still block terminal closure as specified below.

Admission uses formulas, not optimistic threshold labels. For prospective admission,
`R` is the greater of the current offered running rate and every running-rate sample
already observed for the proposed open segment. Define:

- `cold_load = 0.5R`;
- `runtime_qualification = 0.5R` for G-4 parser, sandbox, egress, and recovery drills;
- `warm_authoring = 5R`;
- `turn_timeout_seconds = 1620` (27 minutes) and
  `sentinel_staleness_seconds = 90`;
- `stop_destroy_reserve_seconds = max(120, 2 * greatest observed completed provider
  stop/destroy latency)`; this is an accounting floor, not a provider-latency estimate
  or upper bound. G-4 times two no-repository disposable-instance controls and may
  only increase it. If the provider has not produced a bound stop/destroy receipt by
  that deadline, local traffic remains revoked, the instance is presumed live, and
  the route emits `UNCONFIRMED_DESTROY` and enters `UNRESOLVED_CUSTODY`. From the
  attempted-destroy timestamp until a trustworthy terminal provider observation,
  the greatest observed running rate times elapsed time accumulates without bound in
  `authorization_uncertainty`; no Kinbase action waits on or treats the provider
  timeout as successful cleanup. G-2 and G-11 cannot close, and no terminal monetary,
  custody, or proof claim may be issued until a trustworthy provider terminal
  observation plus billing reconciliation or account closure resolves the exposure.
  `C` is only a local authorization ceiling and is not represented as a cap on
  provider liability;
- `max_in_flight_turn = max(0.5R,
  ((turn_timeout_seconds + stop_destroy_reserve_seconds) / 3600) * R,
  ((sentinel_staleness_seconds + stop_destroy_reserve_seconds) / 3600) * R)`; and
- `charge_reserve = 6 * greatest_observed_stopped_hourly_rate +
  ((poll_interval + stop_destroy_reserve_seconds) / 3600) * R + USD 10.00`, where
  the poll interval is 60 seconds. Stopped-cache exposure and provider-stop latency
  may occur in one lifecycle, so they add rather than masquerading as alternatives.
  The final
  USD 10.00 pessimistically covers bandwidth, provisioning, rounding, and unclassified
  non-rate charges; any observed higher class immediately replaces it;
- `operational_contingency = 0.10 * (cold_load + runtime_qualification +
  warm_authoring + max_in_flight_turn + charge_reserve)`, retained throughout the
  attempt rather than consumed as planned work; and
- `measured_262k_cold_prefill_seconds` is the G-4 cache-cold full-bound request
  measurement under the pinned runtime. It is not a separately funded term: any
  post-disclosure restart prefill consumes seconds and dollars from
  `remaining_warm_authoring`; and
- `cold_restart_contingency = cold_load + runtime_qualification` until the one allowed
  replacement cold-load/qualification begins, whether for the required G-3
  pre-disclosure rehost or a later preemption, then zero with an immutable consumed
  receipt.

At the recorded rates those terms are USD 17.01 + 17.01 + 170.02 + 17.01 +
19.93 = **USD 240.98** (rounded upward per term), operational contingency is USD
24.10, and one cold-restart contingency is USD 34.02: **USD 299.10** total. Against
status 005, route-authorized remaining was about USD 344.08 and authorization
remaining after the USD 2.00 uncertainty floor was about USD 342.08. The historical
unallocated margin at `2026-09-06T03:41:03Z` was therefore at most USD 42.98.
The USD 299.10 already includes the USD 34.02 G-3 replacement reserve. When that
rehost begins, the reserve is atomically marked consumed while its actual cold-load/
qualification charge enters `budget_policy_value`; it is not added a second time.
At the illustrative exact charge, `authorization_remaining` falls from USD 342.08 to
USD 308.06 while the remaining obligation falls from USD 299.10 to USD 265.08, leaving
the same at-most USD 42.98 margin before subsequent storage, rate, or uncertainty
movement. Every live observation replaces this illustration.
Before restart, `authorization_remaining` must cover all five terms and
both then-applicable contingencies. After the server is warm
and G-4 passes, it must still cover remaining warm authoring, the in-flight/charge
reserves, operational contingency, and any unconsumed cold-restart contingency;
actual cold-load and qualification spend stay consumed. If either inequality fails, the route is
`UNFUNDED` before a repository-bearing request; scope and quality gates are not
reduced. The proposed ceiling therefore funds at most five protected warm Coder hours
in total plus one restart's cold load and qualification at the observed rates, subject
to every live gate. It does not fund five new warm hours or a separate prefill after a
restart: prefill and preemption consume time from the same five-hour allocation, and
resumption receives only the unspent remainder. A post-disclosure restart is admitted
only if remaining warm seconds cover the measured cold-prefill seconds, one 1,800-
second work slot, and the still-unspent portion of the 1,800-second control reserve.
Five hours is a
founder-authorized allocation only upon ratification, not a duration calibrated from prior complete Rust
Kinbase runs; no completion probability is claimed. Completion is the G-6 predicate:
one clean final Rust HEAD whose reachable Coder series maps every effective P-1 through
P-10 obligation to implemented paths and implementation-owned checks. Anything less
is an incomplete attempt, even if its Validator-custodied checkpoint is useful later.

The same inequality defines a rate ceiling rather than assuming the current auction
price persists. With authorization-remaining amount `A`, stopped rate `S`, stop/destroy
reserve `D`, the operational contingency active, and the one-restart allowance still
unconsumed, restart is allowed only when
`1.10 * (6R + max(0.5R, ((1620 + D) / 3600)R,
((90 + D) / 3600)R) + 6S + ((60 + D) / 3600)R + 10) + R <= A`. At status 005,
`A` was about 342.0825, `S = 1.3707`, and initial `D = 120`; before the required
destroy-control measurement, the prior USD 39.25/hour figure is only an illustrative
upper bound, not an admissible rate. G-4 fixes `D`, records prefill duration for the
warm-clock restart gate, recomputes every monetary term and the actual rate ceiling,
and returns `UNFUNDED` before repository source exposure if it no longer fits. Any
offered/current rate above
the recomputed ceiling refuses restart or closes the next-turn gate. Cent rounding is
presentation only and contributes no claimed safety margin.

The five-hour warm-authoring clock begins with—not after—a separately manifested,
maximum-20-minute value-of-information turn. That first ratified disclosure tier
contains only the nine effective-authority artifacts plus the fixed planning prompt/
tool schema: no implementation source, `.kin/`, Factory evidence, prior art, tests, or
oracle. Its request receives its own observer/custody row. Before any broader Coder
read mount or editing, GLM produces an obligation-to-module/command plan covering
every P-1 through P-10 surface and orders its critical path. The plan schema has no
effort, duration, slice-count, completion-probability, or fits-budget field; any such
field is rejected. The Validator checks coverage against the effective behavior ledger
and records actual prefill/decode/tool latency.
Every effective behavior-ledger row and amended obligation must map to at least one
named work package with concrete output paths, an executable module/command boundary,
a completion predicate stated as an observable exit/stdout/state transition, and an
implementation-owned check command plus expected observation. Copying or paraphrasing
the obligation is not a predicate or check. Each package names its predecessor
packages and the ledger rows it closes; duplicate placeholder packages and an unmapped
obligation fail as `INVALID_PLAN`. The plan is decomposition/order input only and is
never Product, effort, or completion evidence. Expected dependency/bootstrap transitions
must be named as work packages before source exposure; after source exposure, a new
transition consumes the next deterministic runtime slot or fails the continuation
gate. There is no model-produced effort forecast to show, hide, calibrate, or use as a
decision input. Five protected warm hours means total
running Coder-lane wall time, including model, tools, journal, reconciliation, and
quiescent checkpoint work—not five hours of pure decoding. Reserve 10% of that window
for those controls. After the VOI turn, compute
`remaining_runtime_slots = floor((warm_seconds_remaining - 1800) / 1800)`, where the
fixed 1,800 seconds is that 10% control reserve. At a fresh five-hour window after a
20-minute VOI turn, eight maximum-30-minute slots remain.
`remaining_runtime_slots < 1` fails immediately as `UNFUNDED`. Slots are admitted one
at a time and are clock partitions, not model assertions that a work package will fit
or finish. A next slot may begin only when the prior slot has reconciled, its completed
work-package predicates and implementation-owned checks (if any) are recorded, its
outputs remain mapped to the frozen ledger, a quiescent checkpoint exists, and the
live budget/watchdog equations fund that one slot plus all reserves. An incomplete
work package stays incomplete and may consume another slot only through the same gate;
neither the plan nor the model can reserve future slots. This makes continuation a
realized-work stopping rule rather than a forecast gate. Exhaustion destroys the
instance and asks the founder for more route funding; no answer or a refusal terminates
the route as incomplete. The problem is not relabeled as a smaller PoC. Crossing the
first request remains an authorized irreversible disclosure of the specification
bundle, but the coverage decision arrives before
implementation, `.kin/`, evidence, or test bytes can be exposed.

If live recomputation closes admission during a slice, it does not pretend to recover
spent money or complete the slice. The current tool is canceled at its frozen boundary,
reconciled, the last quiescent checkpoint/prior-art manifest is retained under its
30-day rule, the instance is destroyed after disclosure, and G-6 remains incomplete.
This is bounded salvage, not a renamed milestone or proof result.

Dollar authorization is authoritative; hour figures are descriptive conversions at
sampled rates. Once running, a capability-separated local monitor polls provider status,
current price, balance, and local elapsed-rate spend every 60 seconds, appends/fsyncs
a sample, accumulates every immutable host/state segment, and recomputes prospective
terms at the greatest rate observed for the proposed open segment.
A second sentinel with no Coder/gate write capability requires a fresh monitor sample
at least every 90 seconds; otherwise it denies new traffic and invokes stop/destroy.
Provider timestamps must advance monotonically and balance may rise only with an
independently recorded credit; an anomaly is ignored for authorization while the
local estimate continues. A price decrease closes the next-turn gate until rebound;
a price increase or host change cancels the active model request and closes all later
traffic. A new turn is admitted only
when `budget_policy_value + max_in_flight_turn + charge_reserve +
operational_contingency + cold_restart_contingency <= C`.
During a turn, any observed running-rate increase above the admission-bound rate
immediately cancels the model request and closes later traffic; G-4 injects such an
increase and measures cancel-to-destroy latency against the reserves. If the current
`budget_policy_value + charge_reserve + operational_contingency` would reach `C`,
the sentinel starts the same terminal sequence. Every sentinel terminal path first
revokes new model/egress/tool admission and cancels the model request; any already-
started local mutating call reaches its frozen timeout and runs its postcondition
reconciliation; only then does the sentinel destroy the instance and classify the
last local tree as a quiescent checkpoint or inadmissible crash artifact. The 27-minute
in-flight reserve includes this ordering; failure to finish reconciliation inside it
defaults to crash artifact and destroy, never replay. Independently of monitor health, the
sentinel forcibly cancels every model turn at 27 minutes; its stale-monitor path fits
the separately computed in-flight reserve. Because provider
billing can settle late, `C` is a hard **local authorization** ceiling, not a
claim that a polling client can force the eventual invoice to equal or remain below
exactly `C`.

The monitor also requires an authenticated heartbeat every five minutes from the
capability-separated local Validator supervisor. That daemon emits only while its run-
control loop, journal fsync, sentinel channel, and destroy credential path are healthy;
Coder/gate processes cannot write it. Loss of the heartbeat closes new-turn/tool
admission; an active operation reaches its frozen timeout, is reconciled, and the
instance is stopped before any repository send or destroyed after one. This is an
automated liveness signal, not a human click or presence requirement; no human must
stay awake merely to keep a safe default alive.
Any settled overspend appends the owned exception/apology record described above and
is never silently absorbed.

Public-weight download, pre-ratification probes, runtime qualification, failed turns,
running idle time, and stopped storage all count. No further pre-ratification
inference is permitted after the recorded review-window stop. Before the first
repository send, a stopped instance may retain the public staged cache for at most
six hours. At stop, the monitor fsyncs an absolute UTC deadline, monotonic deadline,
and local boot identifier; a restart reads rather than recomputes them. Expiry occurs
at the earlier of the UTC deadline and monotonic deadline. A changed or unreadable
boot identifier makes the monotonic deadline already expired. The separately
permissioned local sentinel evaluates that rule even if monitor samples stop and
invokes destroy at expiry; it retains the shared-root limitation stated for Q-0.
A false early expiry destroys and may restage once rather than weakening a gate; its
measured cost enters `validator_elapsed_estimate` before new admission and receives a
monitor-owned apology record. A second deadline-attributed destroy in one route
generation emits `UNFUNDED` and requires a new founder decision rather than automatic
restage. A missed deadline appends a monitor-owned exception
naming the overrun, attributable settled storage charge, and resulting change to
`authorization_remaining`.
At the true deadline the Validator restarts only if all gates admit, otherwise
destroys and reports that a future host must restage. After the first repository send,
operator-initiated stop-with-disk-retained is prohibited. Stopping is not terminal
cleanup. Terminal completion, abandonment, review pause, or budget denial destroys
the instance and retains the sanitized local ledger and provider-custody memory
described above.

This proposed USD 400 ceiling funds only Rust Coder infrastructure/authoring and its
required qualification. It neither funds nor determines V-10 pilot/measurement N. V-10 uses
the separate existing rule: pilots estimate fully loaded cost and covariance, the
fixed power program chooses N before measurement, and the founder must separately
ratify/prepay the complete aggregate coding-and-grading ceiling. No pilot or
measurement cell runs on “whatever fits” in this five-hour protected warm-authoring
allocation, and no partial Coder turn is an experimental observation.

The structural minimum is already large before power chooses N: twelve excluded pilot
tasks x eleven arms x three seeds = 396 coding cells, and the minimum eight-task
measurement x eleven arms x three seeds = 264 more, for at least 660 coding cells and
1,320 two-grader measurement/pilot score passes, plus calibration and reserves. This
is only the arm x seed x minimum-task structural floor; the post-amendment power
program is expected to exceed it, potentially substantially. It is not a cost estimate
and is not funded by the proposed USD 400. Before G-10, the pilot plan must report
pre-amendment and post-amendment power-selected N side by side and price the full
post-amendment census;
the founder sees and ratifies the complete ceiling before any pilot outcome. If the
number is unacceptable, the concept is honestly `UNFUNDED_OR_UNDERPOWERED`, not
quietly “validated” by the Rust build.

### 2.6 Proof-gate corrections discovered before any pilot

No V-10 pilot or Product run is admitted in this generation, so the P-10/V-10 changes
repair pre-outcome falsifiability rather than tune a threshold after performance. The
P-5/V-5 change has different provenance: reviewers saw the aborted Python generation's
test-only case selector and rejected it as self-attesting, while its recorded V-5
Product status remained `NOT_RUN`. The amendment therefore responds to an observed
harness-design defect, not a Rust Product outcome, and does not call that history
outcome-blind. All prior V-1 through V-9 matrices, fixtures, reports, and partial
results remain explicitly historical, excluded from the Rust author mounts, and
inadmissible as fresh evidence. Each change requires a fresh implementation-blind
Tester instrument, Detector Review, pilot, power simulation, and effective run manifest.

These corrections are logically distinct from the language/provider substitution but
remain in one effective-generation bundle because P-5/P-10 behavior and V-5/V-10
instrumentation are implementation surfaces assigned to the Rust Coder and fresh
Tester. Ratifying the runtime change alone would knowingly dispatch both authors
against obsolete proof semantics and require a mid-lane authority change. The overlay
receipt keeps each operation separately auditable even though the generation freezes
atomically.

#### Temporal discrimination cannot pass by universal abstention

In `spec/product.md` P-5 insert after this exact anchor:

> Expected results must demonstrate neither newest-wins nor
> oldest/highest-authority-wins blindly. Every decision emits an inspectable evidence
> trace and uncertainty state.

this new paragraph:

>
> The deterministic acceptance matrix contains at least as many current, unexpired,
> single-authority cases whose required result is a substantive fact as genuine
> conflict/expiry cases whose required result is `Unknown`. Every cell freezes its
> expected state and a negative mutation. A false `Unknown` in the substantive mirror
> set is a P-5 failure; universal or strategically excessive abstention cannot pass.
> At least half of the substantive mirror set is superficially conflict-shaped: it
> includes two-source cases where one source is expired, superseded, out of scope, or
> non-authoritative, yet the other current authority requires a substantive answer.

In `spec/verification.md` V-5 insert after this exact anchor:

> Every case freezes `as_of` and authority cursor and asserts the reducer trace and
> counterfactual. Mutations newest-wins,
> highest-authority-always-wins, and repetition-as-independence must each fail.

this new paragraph:

>
> Add a substantive mirror set at least equal in count to genuine-`Unknown` cases.
> Each mirror cell has one current, valid, unexpired, in-scope authority and expects
> its substantive fact, not abstention. V-5 requires zero false `Unknown` results on
> this deterministic set and includes mutations that replace a resolvable fact with
> `Unknown` or treat every conflict as permanent. A single surviving mutation or
> false `Unknown` fails V-5. Report the superficially conflict-shaped stratum
> separately and require zero false `Unknown` there as well; easy single-source padding
> cannot satisfy the mirror requirement. At least half of substantive cases are
> one-to-one matched to genuine-`Unknown` cases on source count, source classes, scope,
> timestamp/validity-field presence, and decoy-prose/token-length band. Within a pair,
> only one preregistered policy-relevant resolving predicate (authority, scope, expiry,
> or supersession state) may change the required result. Before implementation or model
> outcomes are visible, a fresh reviewer who did not author the cases freezes pair IDs,
> the resolving predicate, token-length band, and a no-trivial-lexical-cue finding.
> Every superficially conflict-shaped substantive case must be an admitted member of
> that matched-pair stratum, and matched pairs comprise at least half of the complete
> substantive set. Unpaired admitted substantive cases count only toward the overall
> substantive-mirror count, never toward the conflict-shaped or matched-pair minima.
> Reviewer-rejected candidates are excluded before matrix freeze and remain in a
> rejection census; they are not cases and cannot cause deletion of a genuine-
> `Unknown` case. The Tester supplies, before review, a frozen candidate pool at least
> twice the required matrix size. The fresh reviewer performs one admission pass; if
> the admitted pool cannot satisfy all counts, the result is `INVALID_HARNESS` rather
> than iterative case invention. A conforming worked count is 20 genuine-`Unknown`
> cases and 20 admitted substantive cases, of which 10 conflict-shaped substantive
> cases are paired one-to-one with 10 distinct genuine-`Unknown` cases; those 10 pairs
> satisfy both half-set minima and the other 10 substantive cases test ordinary valid
> authority.

#### Authority-only is a competent causal comparator

In `spec/product.md` P-10 replace this exact old arm definition:

> - `authority-only`: baseline context with no maintained corpus or projector, required
>   to consult the identical frozen authority-answer service for the preregistered one
>   or two fact-only questions for that task;

with this exact new definition:

> - `authority-only`: baseline context with no maintained corpus or projector,
>   required to consult the identical frozen authority-answer service for the one or
>   two neutral fact-only questions frozen by the schema-blind Oracle Curator as the
>   strongest competent questions available from pre-change evidence for that task;

The Oracle Curator freezes those questions, response bytes, scope handling, call
order, and `NO_KNOWLEDGE_AVAILABLE` behavior before candidates while seeing no
Kinbase design or candidate. The arm uses the same coding model, system prompt,
repository, tools, latency, and wall/tool/token budgets as baseline/full-system; only
the preregistered arm difference remains. At least one independently sourced,
load-bearing oracle fact must be absent from the authority replies and available only
through the maintained corpus, and the two replies together may not contain the
complete oracle, code, patch, or hidden-test guidance. Otherwise the task is
`AUTHORITY_ONLY_COMPLETE_ORACLE` and ineligible before the draw. These rules make the
new margin harder rather than permitting the harness author to weaken the comparator.

The Curator is a fresh role in a filesystem/prompt lane independent of Product and
harness authorship and is instructed to maximize—not handicap—the authority-only
control under a fixed time/tool/call budget. No claim of separate corporate employer
or human identity is implied unless its receipt names one. Its selection procedure,
effort budget, candidate-question census, exclusions, and output digest freeze before
task draw and before it sees any arm output. An outcome-blind auditor verifies the
procedure mechanically. Before the task census is admitted, the same frozen Curator
must pass a preregistered calibration subset of authority-sufficient tasks constructed
from pre-change history: its selected one/two questions and frozen replies must let the
same coding model reach the fixed functional threshold under the arm budget. Calibration
tasks are excluded from pilot/measurement, their task/question/reply/expected-result
digests freeze before Curator launch, and failure is `INVALID_HARNESS`. This is a
positive control for under-effort, not evidence that measurement tasks are solvable by
authority alone. Curator failure or discretionary post-output revision is
`INVALID_HARNESS`; it cannot create the required 0.10 margin by weakening the
comparator. There is deliberately no favorable fallback if a competent authority-only
arm closes the gap: that result falsifies maintained-corpus incremental value.

#### Functional behavior and maintained-corpus attribution are co-primary

In `spec/product.md` P-10, insert immediately after this exact bullet:

> - `full-system` composite is at least 0.90 and no more than 0.05 below `oracle-spec`;

this new text:

> - the lower 95% bound on the `full-system` held-out functional component is at least
>   0.90, and the complete 95% TOST interval for `oracle-spec - full-system` functional
>   score lies inside [-0.05, 0.05];
> - the lower 95% paired bound on `full-system - authority-only` composite is at least
>   0.10, establishing maintained-corpus value beyond direct authority consultation;
> - the lower 95% paired bound on `full-system - distractor` composite is at least
>   0.10, establishing that relevant maintained information—not token volume—caused
>   the measured gain;

In `spec/product.md` P-10 replace this exact old paragraph:

> `authority-only` is a mechanism-attribution control, not a hidden success gate. If it
> matches `full-system` within 0.05, a passing report must say that direct
> authority consultation, not the maintained corpus, explains the measured gain; if
> the full system matches its quality with fewer authority calls, that efficiency is
> reported but cannot be renamed a corpus-selection effect.

with this exact new paragraph:

> `authority-only` is a co-primary mechanism-attribution control. The lower 95%
> paired bound on `full-system - authority-only` must reach 0.10. A miss is
> `NOT_PROVEN`, even if both arms reach oracle equivalence, because the maintained
> corpus has not shown value beyond competent direct consultation. Authority-call
> efficiency remains descriptive and cannot replace the quality margin.

The P-10 rubric and every oracle explicitly state that Personal, unauthorized,
withdrawn, expired, or out-of-scope evidence cannot define correctness for a coding
decision. The correct answer is the current in-scope Company/Codebase fact or a
properly owned `Unknown`; a private rejection is not a Company withdrawal. This rule
prevents a grader from penalizing safe exclusion of evidence the coding principal was
forbidden to use.

In `spec/verification.md` V-10 replace this exact old co-primary paragraph:

> The causal claim is an intersection-union claim: it passes only when every
> preregistered co-primary endpoint passes, so no failed endpoint is averaged away.
> Co-primary endpoints are absolute full-system quality 0.90, paired lift over baseline
> 0.15, paired lift over `null-system` 0.15, paired superiority over `static-prior` and
> each top-k control 0.10, paired superiority over `codebase-only` on Company-unique
> tasks and `company-only` on Codebase-unique tasks 0.10, authorization-restricted-
> stratum quality/lift/equivalence at the same 0.90/0.15/±0.05 bounds, and overall
> equivalence to oracle-spec within ±0.05. The pilot covariance and one-sided 90% upper variance bounds feed a
> fixed Monte Carlo power program whose Gaussian-copula/resampling dependence model and
> correlation-matrix digest freeze before pilot labels open. It chooses the smallest N
> with at least 80% joint pass probability and rejects any N where an endpoint has less
> than 80% marginal power. Alternatives freeze before the pilot: full quality 0.95,
> baseline and null-system lift 0.20, static/top-k/store-ablation deltas 0.15, and oracle
> gap 0. Pilot effect means never determine N.
> The same simulation powers edit-time residency and false-completion gates from their
> observed denominators. Alpha is 0.05; equivalence uses two one-sided tests and the
> reported 95% interval must lie inside the band.
> The frozen power report lists marginal power and the selected minimum paired-cell
> count for every aggregate and stratum-restricted endpoint, explicitly names the
> binding endpoint(s), and does not borrow aggregate or cross-stratum correlation to
> satisfy an endpoint estimated only on Company-unique, Codebase-unique, or
> authorization-restricted tasks. Before measurement, the task draw must populate each
> such stratum to at least its power-selected paired-cell count after all
> intention-to-treat cells are scheduled. A starved stratum is
> `UNFUNDED_OR_UNDERPOWERED`; another stratum or reserve task cannot substitute for it.

with this exact new paragraph:

> The causal claim is an intersection-union claim: it passes only when every
> preregistered co-primary endpoint passes, so no failed endpoint is averaged away.
> Co-primary endpoints are absolute full-system composite quality 0.90; absolute
> full-system held-out functional quality 0.90; full-system composite and functional
> equivalence to their oracle-spec values within ±0.05; paired composite lift over
> baseline 0.15 and `null-system` 0.15; paired composite superiority over
> `static-prior`, `distractor`, each top-k control, and competent
> `authority-only` 0.10; paired
> superiority over `codebase-only` on Company-unique tasks and `company-only` on
> Codebase-unique tasks 0.10; and authorization-restricted-stratum
> quality/lift/equivalence at the same 0.90/0.15/±0.05 bounds. The pilot covariance
> and one-sided 90% upper variance bounds feed a fixed Monte Carlo power program whose
> Gaussian-copula/resampling dependence model and correlation-matrix digest freeze
> before pilot labels open. It chooses the smallest N with at least 80% joint pass
> probability and rejects any N where an endpoint has less than 80% marginal power.
> Alternatives freeze before the pilot: full quality 0.95, baseline and null-system
> lift 0.20, static/top-k/store-ablation deltas 0.15, and oracle gap 0. Pilot effect
> means never determine N.
> The same simulation powers edit-time residency and false-completion gates from their
> observed denominators. Alpha is 0.05; equivalence uses two one-sided tests and the
> reported 95% interval must lie inside the band.

The fresh excluded pilots and fixed power program include both functional endpoints,
the competent-authority-only margin, and block/refusal/timeout/no-patch outcomes.
They must demonstrate joint feasibility and select N with the existing marginal and
joint power rules before any measurement dispatch. Failure to fund or populate that N
is `UNFUNDED_OR_UNDERPOWERED`; the new endpoints are not removed to make the run fit.

These are the exhaustive preregistered contrasts; the harness does not inspect 55
pairwise arm comparisons and choose winners. Each named lower-bound estimator first
means seeds within task and then uses the existing paired task bootstrap; equivalence
uses the existing two one-sided tests. The claim is an intersection-union claim, so
every co-primary null must be rejected at alpha 0.05 and a miss on any one defeats the
conjunction; no favorable endpoint is selected from a family. Any other arm-to-arm
contrast is labeled exploratory before unblinding and cannot enter `PROVEN`.

In `spec/verification.md` V-10 replace this exact old scoring text:

> - If `distractor` matches `full-system`, context volume explains the result. If
>   `null-system` is not at least 0.15 worse than `full-system` on the lower 95% paired
>   bound, integration scaffolding explains the result and the product is `NOT_PROVEN`.
>   If `static-prior` is not at least 0.10 worse, a generic constant explains the result.
>   If `topk-raw` matches it, corpus+selector added no measured value. If
>   `topk-maintained` matches it, set-conditional/temporal selection added no measured
>   value. If `authority-only` matches it within 0.05, direct authority consultation
>   explains the measured gain; fewer full-system authority calls may establish an
>   efficiency result but not a corpus-selection effect. Each is a named mechanism
>   finding, not a renamed success.

with this exact new scoring text:

> - If `distractor` matches `full-system`, context volume explains the result. If
>   `null-system` is not at least 0.15 worse than `full-system` on the lower 95% paired
>   bound, integration scaffolding explains the result and the product is `NOT_PROVEN`.
>   If `static-prior` is not at least 0.10 worse, a generic constant explains the result.
>   If `topk-raw` matches it, corpus+selector added no measured value. If
>   `topk-maintained` matches it, set-conditional/temporal selection added no measured
>   value. If the lower 95% paired bound on `full-system - distractor` does not reach
>   0.10, context volume has not been separated from maintained information and the
>   result is `NOT_PROVEN`. If the lower 95% paired bound on
>   `full-system - authority-only` does not
>   reach 0.10, direct authority consultation has not been separated from maintained-
>   corpus value and the result is `NOT_PROVEN`. Fewer full-system authority calls may
>   establish an efficiency result but cannot satisfy or replace this co-primary
>   quality gate. Apply the 0.90 full-system functional floor and functional oracle-
>   equivalence gate independently of the composite; no perfect architecture subscore
>   can compensate for functional behavior below the bound. Each miss is a named
>   mechanism finding, not a renamed success.

#### Candidate egress is hold-back, never scrub-and-grade

In `spec/verification.md` V-10 insert after this exact intention-to-treat block:

> - Apply intention-to-treat accounting. A launch becomes admitted when its prompt or
>   model request crosses the sealed launch gate. Thereafter timeouts, refusals,
>   model/agent/tool errors, fail-closed revocation, degraded/empty projection, and no
>   patch remain in the scheduled task/seed/arm denominator. A missing candidate scores
>   zero composite; declaring done without a passing candidate counts false completion.
>   Only a preregistered infrastructure failure proven before admission may consume a
>   reserve. No admitted result is dropped, retried, or replaced.

this new text:

>
> Before any candidate reaches an external grader, the implementation-blind Tester-
> authored and Detector-Reviewer-qualified egress instrument first verifies authorized
> source/tool-result lineage and absence of forbidden provenance, then scans exact
> bytes as defense in depth. Its rules, thresholds, model/configuration if any,
> positive controls, and true-negative decoys freeze before candidates and apply under
> one digest to every arm. Let `M_egress` be the frozen count of every pilot,
> measurement, calibration, and reserve candidate that may traverse the detector.
> Qualification requires zero observed false positives across at least 500 frozen,
> stratified, difficulty-matched decoys spanning every scanner-visible encoding,
> candidate format, boundary position, and benign provenance class in the frozen
> detector contract. At 500 zero-positive decoys the two-sided 95% Wilson upper bound
> for that frozen decoy population is approximately 0.0076; this is reported as a
> calibration statistic only. No exchangeability with future real candidates or field
> false-positive rate is claimed. The statistic is not divided by `M_egress`, is not a
> familywise guarantee, and does not pretend that 500 establishes a one-percent union
> bound over the structural minimum of 660 or any larger powered census. Every detector positive
> is a blocking event before external transmission and receives a frozen, blinded
> provenance adjudication by the Detector Reviewer; it is never silently converted
> into a dropped candidate or favorable per-arm score, so detector error can destroy
> availability but cannot manufacture measured lift. The exact `M_egress`,
> decoy count, construction cost, difficulty strata, draw, and named Tester/Detector-
> Reviewer ownership freeze with the detector and are priced in the separately funded
> G-10 plan. Per-arm holds and detector outcomes are reported while
> arm identity remains blinded. A positive or scanner error holds the original bytes
> locally; the harness
> never sanitizes and grades a derivative.
>
> A mechanically confirmed protected recovery is a zero-scored cell and Product
> privacy failure. A mechanically confirmed false positive or unresolved scanner/
> Detector disagreement is `INVALID_HARNESS`, not a comparator-only zero that can buy
> a lift margin. Both original findings and the hold receipt persist without leaked
> bytes. Scheduled task/seed/arm cells are never dropped or replaced: ordinary
> refusals, timeouts, tool errors, and no-patch outcomes score zero under the existing
> intention-to-treat rule; accumulated failures lower quality, not N.

#### Erasure destroys the incident confirmation key

In `spec/verification.md` Evidence packet replace this exact old paragraph:

> The packet is Validator-owned mode-0700 run state outside Git during execution and
> is transferred only to the founder/security custodian. A sanitized aggregate report
> may be committed; raw Personal data never is. Permanent failure rows contain canary
> ID, keyed-HMAC match, detector/encoding class, destination/location digest, offset,
> and times—not the canary or leaked bytes. The HMAC key and raw incident subject live
> in a separately access-controlled incident vault under its own retention/legal
> decision. “No rerun erases a failure” preserves the sanitized event, not leaked
> Personal bytes past their retention clock.

with this exact new paragraph:

> The packet is Validator-owned mode-0700 run state outside Git during execution and
> is transferred only to the founder/security custodian. A sanitized aggregate report
> may be committed; raw Personal data never is. Permanent failure rows contain canary
> ID, keyed-HMAC match, detector/encoding class, destination/location digest, offset,
> and times—not the canary or leaked bytes. The Tester owns the HMAC key and raw
> incident subject in the separately access-controlled incident vault. The key is
> destroyed with the corresponding raw canaries no later than 24 hours after terminal
> verdict, leaving no confirmation key behind the permanent HMAC, unless founder and
> named security custodian sign the exact incident hold already defined below. A hold
> has one `expires_at`, cannot be silently renewed, and has a seven-day cumulative
> maximum unless a cited legal obligation names the authority and exact later deadline.
> A subject erasure request destroys immediately unless that recorded legal obligation
> controls; the sanitized hold digest/expiry and later destruction receipt remain
> without raw material. Destruction deliberately closes the mechanical confirmation
> horizon. A later suspected disclosure is `UNRESOLVED_CUSTODY` with the available
> request/surface evidence and cannot be upgraded to confirmed absence or presence
> from the orphaned HMAC. Privacy/erasure wins over indefinite forensic convenience.
> “No rerun erases a failure” preserves the sanitized event, not leaked Personal bytes
> past their retention clock.

For avoidance of doubt, `.kin/events` contain only exact approved minimized Codebase
fact/reference bytes plus authority metadata, while `.kin/manifests` contain digests,
counts, and heads. They contain no Personal body, transcript path/digest, stable
cross-store correlation ID, secret, raw canary, HMAC key, or reversible mapping.

## 3. Failure modes

1. Model/image staging is incomplete, an H200 fails, or the host changes. No inherited
   launch fact survives; rebind the exact host and rerun every infrastructure gate.
2. GLM-4.7/4.5 compatibility parsers corrupt GLM-5.3 text, reasoning, arguments, or
   continuation. The parser probe fails closed; changing configuration creates a new
   binding and complete requalification.
3. BF16 KV cannot sustain the bound 262K request. FP8 KV is not silently substituted;
   a change is separately reviewed because it changes effective inference.
4. Pre-ratification egress is not byte-manifested and sandboxed, a forbidden positive
   control passes, a host key differs, or the inference port is public. Dispatch is
   blocked. An actual unauthorized send is retained as an irreversible failure that
   later approval or deletion cannot cure.
5. The model drives a local tool outside the Coder capability set, general network
   remains reachable, or an inherited descriptor exposes another lane/store. Stop
   the run; the untrusted inference endpoint never gains local authority by emitting
   a tool call.
6. A response/tool interruption produces ambiguous mutation state, duplicate effect,
   missing completed local event, or a forced fresh thread. Do not replay the mutation
   automatically; retain the ambiguity and block until postcondition reconciliation
   or a new reviewed recovery path.
7. The checkpoint cycle misses a fixed phase/870-second deadline, a mutation would
   exceed the exact tree cap, the spend watchdog closes admission, the next turn
   cannot fit its reserve, or the stopped-cache deadline expires. Reject the cap-
   exceeding mutation or stop/cancel/destroy as specified and report
   `CHECKPOINT_CAPACITY_EXCEEDED`, `UNFUNDED`, or incomplete Coder work; do not narrow
   Product scope.
8. The old Python tree contains Tester/oracle contamination, has incomplete provenance,
   or appears in the Rust candidate. Deny the whole historical snapshot or reject the
   candidate; selective model instructions do not repair the channel.
9. The new Tester reads Rust/Coder state, carries forward an old admission by rename,
   or adapts only launch plumbing while leaving Python-shaped assumptions. Invalidate
   the Tester artifact and dispatch a fresh implementation-blind generation.
10. Rust preserves shapes but omits behavior, recreates a universal store/process,
    weakens canonical bytes, or treats type safety/build success as authority. The
    Coder has no successful terminal state until one clean final HEAD whose reachable
    Coder-owned commit series covers every P-1 through P-10 implementation surface and
    ends `FACTORY_STATUS: DONE <sha>`; that series remains an unjudged candidate,
    never Product evidence. Earlier coherent commits may survive as unauthoritative
    recovery material without being called completion.
11. Full-system functional quality/equivalence or maintained-corpus lift over the
    competent authority-only arm misses. The terminal measurement is `NOT_PROVEN`;
    composite weighting or favorable narrative cannot hide the miss.
12. Candidate egress detects protected recovery, false-positive qualification fails,
    or a recovery dispute is mechanically unresolved. Hold the bytes and apply the
    exact Product-failure or `INVALID_HARNESS` disposition; never scrub and grade.
13. The named-human auxiliary-corpus rights grant is absent. Detector admission and
    any downstream combination remain blocked even if code and tests are complete.
14. Observer durability stalls, its volume fills, or wrapper body/MAC equality fails.
    No held body crosses; cancel/reconcile locally, destroy the host, retain the owned
    custody/cost record, and leave G-6 incomplete.
15. The prior requests to cached instance `50012413` lack trusted local pre-send wire
    capture. That instance is ineligible for repository bytes and is destroyed; a
    fresh Q-0-observed host consumes the one restart allowance rather than inheriting
    qualification.
16. Provider destroy does not return a trustworthy terminal receipt inside the
    accounting floor. Presume the instance live, keep egress revoked, accumulate
    open-ended spend/custody uncertainty, and escalate; elapsed time is not success.
17. The macOS artifact contains an external-classifier module, command, configuration
    variant, launcher, identifier string, or accepts a hostile Linux-only classifier
    invocation. G-9 fails with `UNSUPPORTED_UNPROVEN_PLATFORM`; Linux proof cannot
    cover an unexercised second platform implementation.

## 4. Constraints

- All P-1 through P-10 behavior, V-1 through V-10 verification, threat catalog,
  source authority, exact error dispositions, and privacy boundaries remain binding.
- Rust and Vast do not reduce scope; the proof must still do the complete thing.
- No repository-derived byte reaches Vast before exact founder and Validator
  ratification plus a passing structural egress gate. Synthetic qualification admitted
  into this generation has an exhaustive byte manifest and positive denial control;
  the earlier pre-Q-0 probes are historical observations only. Their missing trusted
  local pre-send wire capture deterministically disqualifies instance `50012413` and
  forces rehosting.
- Model artifact manifest, image digests, serving configuration, parser choices,
  provider/account/host, SSH key, Coder harness, tool capability policy, egress gate,
  spend monitor, and response fingerprints are immutable run inputs.
- Agy remains resident and non-authoring; Coder, Tester, and Validator roles remain
  separated.
- The Rust Coder cannot read tests or Tester findings. The Tester cannot read Rust
  implementation.
- Local tool execution is OS-confined to the enumerated Coder/run roots and network
  destinations. The initial generation has no historical-implementation root; a later
  separately amended generation could add one read-only manifested root. All Product
  writes remain in the isolated Rust Coder repository.
- No Personal or customer data may be used in infrastructure or compatibility
  probes.
- Completed Coder events and bounded worktree progress survive model-host/tunnel loss
  from workstation authority; ambiguous mutations are reconciled, never blindly
  replayed. Provider prefix state is explicitly provider-accessible repo-derived
  custody and is never recovery or erasure evidence.
- Factory receipts live in the Validator run ledger, not in Personal, Company, or
  `.kin/`; using an unproven Product store to prove its own run is forbidden.
- No old Tester, Detector, canary, builder, oracle, pilot, or unstarted-manifest
  admission carries into this generation without the explicit fresh disposition in
  section 2.3.
- Budget and time pressure may end the route as incomplete or `UNFUNDED`; it cannot
  relax gates, change model family, leak lanes, or create a smaller claimed PoC.
- A passing build, translation completion, or model-server health check is not a
  product or proof milestone.

## 5. Assumptions

1. **Measured infrastructure fact, not Product evidence:** the pinned model/runtime
   sustained a 262,067-input-token synthetic request with BF16 KV on the observed
   8xH200 host, and the simple Responses/tool/full-replay loop worked. Host restart,
   expanded parser cases, structural egress, watchdog, and ambiguous-mutation recovery
   remain pre-dispatch gates.
2. **Conditionally resolved feasibility, still acceptance-gated:** the offline survey
   found safe public dependency APIs for descriptor execution, descriptor-relative
   open, no-symlink/beneath resolution, and Landlock on Linux while first-party crates
   forbid unsafe code. Final crate checksums, audit, Linux hard-requirement status,
   live Linux denial probes, and macOS artifact-omission/configuration-denial probes remain mandatory.
   macOS has no external-classifier implementation in this generation and cannot claim
   that boundary; a failed Linux gate blocks rather than hiding the boundary in an
   exception.
3. **Capacity risk, not a scope premise:** at the recorded rates and proposed USD 400
   cap, the remaining credit funds the specified load/qualification, five protected
   total warm Coder hours, maximum in-flight turn, charge reserve, 10% operational
   contingency, and at most one cold restart's load/qualification. G-3 necessarily
   consumes that allowance on a fresh pre-disclosure host. It does not establish that
   GLM can finish the complete Product in that window; deterministic runtime-slot gates
   and actual progress determine whether to request more funds. Exhaustion is an honest
   `UNFUNDED`/incomplete result.
4. **Historical input excluded:** the old Python implementation might contain useful
   prior art, but the initial Rust generation does not mount it. GLM proceeds from the
   effective authority alone; any future use requires a new exact amendment and the
   full contamination/manifest gate.
5. **Fresh-instrument feasibility risk:** Claude can author a Rust-neutral complete
   Tester artifact from effective authority without implementation access. Failure
   blocks combination and is not repaired by importing old admission status.
6. **Provider assertion only:** Vast reports that destroy removes instance storage.
   The design assumes no stronger erasure fact and permanently records residual
   custody uncertainty.
7. **Measurement feasibility risk:** the new functional and competent-authority-only
   conjuncts may require a larger N or reveal that maintained-corpus value is not
   separable. The pre-outcome power run or final outcome is allowed to say so.

## 6. Limitations

- Rust does not prove memory safety of dependencies, policy correctness, privacy,
  or product value. It narrows first-party memory-unsafety and deployment variance.
- A verified Vast host is still a third-party marketplace custody boundary; this
  amendment does not claim confidential-computing, remote attestation, or host-
  operator exclusion.
- The 262K Coder context is below the model's advertised maximum. The proof needs a
  coherent build, not a maximum-context serving benchmark.
- The Coder's 262K serving context is a Factory input unrelated to the unchanged
  Product projection ceiling of 32 facts / 128 KiB.
- No production data migration exists because no Python Kinbase product or user
  corpus has been admitted. Migration tooling remains outside this amendment.
- The Rust binary still depends operationally on the separately installed, pinned
  Kindex `kin` CLI for Personal/legacy Codebase compatibility; it does not make the
  Python Kindex implementation part of Kinbase's production binary.
- The already completed model download, BF16 load, tool smoke, and tunnel-loss drill
  qualify infrastructure only. They neither pass a Product gate nor guarantee the
  expanded pre-dispatch controls.
- No duration, token count, green build, module count, or Coder declaration proves
  completion. The funded Coder window may end without an admissible commit.
- The named-human auxiliary-corpus rights grant and fresh Detector Review remain
  blockers; Rust/Vast does not waive them.

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
7. Build a smaller vertical slice inside the remaining budget: rejected because it
   would test code shape rather than the founder's complete P-1 through P-10 concept.
   Capacity failure is more honest than a mislabeled milestone. Coherent partial
   commits may be retained as unadmitted prior art so the bytes are not thrown away;
   retention is not a slice-level success criterion and cannot advance a Product gate.
8. Permit one first-party unsafe syscall crate immediately: rejected because audited
   safe wrappers may preserve the stricter boundary. If implementation proves that
   false, the question returns for explicit review rather than arriving as a hidden
   exception.
9. Put Factory launch/usage/destroy receipts into the Kinbase Company store:
   rejected as circular proof. The Validator ledger exists before the Product and
   cannot be made trustworthy by the component it is judging.
10. Reuse the old Tester and change only Python launch plumbing: rejected because the
    new functional, authority-only, egress, process, and tool-recovery obligations
    require a fresh independently authored instrument and new Detector Review.
11. Treat a scanner block as a zero even after it proves false: rejected because
    arm-dependent false positives can manufacture lift. A confirmed false positive
    invalidates the harness; a true protected recovery is the zero/Product failure.

## 8. Open questions and resolution gates

The dependency graph—not table order alone—is the only run-enabling interpretation:

```text
G-1 -> G-2 -> G-3 -> G-4 -> G-5 -> G-6 ----+
                              \------> G-7 -> G-8 -> G-9 -> G-10 -> G-11
```

G-7 may run concurrently with the G-5/G-6 branch after G-4. The human-rights part of
G-8 may resolve earlier, but Detector admission waits for G-7. G-9 requires G-6,
G-7, and G-8. A green infrastructure row never advances Product status, and a Coder
commit is a handoff rather than a gate verdict.

| Gate | Owner | Required evidence | Failure disposition |
|---|---|---|---|
| G-1 effective authority | founder + Validator | dry-run receipt for every overlay operation, section extent, boundary byte, and whole-effective-artifact pre/post occurrence count; two structurally separate equal plans/bundles; equal results on the frozen 32-case parser/splice/layout/seam/link corpus; semantic-delta, four-inline-term, load-bearing glossary-term, and complete supplement-consistency review; Agy `no-op` disposition bound to full rendered artifacts, diff, context/link census, semantic receipt, and a Validator/OS/provider-observed executable/model/provider/family/endpoint/configuration fingerprint whose unknowns conservatively overlap every possible family; founder and Validator exact amendment-digest + bundle-root receipts after receiving those rendered surfaces; new run binding contains base/amendment/effective digests and pre-outcome null census | no author dispatch |
| G-2 budget/custody | Validator + capability-separated local monitor | run-specific Rust 1.98.1 install/archive verification and online-then-offline edition-2024 hello-world before billable staging; live provider/invoice observations plus both Validator-owned spend derivations, dimensioned USD uncertainty band, and directional deltas; founder-ratified USD 400 route cap and uncalibrated-attempt acknowledgment; arithmetic cold/qualification/five-total-warm-hour/in-flight/charge/10%-operational/one-restart-load-and-qualification reserves with restart prefill consuming that same warm clock; separately witnessed boot-bound stopped-cache deadline; exact host/image/model/SSH binding; credit-only/no-autobill observation as defense in depth but not a provider-liability bound | `UNFUNDED` or destroy/rehost; no scope cut; unconfirmed destruction prevents terminal G-2/G-11 closure |
| G-3 pre-rat egress history | Validator | deterministic disposition that instance `50012413` lacks trusted local pre-send canonical wire capture, is permanently ineligible for repository traffic, and must be destroyed; replacement instance observed by Q-0 from its first request | unauthorized send permanently blocks the route; required rehost consumes the restart allowance |
| G-4 runtime controls | Validator + capability-separated observer/local sentinel | Q-0 retirement and non-adversarial rollback drill with shared-root limitation stated; literal OS sandbox, Linux Landlock-ABI filesystem hard requirement, unshared-network/seccomp denial matrix, and interval-union readable-subset/descriptor denial; complete remount reprobe; intermediate/final path-component race denial; qualification-marker destruction ordering; strict tool registry and reconciliation runbook; Q-1 accidental-inclusion controls; terminating HTTP/1.1 framing denials; body-bound one-use observer MAC plus durable pre-send wrapper spend, prepared/spent/forwarded ownership and crash/replay/substitution/duplicate/stall/full-volume reconciliation; rate-rise cancel drill; spend monitor/sentinel; full-bound cold-prefill measurement; exact 20,000-path/1-GiB source cap with build roots outside it; fixed 300/60/120/30/360-second single checkpoint-cycle deadlines and separate Validator object/ref-store survival under Coder `git gc`; expanded parser and mid-forwarding/mutating-tool recovery drills | no repository-bearing request |
| G-5 historical Python exclusion | Validator + sandbox launcher | initial-run mount/descriptor manifest omits the entire old Python lane and related Git/session/evidence paths; open/read denial positive control | no Coder dispatch; later inclusion requires a new exact amendment |
| G-6 Coder handoff | Validator, from GLM-5.3 Coder evidence | one clean final Rust HEAD whose reachable Coder-owned series covers every P-1 through P-10 implementation surface and full status/diff receipt; `FACTORY_STATUS: DONE <sha>` is a necessary model marker with no authority, while Validator ledger coverage admits the handoff | incomplete/blocked Coder result; preserve coherent work only as unadmitted prior art, never a milestone |
| G-7 Tester handoff | fresh Claude Tester | clean implementation-blind commit derived from effective authority, no Coder access, complete V-1 through V-10 obligation map | discard/re-dispatch under unchanged authority |
| G-8 Detector/rights | named human + fresh Detector Reviewer | explicit auxiliary-corpus rights grant including maximal-superset/overbroad-notice semantics and each rightsholder's 24-hour-default-or-seven-day-hold election; signed current roster snapshot plus standing post-run custodian; exact Tester artifact, attack catalog, canary metadata, auxiliary corpus, review/disposition digests | combination prohibited |
| G-9 Product gates | Validator | combine immutable Coder/Tester candidates and run V-1 through V-9, mutations, Rust nonfunctional gates, Linux hard-requirement external-classifier confinement, macOS artifact hash/symbol/string/schema proof that the external-classifier module/command/configuration/launcher is omitted plus hostile configuration/launch denial, and evidence-retention checks | `PRODUCT_FAILURE` or `INVALID_HARNESS` per Verification |
| G-10 pilots/power | independent roles + Validator | fresh excluded pilots including failure outcomes; competent authority-only control; functional endpoints; per-endpoint and per-stratum marginal-power/cell-count report naming the binding endpoint; fixed joint power N and prepaid aggregate measurement ceiling | `UNFUNDED_OR_UNDERPOWERED`/`INCONCLUSIVE_CEILING`; no partial proof |
| G-11 terminal measurement | Validator | frozen eleven-arm execution census, dual calibrated blind scoring, integrity audit, all co-primary confidence bounds, exact terminal claim | deterministic terminal verdict; only all gates may yield `PROVEN` |

The existing infrastructure receipt resolves only the observed model artifact load,
BF16 262K capacity, simple Responses/tool replay, prefix reuse, and one tunnel-loss
scenario for its recorded host/configuration. G-4 remains open because the final
egress gate, sandbox, watchdog, expanded parser matrix, and ambiguous-mutating-tool
drill did not exist. G-5 is resolved for the initial-run design only by proving the
entire Python prior absent; actual launcher evidence remains open. G-8 remains blocked
on the named-human corpus-rights grant. No code has yet satisfied
G-6, and no fresh Tester artifact has yet satisfied G-7.

Amendment-specific terminal/action codes are:

| Code | Meaning | Required next action |
|---|---|---|
| `AUTHORITY_MISMATCH:<O-id>` | overlay/bundle bytes cannot be derived exactly | no dispatch; repair as a new candidate and repeat review/ratification |
| `UNFUNDED` | arithmetic admission or continuation reserve fails | stop/destroy, retain honest partial lineage, ask founder for new authority/funds |
| `UNFUNDED_BY_OBSERVER_STALL` | observer cannot durably authorize a held body within 30 seconds | discard body, reconcile locally, destroy, append burned-cost apology |
| `UNRESOLVED_ACCOUNT_DELTA` | provider balance moved without a billing authority row inside the attribution window | retain full absolute uncertainty, close admission, escalate to founder |
| `UNCONFIRMED_DESTROY` / `UNRESOLVED_CUSTODY` | the provider did not confirm terminal destruction inside the accounting floor | presume the instance live, keep all traffic revoked, accrue open-ended charge uncertainty, block terminal G-2/G-11 closure, and escalate until trustworthy terminal plus billing reconciliation/account closure evidence |
| `INVALID_PLAN` | VOI plan reports zero work or fails complete obligation/slice mapping | no source exposure; destroy and obtain a new plan/authority |
| `CHECKPOINT_DEFERRED:<call-id>` | checkpoint interval elapsed during a mutating call | cancel at frozen timeout, reconcile, then checkpoint before any new operation |
| `CHECKPOINT_CAPACITY_EXCEEDED` | the live tree would exceed the exact 20,000-path/1-GiB cap or any fixed checkpoint phase/870-second total deadline is missed | reject the mutation before the cap is crossed, or terminate the route with the last admitted checkpoint; expansion requires a new ratified amendment |
| `UNSUPPORTED_UNPROVEN_PLATFORM` | the closed macOS schema received any unknown field/subcommand; the disposition is generic and carries no omitted-surface identifier | deny before process/network access; the macOS artifact must omit the external-classifier module/command/configuration/launcher/identifier and may use an admitted in-process/replay mode or Linux |
| `FACTORY_QUESTION` | authority forces a semantic choice the role cannot own | stop that role and ask the founder/owned authority exactly one question |
| `PRODUCT_FAILURE` | implementation violates a P-1 through P-9/finite-threat obligation | retain evidence; no proof or favorable rerun |
| `INVALID_HARNESS` / `INVALID_RUN` | judging instrument or bound execution is invalid | retain the census; repair only under the existing pre-unblinding/superseding-run rules |
| `NOT_PROVEN` | valid evidence misses a terminal causal/quality/privacy criterion | publish the miss; do not rename, tune, or filter it into success |

---

Per architecture-review protocol: if you identify a flaw, ground it in a cited
invariant, design principle, or worked example. Ungrounded assertions are not
adversarial review — they are disagreement. Enumerate distinct critiques as numbered
items so each can be resolved individually.
