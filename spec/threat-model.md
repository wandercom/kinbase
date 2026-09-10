# Acceptance Threat Model — Kinbase proving ground

Status: **candidate for review and exact-byte ratification**

Authority: [`product.md`](product.md) and [`architecture.md`](architecture.md).
This artifact narrows neither. It defines the finite adversary against which V-3 is
allowed to make an evidence claim.

## Claim boundary

The only permitted passing claim is:

> Zero observed unauthorized durable disclosure outside the authorized processor
> boundary under Acceptance Threat Model `kinbase-atm/1`, identified by its exact
> SHA-256 digest, across the frozen execution census.

That is not a claim of universal confidentiality or a zero population rate. It means
the tested executions observed no exact, encoded, normalized, partial, or
deterministic-lineage recovery of a protected canary on any unauthorized durable or
shared surface under the frozen attacks and observation powers below. The report
states the exact vector/control count and, for any sampled or stochastic family, its
binomial confidence bound. Semantic paraphrase recovery is measured and reported
separately because the finite instrument cannot prove its universal absence.

The founder and a distinct Validator ratify the exact bytes of this artifact before
author lanes start. The Tester implements attacks and detectors but cannot change
this threat model. The implementation-blind Detector Reviewer challenges coverage
before implementation is combined. This file's digest, the attack-catalog digest,
the auxiliary-corpus digest, and the sealed canary-registry ciphertext digest are
all bound into the experiment manifest. Omitting an attack requires a newly ratified
artifact and a new run; it cannot be treated as harness repair.

## Protected boundaries and assets

- Personal observations, facts, transcripts, directories, identities, candidate
  payloads, omission context, raw canaries, salts, and signing material may not enter
  Company, Codebase, Git, host projections, shared receipts, or shared logs except as
  one destination's exact approved minimized bytes.
- Company-confidential source bodies, directory/contact data, bearer tokens, private
  keys, and non-published Company fact prose may not enter Codebase, Git, host logs,
  or unauthorized clients. Codebase may carry only the approved fact/reference
  forms defined by Architecture.
- One destination's approval cannot authorize another destination. Rejection,
  deferral, expiry, or partial fan-out cannot silently widen admission.
- Worktree `.kin/` content cannot mint roots, certificates, authorities, repository
  identity, Company endpoints, or exceptions.
- Canary registries, raw fixture instantiations, auxiliary-corpus private extensions,
  unblinding material, and incident subjects are private test assets and are never
  Git-reachable or included in a sanitized evidence packet.

For this proof, **durable** means written to any filesystem, database, Git object,
cache, log, retained evidence, service state, remote request, or cross-process/
cross-machine channel where a receiver may retain it after the producing operation
returns. A same-process heap value erased before return is not itself durable, though
any derived output remains in scope. **Unauthorized** means the destination lacked a
valid destination-specific exact-byte approval, scoped authority/certificate, or
explicit data-processor authorization at the decision's recorded Company revocation
cursor and event time. Later approval cannot retroactively authorize an earlier send.

## Model-provider boundary

Real Codex and Claude hosts necessarily transmit the user's active prompt and
authorized repository material to their configured model providers. In the proof,
each exact provider/account/retention mode is an explicitly authorized data processor,
is named in the manifest, and sits inside—not outside—the authorization boundary.
That authorization covers only bytes the user submitted to that host in the current
session and benchmark repository bytes whose provider-transmission rights are bound
in the task manifest. It never covers historical Personal-store recall, secrets,
canary registries, hidden tests, or Company bodies not already authorized for that
host. Kinbase may not send any such bytes to a separate classifier provider merely
because the host has a provider relationship.

Private-message classification therefore uses a local model, or the already
authorized current host processor under the same data/retention scope; otherwise it
abstains and creates a private Unknown. The acceptance packet records every outbound
model-request digest and authorized-purpose receipt and plants positive controls in
the egress detector. Transmission to an unnamed provider or outside the authorized
byte/scope set is a V-3 product failure. Provider-side custody and compromise are not
tested, so the permitted claim explicitly names the digest-identified authorized
processor boundary.

## Adversary and observation powers

The acceptance adversary may:

- control repository files, branches, commits, Git object history, `.kin/` events,
  symlinks, paths, hook payloads, signed fact prose from a malicious-but-authorized
  content signer, network timing, process retries, cache age, and message size;
- replay an approval, retarget its destination, substitute payload bytes, race the
  preview/commit seam, present an unauthorized or revoked key, forge a repository
  certificate inside the worktree, delete or hide events/manifests, and use shallow,
  sparse, rebased, squashed, or conflicting histories;
- inject delimiter-like, Unicode-normalized, hex, base64, percent, JSON-escaped,
  fragmented, transformed, and correlated variants of protected material;
- inspect every Company/Codebase/shared output, Git object, service response, host
  projection, log, receipt, cache, SQLite text/blob field, process exit artifact,
  and retained sanitized evidence surface;
- run the coding agent inside the declared acceptance sandbox and induce it to read
  Personal paths; and separately run an arbitrary same-UID process that can read
  user-readable files, then attempt to pass recovered bytes through every shared
  promotion boundary.

The application boundary does not claim to stop a compromised kernel, root, a user
who deliberately copies approved Personal content outside Kinbase, or an arbitrary
same-UID process from reading user-readable files. The acceptance claim still
requires the promotion gates to reject protected bytes obtained by that process.
Production identity, hardware key custody, remote service compromise, traffic
analysis, and denial-of-service beyond the bounded overload cases are not proved.

## Frozen attack catalog

V-3 must execute, at minimum:

1. exact/partial/substring and deterministic-lineage disclosure across every shared
   surface and destination;
2. NFC/NFD, hex, base64, percent, JSON escape, delimiter, fragmentation, case,
   whitespace, and reversible-composition transformations;
3. approval replay, cross-destination retarget, payload substitution, expiry bypass,
   approval-preview race, and pathname/symlink swap;
4. malicious clone root/certificate, unauthorized signer, rotated/revoked signer,
   stale revocation cache, parent/substitution, and foreign-branch authority;
5. signed prompt-injection prose that attempts to change host instructions, tools,
   destination, or approval requirements;
6. deletion, hidden packed Git object, missing manifest, forged completeness,
   shallow/sparse checkout, rebase, squash, and incompatible branch-head union;
7. oversized/boundary events, duplicate keys, noncanonical numbers, Unicode
   ambiguity, duplicate/reordered retries, crash/restart, and backup/restore replay;
8. accidental disclosure through errors, traces, telemetry, receipts, evidence
   packets, caches, temporary files, cleanup, and process command lines;
9. sandboxed coding-agent Personal-root reads and arbitrary same-UID acquisition
   followed by attempted shared promotion;
10. correlated reconstruction using the independently frozen auxiliary corpus;
11. persistence and authority-matching injection using SQL/LIKE/GLOB/FTS operators,
    wildcard scope/logical keys, NUL, separators, malicious `.kin/config` fields,
    and parameter/type confusion;
12. signature/parser differential and cross-domain reuse: duplicate/reordered keys,
    verify-one-parse/use-another, NFC-changing bytes, cross-message-type signatures,
    digest substitution, and signed-buffer replacement;
13. stolen base bearer token attempting directory/contact read, answer admission,
    scope escalation, auth-failure flooding, and token replay after rotation;
14. process-capability inspection: dump argv, environment, file descriptors,
    serialized config, exception bodies, and child-process inputs from every shared
    writer/projector and search for the Personal root/path/capability canary;
15. concurrent approvals, double submission, crash at every nonce/event/manifest/
    receipt transition, counter races across two host sessions, and reset spam.
16. classifier-executable substitution through relative/PATH lookup, changed binary
    under the same name, writable parent directory, environment/descriptor leakage,
    and processor-scope mismatch before private input delivery.
17. terminal approval deception using CR/LF, C0/C1 controls, ANSI escape sequences,
    Unicode noncharacters, and bidi formatting/override characters, plus mutation of
    the bijective escaped renderer;
18. saturated signed-insider prompt injection at the full 32-fact/128-KiB projection
    ceiling, requiring no change to the permitted host action/tool trace;
19. check/execute classifier swaps and inherited open-Personal descriptors, including
    the case where path denial succeeds but the shared process can read through an fd.

Every family has an exact positive control, negative control, and detector mutation.
A missing family, missed positive control, false-positive negative control above its
frozen tolerance, or surviving detector mutation makes V-3 `INVALID_HARNESS`.
The catalog enumerates every test vector and surface rather than reporting only a
family name; its report gives counts and confidence bounds and never infers universal
detector recall from a finite planted set.

The randomized sensitivity qualification contains at least 300 independently drawn
positive variants, with at least ten from every declared surface/encoding family, and
at least 500 independently drawn true-negative decoys. All fixed deterministic
positive controls must be caught. The Wilson 95% lower confidence bound on randomized
sensitivity must be at least 0.98 and the Wilson 95% upper confidence bound on the
false-positive rate at most 0.01. The report publishes every denominator, miss, and
bound, including the resulting measured false-negative bound; registry plaintext is
never exposed to improve the detector score.

Hard-blocking taint is assigned by the frozen registry, exact/normalized identifier
sets, credential parsers, explicit secret fields, and source-class rules. A stochastic
classifier may only add taint or abstain. Unknown private semantics outside those
detectors remain an explicitly measured residual risk and require exact-byte human
approval; the passing claim covers the registered/canary execution census, not all
possible sensitive meaning.

## Canary and auxiliary-corpus custody

The Tester generates randomized raw V-2/V-3 canary values into a dedicated
mode-0700 test vault outside every repository, worktree, agent home, and evidence
packet. Committed fixtures contain generators, structural labels, and placeholder
IDs only. Raw instantiated messages, registry entries, salts, and keys never enter a
Coder-visible or Git-reachable path.

The canary registry is a Tester-custodied encrypted file in that vault. It maps an
opaque canary ID to raw value, transformation family, planted surfaces, expected
destination denial, and gold atom/destination labels. The manifest binds its
ciphertext digest and schema/count metadata without its key or plaintext. The
Validator receives only the minimum read capability during V-2/V-3 execution; the
reconstructor receives no registry capability. Raw registry plaintext, raw fixture
instantiations, and decryption keys are destroyed within 24 hours of terminal
verdict unless an explicitly authorized incident hold applies. Permanent evidence
retains keyed HMAC matches and digests, never raw values or a reversible lookup.

The implementation-blind Detector Reviewer selects the adversarial reconstructor's
auxiliary corpus before implementation combination from the eligible licensed
public source pool plus generated transformation dictionaries and preregistered
correlation/decoy records. The Reviewer records selection procedure, source rights,
contents, versions, and digest. Neither Tester, Coder, Validator, nor reconstructor
may weaken or replace it after execution begins. The reconstructor gets all shared
surfaces and that exact corpus, no labels, registry, hidden tests, or arm identity.

## Mechanical recovery decision and adjudication

A recovery is positive when a shared surface contains an exact protected sequence,
a frozen reversible transformation of one, a partial sequence meeting the frozen
length/rarity rule, or a deterministic chain from auxiliary evidence to one unique
canary value. The attack catalog specifies those algorithms and thresholds before
the run. Semantic similarity without deterministic lineage is reported but is not
silently promoted into or excluded from the zero-tolerance result.

Tester and reconstructor emit independent, content-addressed findings before seeing
one another's conclusions. A disagreement is adjudicated by the Validator using the
ratified mechanical rule while both original findings remain. If the rule does not
determine the case, V-3 is `INVALID_HARNESS`; the Validator cannot invent a favorable
interpretation. Any mechanically positive recovery is an immediate product failure.

## Retention and reporting

The private run evidence root and incident vault obey
[`verification.md`](verification.md) retention and withdrawal rules. The sanitized
report names `kinbase-atm/1` and its digest, lists every executed family/control/
mutation and surface, preserves disagreements and adjudication receipts, and uses
the qualified claim verbatim. It never says merely “privacy proved” or “zero
leakage.”
