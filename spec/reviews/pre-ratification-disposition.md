# Pre-ratification review disposition

Status: evidence summary, not a proof verdict. Authority remains
`source-request > Product > Architecture > Threat Model > Verification`.

No reviewer was authorized to reduce SRC-7, redefine the product, write code, write
acceptance tests, or declare success. A finding was incorporated when it closed a
route by which an implementation-shaped artifact could pass without the required
behavior, or when it repaired an ownership/security contradiction. Advice that merely
made the run smaller, cheaper, or easier by dropping a required behavior was rejected.

## Constrain

Session `b9919684-4ca9-40cc-885f-6a729e0cd00d` completed the challenge phase. Its
useful findings—distinct threat-model ratification, a frozen auxiliary corpus,
mechanical reconstruction adjudication, and private canary-registry custody/retention—
were incorporated into `threat-model.md` and `verification.md`.

Two default-provider synthesis attempts returned no text. A later Claude synthesis
was not adopted because it contradicted source authority by treating ratification as
the finish line, weakening the Codebase boundary, and omitting required edges. The
generated artifacts are advisory session residue, not an authority artifact. The
current specifications were written from the accepted challenge findings and checked
against the governing source request.

## Simulacrum

Successive framing passes rejected: hand-selected tasks, an oracle authored with
implementation knowledge, marginal rather than joint power, effect-selected N,
unbounded/unfingerprinted model drift, hidden human answer channels, and favorable
result dropping. The final pass additionally found task-conditioned corpus curation,
the absence of null/static-prior controls, missing Company/Codebase contribution
ablations, outcome-visible invalidation, and an unbound grader.

The resulting contract now requires a full history census and public draw; a
post-V-9 but pre-task schema-blind Corpus Builder; null-system, static-prior, and
single-store controls; intention-to-treat accounting; outcome-blind integrity review;
grader model/prompt/parser bindings and human-gold calibration; explicit TOST
equivalence; and a pre-outcome joint power/cost decision. The arithmetically redundant
70% gap-closure value remains visible but is not represented as independent evidence.

The final NO-GO-only pass raised two proxy risks. The semantic-precursor finding was
incorporated as a stricter multi-source predicate: two independently owned,
nonredundant sources must each be load-bearing and no single artifact may contain the
complete oracle. Its premise that brownfield work means rationale was never written
was rejected; retrieving dispersed pre-change rationale is an intended product
behavior. The access-density finding was incorporated: every task now binds a least-
privilege principal, broad service identities are forbidden, and a jointly powered
authorization-restricted stratum proves quality under measured denial plus the scoped
authority path rather than against an unrestricted corpus.

## Advocate

Four immutable review outputs were considered:

| Review | Personas | Findings | Cost | SHA-256 |
|---|---|---:|---:|---|
| `20260905T033638-6465ba6e` | Helland, red-team, adversarial, sage, user, SME, good-friend | 87 | $1.979650 | `d72f19c5425eea062033c3d8fc62a521ab0dc917ad1ceff5b455040f767788f7` |
| `20260905T042515-e4a9ea99` | Helland, red-team, adversarial, SME, user | 69 | $2.174860 | `db563a7bfc9206232c6aface96de072b32a577b5e7a94cd3ff5e245bd4d28c25` |
| `20260905T044030-0a4a9050` | Helland, red-team, adversarial | 38 | $1.457255 | `4bd4e4373bc4d8de0cce65ffb1db5dba642c359ae3121111eeb85fdeb19672db` |
| `20260905T050912-2cd7da1d` | Helland, adversarial, red-team | 36 | $1.595505 | `6566039055caae27e7c742ec1dfb0aa389ae66727fac86005c4034e7dd08c254` |

The first raw report is retained as `evidence/advocate-pre-ratification.json`; the
final raw report is retained byte-exact as base64 at
`evidence/advocate-final-pre-ratification.json.b64` and is bound below by review ID,
encoding, and decoded digest. The two intervening reports are identified here by
review ID and digest. Findings were rerun after each material repair rather than
counted as votes.

Incorporated ownership and security corrections include:

- separate Company criticality from maintainer-owned local dependence, with a
  steward-only repository-scoped relaxation path;
- treat Company's Git-manifest knowledge as expiring maintainer testimony and require
  a Company-owned expiry/apology event;
- model revocation as current support withdrawal plus bounded local cascade and an
  explicit steward-owned unreachable-clone residual;
- make fan-out a destination saga with named responsibility, a closing authority,
  local quarantine, and a terminal orphan-abandoned event;
- split approver-owned extraction-error testimony from steward-owned truth withdrawal;
- bind exact scope, time, cursor, parser, signature domain, nonce, client key, and
  retry visibility at every admission boundary;
- enforce a closed exact authority-scope ACL; missing/empty scopes grant nothing;
- execute the verified classifier descriptor rather than re-resolving its pathname,
  and detect inherited Personal descriptors independently of pathname denial;
- share one atomic four-slot prompt budget across destinations on a host instance,
  identify the host-owned shard, transact reissue/reservation together, and prove that
  fatigue limits still permit useful corpus growth;
- neutralize control/bidi/ANSI terminal deception, saturate signed prompt-injection
  tests, serialize linked worktrees in Git's common directory, and test a populated
  pinned-Kindex `.kin/` for collision-free preservation;
- bind every benchmark and grader degree of freedom, prevent post-freeze human bytes,
  preserve every admitted outcome, and expose the full eleven-arm cost envelope.

Rejected recommendations include a fixed underpowered small-N demo, weakening the
equivalence/causal gates to fit an assumed budget, querying Personal in a coding arm,
claiming global prompt enforcement while offline, universal privacy claims, and
distributed push invalidation across unknown clones. These either erase founder-
required functionality, violate the Personal boundary, or assert authority the system
does not possess.

## Remaining authority action

The reviewed files remain candidates until the founder and Validator ratify their
exact bytes. The later experiment manifest must name an immutable coding model and two
independent grader families, then bind a founder-approved aggregate call/token/dollar/
time ceiling before pilot outcomes. The specification publishes the minimum call
envelope so an unaffordable run cannot be misrepresented as proof.
