# Amendment register

The Kinbase (Kinbase) specification is ratified by exact digest: the founder and a
distinct Validator approve the bytes of the authority files, and only ratified bytes
may be read by an isolated Coder lane. Changes arrive as candidate amendments in an
append-only overlay format: each names the exact base passages it replaces or
inserts after, and everything it does not name stays byte-for-byte binding. A
candidate is not authority. Ratifying one creates a new run generation; it never
rewrites the original manifest.

Status vocabulary: `candidate` (under review, no dispatch), `ratified` (approved by
exact digest for one run generation), `proven` (earned only by the independent
oracle and the terminal experiment, never a synonym for implemented).

| Amendment | Subject | Status | Digest |
|---|---|---|---|
| [001](../spec/amendment-001-rust-vast.md) | Rust implementation; self-hosted GLM-5.3 Coder against a pinned Vast/vLLM processor; custody, egress, recovery, checkpoint, and cost controls; tightened P-5/P-10 and V-5/V-10 falsifiers. | candidate | see the amendment header |
| [002](../spec/amendment-002-emission-ledger.md) | Emission ledger, leak stories, withhold, and redaction by reference, so that a shared-data leak is answered by a query rather than an investigation. | candidate, revision 3 | `81eb5b151c41541d230d582c1697399d7f9d99fde75a242683aea0d2306962a3` |

## Amendment 002 in brief

One invariant generates the design: a projection served but not recorded
under-approximates the served set and is the failure to close; a projection recorded
but not served over-approximates it and is a safe error. Every rule permits only the
second.

- Every projection leaves an acknowledged **emission record** before it is returned:
  references to the atoms served by identity and version, the cursors, the
  service-issued session and sequence, the authenticated principal and host, and the
  receipt time. Never bytes, never content digests. States: `intended`,
  `delivered` (an attributed adapter assertion), `withdrawn` (refused before any byte
  reached the transport).
- A **responder capability**, signed and scoped to one story, authorizes the lineage
  query after taint has made the ordinary read rule unsatisfiable. Every use is
  recorded. A sealed dual-control break-glass path covers the owner being unreachable
  or implicated.
- **Withhold** is immediate and reversible. **Redact** appends a tombstone version
  and happens only on an owner's confirmed disposition or a data subject's request.
  **Purge** is the owner-signed physical removal of earlier bytes, named as a scoped
  weakening of the rebuild gate. A scanner rule can withhold; only an owner or a data
  subject can destroy.
- A single-writer **story builder** assembles the atom's lineage, the served set,
  and the transitive **derived set**, enumerated completely in a deterministic
  order. Only the withhold action is bounded, by refusal and escalation rather than
  truncation; release is one owner-signed predicate.
- The runbook's manual enumeration and revocation steps become the ledger query, the
  withhold, and the redaction; the Git-clone caveat stands.

Proposed numbers for ratification: a sixty-second query bound, a one-hour
capability issuance bound, twenty-session and two-generation instruments, and a
512-atom automatic-withhold ceiling.

Review artifacts for revisions 1 and 2 (Simulacrum and Advocate) are in
[`evidence/reviews/`](../evidence/reviews/).

## Gates before a Coder lane may read a candidate

1. A Validator semantic-delta receipt for every operation.
2. An Advocate pass over the exact revision.
3. Founder ratification of the exact digest, recorded in the run ledger.
