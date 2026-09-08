# Simulacrum review of amendment-002 revision 2 (2026-09-08)

## The six

Five closed. One closed as stated and reopened by a detail. Ranked verdicts first, then the objection that matters.

**Responder lockout — closed.** The two-operation read model is the right shape, and "the responder is audited by the same ledger they are reading" is the correct resolution rather than an exception carve-out. One residual: the capability is issued by the Company owner, synchronously, on the critical path of runbook step 3. You replaced "look in these places" (slow, always available) with "obtain a human signature" (fast, sometimes available). Name the issuance SLA and the self-issuance case — when the trigger's store is `company` and the Company owner is the principal named in the story, who signs?

**Redaction before adjudication — closed.** Reversibility-and-authority as the axis of separation is correct, and "a scanner rule can withhold; only an owner or a data subject can destroy" is the sentence that closes it.

**In-place rehash — closed.** The tombstone version preserves identity, the digest chain, and rebuild. One overclaim: "the digest chain stays verifiable per version" is false for a purged version. You can verify the marker's *claim* about a digest; you cannot verify a chain over bytes you destroyed. Say that, or purge becomes the hole in the proof that the proof says doesn't exist.

**Content digest as oracle — closed in the record, contradicted in §4.** The `atom_refs` are `(atom_id, version)`; good. But idempotency requires the service to persist a **payload digest** keyed on `(session_id, projection_seq)` — that's the only way "identical payload digest returns the original receipt" survives a restart. Section 4 says: "No bytes and no content digests on the record path." The mechanism in 2.2 stores one. The oracle value is low (same-principal, same-session, confirms bytes the caller already holds), so this isn't a security defect — it's a spec that contradicts its own constraints section, and a Validator running the semantic delta will trip on it.

**`missing[]` vacuity — closed, but `unattested[]` is now overloaded.** It carries two disjoint types: observation classes with no declared expectation, and closure truncation. Truncation is not an observation class. Worse, the V-3 instrument asserts `unattested[]` names "only classes with no declared expectation" — which means the instrument *fails* on any run that truncates. It passes today only because the instrument is sized under the bound. Split the field: `unattested[]` for undeclared classes, `truncated[]` for the frontier.

**Derived-set transitivity — this is the one.**

## The strongest remaining objection

The bound reintroduces under-approximation, and it does so in exactly the fan-out regime the amendment exists to serve.

Your governing invariant: served-but-not-recorded under-approximates, and that hole *is the failure this candidate exists to close*. Every rule is chosen so errors fall in the safe direction. Good. Now run the closure arithmetic on your own predicate.

B is derived from A if B was extracted from a session that received A. Take a modestly-served atom: 20 sessions (your own instrument's number). A working session extracts, conservatively, ten atoms over its life. Generation 1 = 200. Each of those 200 is served into some sessions — say two — each extracting ten. Generation 2 = 4,000.

Bound is 512. **You truncate inside generation 2.** The three-generation depth bound is decorative; it is never reached, because the size bound binds first in every realistic corpus. The only bound that operates is 512, and it operates one hop past the toy.

At truncation, the runbook says: treat the truncated frontier as retained copies. Which is the manual investigation this amendment deleted, returned, in the high-fan-out case — the case where manual investigation is least tractable and the taint has spread furthest. The system *knows* those 4,000 references exist. It declines to enumerate them and hands the responder a bag.

That is under-approximation of the served-and-derived set. Not by an unrecorded projection — by design. The invariant is stated in the reader summary and in O-01, and the closure bound violates it.

**Second-order:** the truncated set has no specified total order. "Bounded by 512 atoms" doesn't say *which* 512. Traversal order over the frontier is unspecified, which means it falls out of query plan and insertion order. Stories are record-path facts subject to byte-identical rebuild. Two rebuilds of the same story over the same event set can produce two different 512-atom sets and two different truncation records. And V-3 never exercises a truncation — your instrument is sized at 20 sessions and 7 derived atoms, well under the bound — so the nondeterminism is invisible to the gate that's supposed to catch it.

**The actual defect is that one bound is doing two jobs with opposite cost profiles.**

Enumeration is cheap. It's references — 4,000 rows out of an indexed table, well inside sixty seconds. Withholding is expensive: 4,000 atoms removed from trusted projection, dependents reopened as apology Unknowns against the fatigue budget, and release capped at 64 atoms per signed event — 63 owner signatures to undo a false positive, each requiring explicit truncation acknowledgment. The withhold is reversible in principle and prohibitively expensive in practice, which trains owners to set `tolerated` rather than pay the release cost. You've modeled "defective rule with destructive authority" and missed "defective rule with unaffordably-reversible authority."

So bound the *action*, not the closure:

- **Enumeration: unbounded, to fixed point, deterministically ordered.** Total order by `(generation, extraction_time, atom_id)` so the traversal is reproducible and the story rebuilds byte-identically. The responder always gets the complete answer, because the complete answer is the product.
- **Withhold: bounded, with the bound as a refusal rather than a silent degradation.** When the withhold set exceeds the ceiling, the story does not truncate — it refuses to auto-withhold and escalates to the owner with the full enumeration and a count. Explicit choice, recorded, on complete information.
- **Release: by predicate over the enumerated set, not by listed 64.** Owner-signed, over "generation ≥ 2 excluding {…}", so recovery cost is one signature, not sixty-three.

Then truncation stops being a correctness boundary and goes back to being a tractability limit, which is the only thing it should have been.

## The one to check next

Your state machine gained a third state and the two definitions that quantify over states did not follow it. The served set is "every emission referencing it **in either state**"; the derived-set predicate says "**in either state**." The glossary says states are `intended`, `delivered`, `withdrawn`. Does a `withdrawn` emission — a projection that was refused and never returned — contribute to the served set and seed the derived closure? Safe-direction reasoning says yes. The race semantics say no, the session never received it. Unresolved, and it's the difference between a false-positive class and a hole.

Related, and worth naming in §3: a sustained `EMISSION_UNRECORDED` rate is a leak-story trigger, and every responder-capability use is a record-path event. So the condition that raises the story is the condition that prevents its investigation. Record path under write pressure → stories open → responder cannot query, because recording the query is a precondition of the query. Give the capability-use event a separate durability path or a bounded-deferral write, or the containment mechanism deadlocks under the load that triggered it.
