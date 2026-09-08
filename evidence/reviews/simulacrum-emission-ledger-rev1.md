# Simulacrum review of amendment-002 revision 1 (2026-09-08)

## Direct answers first

**Is the emission record on the acknowledged path the right call?** Yes — but the justification you gave is not the one that holds, and the weak justification is why two of the defects below survived review.

You argue it as: "the emission record is the one thing on this path whose loss would cost a boundary, so it alone is acknowledged." That's not quite it. Losing an emission record doesn't cost a boundary; the boundary was crossed by the *projection*, recorded or not. What the loss costs is the ability to know it happened — and critically, the error is **one-directional**: recorded-but-not-served over-approximates the served set (safe, you notify someone who didn't need it), served-but-not-recorded under-approximates it (fatal, exactly the hole the amendment exists to close). That asymmetry is the whole argument, and it's a stronger one, because it *derives* the write-then-return ordering rather than asserting it, and it tells you the correct direction of every error in the design.

State it that way, because right now the spec asserts an ordering and a refusal without naming the invariant that makes them correct, and O-01's text is therefore unfalsifiable on the point that matters: a reader can't tell whether a future optimization (batching emissions, async ack) violates the design or merely tunes it. With the asymmetry stated, the test is mechanical — any change that permits served-not-recorded is out, any change that permits recorded-not-served is in.

**Is retraction by reference sound?** The shape is right. The specification is not. It conflates a reversible operation with an irreversible one, performs the irreversible one before the owner has adjudicated, and contradicts the clause it is being inserted immediately after.

**Where does it leave the responder without an answer?** Five places, listed below. The worst one is that the read rule provably refuses the query the amendment exists to enable.

---

## Defects, ranked

### 1. The read-scope rule locks the responder out of the ledger at exactly the moment the ledger matters

O-01: "Emission records are readable only under a facts token whose authority scopes could read every atom they reference."

Trigger 1 is *retroactive taint*. The taint event's purpose is to make the atom unreadable. So after the trigger, by construction, no live token has scope for the tainted atom, and therefore no token satisfies the read predicate for any emission referencing it. The responder's first query — "which sessions received atom X after it was tainted" — fails closed on the atom that caused the incident.

Additionally, a leak story spans `company` and multiple `codebase:<repo-id>` stores. The "every atom they reference" conjunction means the responder needs a token whose scopes union across stores that P-3 keeps separate. Either that token exists (in which case P-3 has a hole and you must say so and scan for it) or it doesn't (in which case cross-store stories are unassemblable).

V-3 tests only the refusal case ("read emission records with a facts token lacking one referenced atom's authority scope; the read must refuse"). It does not test the responder case, so the instrument passes while the mechanism is unusable.

Fix: name a break-glass responder capability, scoped to *references only* and never to bodies, whose every use writes its own record-path event with principal, story, and justification. Audit the auditor. Put it in O-01 and O-02 and add the positive case to V-3: after taint, the steward's query returns the served set.

### 2. Redaction is irreversible and happens before the owner adjudicates

Section 2.4 orders it: (1) bytes redacted and rehashed; (4) owner sets disposition to `confirmed` or `refuted`.

Section 3 concedes that rules get refuted, repeatedly, and that this is expected enough to warrant a defect-reporting path. So the specified sequence is: a scanner rule fires, the bytes are destroyed, and then the owner tells you the rule was wrong. There is no recovery path. "Nothing is deleted from the graph" is true and irrelevant — the fact is gone, and your own alternatives section explains why holes in a corpus agents reason over are wrong answers waiting.

You have two operations wearing one name:

- **Withhold** — reducer excludes the atom and derived set from trusted projection, reopens dependents as apology Unknowns, notifies the served set. Fully reversible; a release is a new event.
- **Redact** — bytes destroyed, rehashed, identity and digest history preserved. Irreversible.

Erasure requests (trigger 4) and confirmed secret exposure go straight to redact — the principal's request *is* the adjudication. Scanner/canary/recheck triggers (1, 2, 3) withhold on trigger and redact only on `disposition = confirmed` by the named owner. The containment property you actually need — nothing tainted reaches trusted projection — is delivered entirely by withhold. Redaction delivers erasure, which is a different obligation with a different trigger and a different authority.

As written, the amendment couples them, and a defective regex gets the same destructive authority as a data-subject request.

### 3. Redaction contradicts the anchor block it is inserted after

O-01's insertion point is directly beneath:

> stability metrics. Byte-identical rebuild applies only to reduction/current-view and selection over a frozen admitted event set.

And the new text says the atom's "bytes are redacted and rehashed while its identity and digest history are kept."

Those are two incompatible designs and the amendment contains both:

(a) **Mutate in place**, record a note that it changed. This breaks append-only, breaks byte-identical rebuild over the frozen admitted event set, and means "the fact that it changed and when is itself an event" is a log entry rather than the mechanism.

(b) **Append a redaction event**; the reducer resolves identity → current content; the original bytes are unreachable through the reducer but the event set is unchanged and rebuild still holds.

Only (b) is consistent with the paragraph you're inserting under and with section 4's "corrections are new events." But (b) does not actually destroy the bytes — it makes them unreachable *through the reducer*, which is not erasure, which means your erasure claim needs a separate physical-destruction step against the event store with its own proof gate. Pick one and write out what happens to byte-identical rebuild across a redaction boundary, because a Coder reading O-01 today can implement either and both pass the text.

### 4. The emission record retains a content verifier for the fact it is helping erase

`atom_refs` records "the fact's semantic digest at that moment." Emissions are never deleted; corrections are new events.

So after redaction, the emission table permanently holds a digest of the redacted content. If the digest is over fact content with a fixed algorithm and no secret, it is an oracle: guess the secret offline, compute, compare, confirm. For the class of facts this amendment exists to contain — API keys, forbidden identifiers, secret formats recognized on rescan — the guess space is often small enough that this is a practical attack, not a theoretical one. Section 3's "a record that leaked would reveal that a fact was served, not the fact" is therefore false for exactly the facts that matter most.

You also can't fix it by deleting the digests, because that violates section 4.

Fix: the digest in the emission record must be keyed per store with a secret the emission table's reader does not hold, or must be over the atom *identity and version* rather than content. If you need content-digest continuity for reference resolution, keep it in the atom's own digest history — which redaction governs — not replicated into an append-only table that redaction cannot touch.

### 5. Derived-set transitivity is unresolved, and both branches break something the amendment claims

O-01 defines the derived set as "every atom whose extraction provenance names a session that held the tainted atom in its projection at the time." One hop. Retraction withholds "the atom and its derived set."

If one hop: derived atom B is withheld, but B was served to session S2 before retraction, and atom C extracted from S2 is neither in A's derived set nor withheld. The taint escapes at hop two, and the emission ledger has every record needed to have caught it. That is the same class of failure as the original hand-enumerated runbook step — incomplete precisely where the system acted.

If transitive closure: in a long-lived corpus the closure grows toward the whole store; `impact` as counts becomes an unbounded number; the sixty-second bound is a guess about a graph whose size you haven't bounded; and section 3's remedy — "the owner releases clean atoms by setting the story to `tolerated` for each, which is a recorded act" — is a per-atom human decision over a closure of unknown size, inside an approval-fatigue budget. That remedy does not survive contact with a closure of four thousand atoms.

V-3 tests one hop with five derived atoms from twenty sessions. The instrument is sized to the easy case and cannot distinguish the two designs. Decide which it is; if transitive, add a depth or fanout bound with a stated cost model and an owner-facing release that operates on *sets* rather than per atom; and make V-3 extract derived atoms *from sessions that received derived atoms*, so the instrument can fail.

### 6. `missing[]` has no expectation source, so the V-3 "empty missing[]" gate can pass vacuously

"Anything that should exist and cannot be found is an explicit entry in `missing[]`."

For record-path items this is well-defined: the record path is append-only and sequenced, so absence is detectable. For observation notes it is not. You cannot record what you don't know was supposed to exist. If a scan pass was never written, or the buffer dropped it without a sequence gap, absence is indistinguishable from never-scheduled — and the story reports empty `missing[]` while under-reporting. That is the exact failure the amendment indicts in section 0: "an investigation with holes exactly where the system acted."

Fix: `missing[]` is only sound where there is a declared expectation. Give observation notes a scheduled cadence and a sequence number, so the builder can detect a gap; then `missing[]` means something. Where no expectation exists, the story must carry a third state — `unattested`, not empty — naming the observation classes for which no expectation was declared. Otherwise the V-3 gate is checking a field, not a property.

Related text defect: the O-05 instrument requires the enumeration to complete "with an empty `missing[]`" and then, in the same chained sequence, requires "Deliberately evict one observation note before assembly; the story must list it in `missing[]` with `evicted`
