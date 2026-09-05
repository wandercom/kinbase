# Governing source request

The Validator preserves these founder statements as the source authority. Derived
specification language may clarify them but may not narrow away their functionality.

## SRC-1 — repository knowledge must travel with the repository

> The goal is for users of kindex working in a codebase to pool knowledge via the
> .kin/ files about that codebase. IF folks (or agents) are doing conversational
> things, capture it in the SQLite graph by all means. If they're working on code in
> a repository, the style and conceptualization and ideas can go to SQLite; but
> there should _also_ be any notes germane to the codebase captured in .kin/.

## SRC-2 — three products and their reach

> The codebase informs the codebase. The company kindex informs all coding work.
> The personal kindex is for personal conversations and whatnot. So, really, three
> products, yeah?

## SRC-3 — classification, safe fan-out, and global references

> We need the system to correctly identify and classify messages. De-identified
> could be used in shared repos. Writes can go to multiple destinations. The
> structure needs to be what's optimal for improving brownfield performance. We
> need specific notes on the architectural aspects identified. Even the repo's
> .kin/ needs to reference global architectural ideas.

## SRC-4 — irreversible disclosure boundary

> The classification is absolutely correct. This is a classic Type 1,
> expensive-to-revert architectural decision. The physical distribution of Git
> clones means that any cryptographic or programmatic boundary failure resulting in
> Personal data leaking into the Codebase or Company store is functionally
> impossible to erase.

## SRC-5 — accepted architectural corrections

> Use ../factory methods to implement this proof of concept in a fresh directory.
> I approve and accept 1-7.

The seven accepted corrections are: a falsifiable approval-fatigue bound; an
explicit private-lineage threat model; acknowledgement and measurement of off-policy
VOI error; stable signed repository identity and fork semantics; Core-enforced
absence of accept-all; research-only labeling for known-eligible artifact/bit
experiments; and Company-steward authority for exceptions rather than Factory
authority.

## SRC-6 — independent Factory roles

> Use tmux to fire up agy as orchestrator, glm-5.3 as coder, and claude as tester?

The requested role assignment is retained: Agy is the resident, non-authoring
strategic Orchestrator; GLM-5.3 is the Coder; Claude is the implementation-blind
Tester; the current Codex instance is Validator. The Orchestrator must receive the
ultimate goal and every material activity delta, assess whether work advances that
goal, and may block but cannot redefine intent, implement, test, or issue a verdict.

## SRC-7 — sine qua non proof definition

> A proof of concept is like the factory project. It DOES THE FUCKING THING. What's
> missing are the nice-to-haves. Not the actual fucking functionality.

> A proof must ingest data from a multitude of sources, sift through it, build a
> corpus, maintain that corpus, be tested for appropriate recency bias, discernment
> and discrimination between temporary or ill-conceived shifts, propensity to seek
> real guidance from the authority (ask the chief architect about the direction of
> the architecture, for instance)... it should be able to materially shift the
> brownfield factory from a shitty implementation to something that's nearly ideal
> and on par with greenfield outputs. It needs to test to ensure data lands in the
> right buckets in the right ways and doesn't leak sensitive information places
> where it shouldn't go. That's all sine qua non for the PROOF of concept.

## Interpretation rule

Anything described in SRC-7 is acceptance-critical. A reviewer may harden its
implementation or replace it with an observably equivalent mechanism; a reviewer
may not make the plan easier by relabeling it future work. Deferred work is limited
to scale, polish, deployment, and breadth beyond what the proof contract explicitly
requires.

