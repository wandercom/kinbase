# Kinbase overview

Status: specification ratified; proof of concept not yet run. Public name Kinbase;
developed in this repository as Guildhall. A Wander project. The pitch and the
proof condition live at [kinbase.tools](https://kinbase.tools); this document is the
technical summary, and the [specification](../spec/README.md) is the authority for
every claim in it.

## What it is

Kinbase is the Company product of a three-store Kindex system:

| Store | Product | Holds | Authority |
|---|---|---|---|
| personal | Kindex | your conversations, decisions, and context, in SQLite on your machine | you, the principal |
| codebase | Kindex | the repository's git-tracked `.kin/`: decisions, constraints, code maps | the codebase maintainer, for one stable repository identity |
| company | Kinbase | engineering direction, architecture, standards, ownership, history | the Company steward; scoped authorities such as the chief architect |

A coding session composes company and codebase. It never mounts personal. The three
stores have separate roots; the shared writer process is denied the personal root by
OS policy before it starts, and the projection layer checks again. Same engine, same
protocol, physically separate stores.

## What it is specified to do

- **Ingest heterogeneous evidence** with provenance: Codex and Claude Code
  transcripts, code and interface declarations, tests and results, git history,
  documentation and ADRs, issues and pull requests, runtime and configuration
  evidence, existing Kindex and `.kin/` facts, and signed human answers. Re-ingest is
  idempotent; a changed source produces a new observation, never a silent mutation.
- **Atomize and classify.** One source item may yield zero or more minimal atoms
  (decision, constraint, observation, question, rationale), each with scope,
  confidence, provenance, taint, and proposed destinations. The classifier has no
  write authority. Only exact-byte human approval publishes, one destination at a
  time, with per-destination receipts and no cross-store transaction.
- **Keep taint non-clearable.** Secrets, credentials, configured canaries, and
  forbidden identifiers are hard-blocked from every shared candidate, even when a
  model paraphrases them. Ordinary private provenance is approval-gated. Detection
  is deterministic for registered classes and measured, not promised, beyond them.
- **Ask the named authority.** When the evidence cannot settle a load-bearing fact,
  the question is shown as an open unknown and routed to the authority registered
  for that scope. Signed answers carry scope, date, and validity, and can be
  superseded; a later revocation reopens dependent facts as apology Unknowns.
- **Project only what the task needs.** A decision-conditional selector supplies a
  bounded working set of admitted facts, re-checking revocation and validity at
  every projection, not only at session start.
- **Bound approval fatigue.** At most four shared-destination approval prompts per
  person and host in any sliding hour, never three in a row without returning the
  person to their task, and never an accept-all.
- **Run on the ordinary Codex and Claude lifecycle.** Host adapters present the
  same protocol and hold no publication authority.

## What it does not claim

- General detection of private meaning. Hard blocks are deterministic only for
  registered canaries and identifiers, credential formats, explicit secret fields,
  and configured source classes.
- That a human authority's answer is correct. It claims the answer is signed,
  scoped, dated, and supersedable.
- That the protocol will not change before Kinbase ships. Kindex ships today under
  its own versioning.
- Production hosting, multi-region replication, enterprise identity, a web UI, or
  billing. Those are deliberate omissions of the proof of concept.

## Where the proof stands

The proof is a blinded brownfield experiment with eleven arms on the same commits,
scored against a fully informed spec-fed arm. The conditions are listed in plain
words in [proof.md](proof.md). Until it passes, everything above describes intent.

## Names

Guildhall is the development name and appears throughout the specification, the
CLI contract, and every ratified artifact; renaming ratified bytes would change
their digests. Kinbase is the public name. They are one thing.
