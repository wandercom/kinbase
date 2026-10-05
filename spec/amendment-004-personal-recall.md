# Amendment 004 — Personal recall through Kindex

Status: **proposed**. It is not authority. It becomes authority only when the founder
ratifies it, a named human privacy reviewer signs it off, and the ratification
manifest binds its bytes. Until then, what it describes exists only on a branch, and
it stays off unless a principal configures it.

## Why

The specification makes the Personal store Kindex, but no command reads it back.
A principal's own conversations are the memory a host most needs. "What did I decide
about the scheduler?" is answered from them, and answering means a model reads
historical Personal text.

The threat model's model-provider boundary allows this to no one today:

- a host's provider authorization covers only the current session and never covers
  historical Personal-store recall;
- every authorized processor is an exact provider, account and retention mode.

This amendment adds a separate authorization for recall, and says what Kinbase
enforces around it.

## What this amendment changes

- `threat-model.md`, "Model-provider boundary": it adds a **recall processor**, a
  processor the principal authorizes for historical Personal-store text. This is a
  separate authorization. The host-provider rule and the classifier rule stand
  unchanged, and a host's provider relationship never stands in for a recall
  processor.
- `cli.md`: it adds `kinbase recall --question TEXT [--as-of DATE] [--json]` and the
  `[personal] kindex_*` keys (`kindex_executable`, `kindex_executable_sha256`,
  `kindex_config`, `kindex_timeout_seconds`, `kindex_digest`,
  `kindex_retention_seconds`, `kindex_team_knowledge` and `[[personal.kindex_processors]]`).

On every other point the earlier artifacts govern.

## Requirements

1. **Local unless authorized** (`recall-local`). Without a recall processor, Kindex
   runs on the machine: no LLM, and local embeddings. No Personal byte leaves it.
2. **Exact authorization** (`recall-processor`). A recall processor is authorized only
   by a `[[personal.kindex_processors]]` entry, and every field is required:
   - `provider` and `model`;
   - `key_env`, the variable holding the account's key;
   - `key_sha256`, the SHA-256 of that key, which identifies the account;
   - `retention`, the retention mode the account is under.

   Every processor a Kindex run could send Personal text to, its LLM and its
   embedding provider alike, must match an entry exactly, including the account. A
   run that does not match is refused with `PROCESSOR_UNAUTHORIZED` before anything is
   sent.
3. **One checked configuration** (`recall-config`). Kinbase resolves the Kindex
   configuration itself and refuses anything it cannot check. It passes that exact
   configuration to every Kindex run, so no global, project or profile configuration
   is read. Kindex receives the authorized processors' keys and no other environment.
   A run that only stores text receives no key.
4. **An exclusive graph** (`recall-graph`). Kindex keeps the Personal graph in a
   directory that Kinbase creates and marks, and refuses any existing directory it
   did not create. No other Kindex process, with another configuration, works on the
   graph or drains its queues. What an interrupted run leaves behind is removed by the
   next run.
5. **Retention and deletion** (`recall-retention`).
   - A handed-off transcript keeps its private retention. Once that passes, the
     transcript and everything Kindex derived from it are retracted.
   - A transcript that is emptied, or gone from a source that is scanned again, is
     retracted.
   - Reconciliation uses what the scan itself saw. A scan that began before the newest
     scan of the same source never imports, restores or retracts anything there.
6. **The question stays private** (`recall-question`). The question reaches Kindex on
   standard input, never on a command line. Recall raises no question to an owner,
   logs nothing, and writes nothing to a shared store, projection or hook.
7. **Team knowledge is opt-in** (`recall-team`). Shared statements go to a recall
   processor only when `kindex_team_knowledge` is set. They come from a read-only
   projection. A withheld projection passes none of its statements, and a released
   statement keeps its governance annotations.
8. **Receipts** (`recall-receipt`). Each recall and each digest names the processors
   it used: provider, model, account digest and retention mode. A recall also gives
   the SHA-256 of what Kinbase handed Kindex.

## Ratification

Ratification needs three things: the founder's ratification, a named human privacy
reviewer's sign-off on requirements 1 to 4 and 6, and a manifest entry that binds
this file's bytes. Until then, the README describes the behaviour as a branch
addition.
