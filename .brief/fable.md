# Fable: cut the approval gate, make the ruling loop the main path

You are working in `~/WanderRepos/kinbase-work` (branch `rescue/ruling-loop`).
Claude Opus is working the same branch in parallel. **Strict file ownership** —
do not edit files outside your list, even trivially; we will collide.

  YOURS:  proposals.rs, experiment.rs, session.rs, repository.rs, cli.rs, questions.rs
  NOT YOURS (Opus owns): model.rs, classifier.rs, reducer.rs, lifecycle.rs

## Why

Kinbase indexes a company's knowledge so AI coders can tell, in a brownfield repo,
which signals are direction and which are noise. It currently gates that behind a
human approving **every byte** admitted to a shared store, capped at 4 prompts/hour
per person. For 40 engineers that starves by construction: the queue refills faster
than anyone can drain it, so the corpus never fills and the tool never helps.

The valuable half is already built and currently subordinate: `questions.rs`, the
Unknown → question → named-authority → signed-answer loop. One ruling from an
architect settles a question permanently and serves every future session. That is
where scarce human attention belongs. Per-byte approval is the part to delete.

## What to do

1. **Delete `proposals.rs` (2,735 lines) and `experiment.rs` (1,138 lines).**
   `experiment.rs` is the eleven-arm research harness; it is not product.
   Remove the `proposals` and `experiment` CLI subcommands with them.

2. **Rewire the callers** — `session.rs`, `repository.rs`, `cli.rs` reference both.
   Where a candidate previously waited for per-byte approval, it should now be
   **admitted directly**, and the approval budget/ceiling logic goes away entirely.
   Keep every signed-event, content-address and revocation path intact: the audit
   trail is cheap and invisible and we keep it. What we are removing is the *human
   gate*, not the record.

3. **Make the ruling loop the main path.** When the system cannot resolve something
   — conflicting evidence, no authority in scope — it opens an Unknown and asks the
   named authority, exactly as `questions.rs` already does. That path stays and
   becomes the primary way a human is ever interrupted.

4. `cargo build --release --offline --locked` green. `cargo fmt --all`.
   Do not chase the acceptance suite in `tests/` — it encodes the approval gate we
   are deleting and will fail loudly. Leave it; we rewrite it after the model lands.

## Rules

- Small commits, each one building. Message says what and why.
- If you need a change in one of Opus's files, **write it in `.brief/for-opus.md`**
  and keep going; do not edit it yourself.
- No new dependencies.
- If something in your files looks load-bearing for the ruling loop, keep it and say
  so rather than deleting to hit a line count.

Report when the build is green: what you deleted, what you rewired, anything you
kept that the brief told you to cut, and why.
