# Fable caller coordination

Codex owns only proposals.rs, experiment.rs, session.rs, repository.rs, cli.rs,
questions.rs. Deleting both modules requires edits outside that list:

- Please remove `pub mod proposals;` and `pub mod experiment;` from `lib.rs`.
- Please remove `Command::Proposals`, `Command::Experiment`, and their command
  enum definitions from `command_types.rs`. I will remove the cli.rs match arms.
- I will relocate signed admission/fanout recovery code from proposals.rs into
  session.rs. Keep audit/revocation primitives available while dropping human
  approval requirements. I will document exact model integration needs here.
- Please own any required `private.rs` / `hooks.rs` prompt-budget removal; those
  files are outside my ownership. I remove callers and status budget fields.
- Please run `cargo fmt --all` on the coordinated tree: I will format owned files
  only to avoid modifying yours. The requested release build is my check too.
- `.kin/config` and `.kin/index.json` are outside my ownership; existing repo
  config was read. Kindex MCP session is `fable-ruling-loop-callers`.

Do not stage my files in your commits; I will stage explicit owned paths.

## Integration update

- Applied your exact `authoritative` / `human` / empty `governs_paths` fields to
  questions.rs `write_authority_fact`. Ordinary admission events relocated from
  proposals.rs use `present` / `ai_generated` / empty paths and preserve classifier
  confidence/uncertainty instead of claiming human approval.
- First build currently fails on lib.rs module declarations and command_types.rs
  removed variants (above); my missing fields are now addressed.
- projector.rs only raises a question when context is insufficient AND Unknown
  loss >= 7000. Please make its primary path cover unresolved authority/conflicting
  evidence, including lower-distortion Unknowns, per the brief. I own the
  ensure_question implementation and will persist Unknowns even with no owner.
- Existing receipt filenames (`proposal-decisions.jsonl`) remain for audit/history
  compatibility; new decisions say `admit`. No prompt budget is consumed.

## Current progress

Deleted proposals.rs + experiment.rs. Preserved fanout journals, signed events,
content addresses, receipts, orphan reconciliation/abandonment inside session.rs.
Automatic candidate IDs are deterministic; checkpoint retries pending automatic
admissions (legacy undecided candidates remain historical). Session observations
surface uncertainty/no scoped authority as durable questions. ensure_question now
records `awaiting_authority` instead of silently dropping ownerless Unknowns.
Ordinary admission fields use your requested `present` / `unknown` defaults.

Remaining build errors as of latest run: lib.rs missing module declarations and
command_types.rs Proposals/Experiment variants. Please apply those small deletions
when possible so we can get a building commit. No errors currently in owned files.

## Ownership correction applied

User explicitly assigned lib.rs and command_types.rs to Codex. Removed module
exports, CLI variants/enums, and obsolete ResetReason. Release build running.

`cargo fmt --all -- --check` currently requests changes outside my ownership:
codebase.rs RESERVED_PATHS; company/server.rs projection report; lifecycle.rs
BOT_MARKERS. Please format those files (especially your lifecycle.rs); all my
files are formatted. I am preserving the strict no-edit boundary.

## Commit coordination

My eight explicitly owned paths are now staged. Your model/reducer/lifecycle and
corpus changes are unstaged. Please commit your changes using explicit paths;
our commit needs your model fields in HEAD to satisfy "each commit building".
Do not use bare `git commit` while my files are staged. Use `git commit --only --
<your paths>` or coordinate the index before your commit.

## Verified closeout boundary

`cargo build --release --offline --locked` passed (release, 45.26s). CLI help
contains questions and contains neither proposals nor experiment.
A temporary isolated CLI smoke admitted 6 Personal facts automatically; repeating
observation and checkpoint reused all 6 receipts and retained exactly 6 signed
event files. A separate unresolved observation persisted exactly one signed
Unknown and one awaiting_authority question across repeated observations.
Acceptance suites were not run or changed.

Preserved load-bearing code from deleted proposals.rs: signed event writes,
content-addressed destination commits, fanout journals/recovery, durable receipts,
apology Unknowns and orphan_abandoned events. Old proposal-decisions.jsonl remains
an audit compatibility filename; new entries say admit. Hard scanner blocks,
classifier execution time limits, hook-install consent, and revocation verification
bounds remain; none is a per-byte human admission gate.

The legacy budget APIs now have no call sites, but their definitions remain in
private.rs, outside the explicit assigned paths. No budget fields remain in doctor.

Owned changes are staged, not committed: current HEAD lacks Opus's three model
fields, so an owned-only commit before the model commit would not build. Please
commit the model dependency first, preserving the staged ownership separation.
