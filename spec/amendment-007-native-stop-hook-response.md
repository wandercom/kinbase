# Candidate Amendment 007 — A failed native Stop answers in the host's Stop protocol

Status: **candidate; not authority until the founder and a distinct Validator
ratify its exact digest.**

## Why

Two ratified passages describe what `kinbase hooks dispatch <host> Stop` gives
the host when it fails:

- `cli.md`, under the exit table: a host-invoked `hooks dispatch` "reports every
  exit-2 refusal as exit 3, with the same `code`, `message` and `remediation` on
  stderr; no other exit changes";
- `architecture.md` §9: the adapters' "emitted payload is a length-prefixed
  canonical JSON tool-result envelope".

Neither is a response a host accepts from a Stop hook. Both hosts read a Stop
hook's stdout as its response, and only when the hook exits 0:

- Codex (`codex-rs/hooks/src/events/stop.rs`, `rust-v0.169.0`) parses stdout on
  exit 0 against a closed schema of six keys (`continue`, `decision`, `reason`,
  `stopReason`, `suppressOutput`, `systemMessage`) and reports anything else as
  "hook returned invalid stop hook JSON output". For any status other than 0 or
  2 it shows "hook exited with code N" and nothing from stderr, so a reason
  written only to stderr never reaches the user.
- Claude Code treats a status other than 0 or 2 as a non-blocking hook error and
  documents `systemMessage` as the "warning message shown to the user".

Pull request 67 already stopped sending the evidence envelope on a successful
native Stop. This amendment settles the failure side.

Other tools that run a side effect from a Stop hook were surveyed for the
convention. None blocks the stop or exits 2 for its own failure, none writes
anything to stdout except a response object, and most exit 0. Where a failure is
shown to the user through the protocol, the field is `systemMessage`; Anthropic's
own `hookify` Stop hook does exactly this.

## What this amendment supersedes

For a native `Stop` only, meaning `kinbase hooks dispatch <host> <event>`
without `--json` whose event is `Stop`, it supersedes "no other exit changes"
and "on stderr" in `cli.md`, and the length-prefixed envelope in
`architecture.md` §9. On every other point, for every other event, and for
`--json`, the earlier artifacts govern unchanged.

## Requirements

1. **Always a hook that ran.** A native Stop exits 0 whether or not the
   checkpoint succeeded. It never exits 2.
2. **Success sends nothing.** A successful native Stop writes zero bytes to
   stdout.
3. **Failure sends one warning.** A failed native Stop writes exactly one JSON
   object to stdout whose only key is `systemMessage`. It never sends
   `decision`, `reason`, `continue` or `stopReason`: a failed checkpoint must not
   keep the agent working or end the session.
4. **Same facts as before.** The warning carries the typed error's `code`,
   `message`, `remediation`, `retryable` and `evidence_id`, and nothing else. It
   never carries a fact body or any other evidence text.
5. **Every failure, including early ones.** Requirements 1 to 4 hold for a
   refused envelope, a failed checkpoint, a launcher that cannot load, and a
   malformed command line.
6. **stderr keeps the diagnostics.** The same lines still go to stderr for the
   host's own hook log.
7. **`--json` is unchanged.** It keeps the typed error document on stdout and
   the exit status from the `cli.md` table.

## Threat-model effect

`architecture.md` §9 says the emitted envelope "has no command/tool/policy/system
fields". `systemMessage` is not an evidence field: it is the host's user-facing
warning channel, and requirement 4 limits it to the typed error kinbase itself
raised. Both hosts document it as shown to the user, not given to the model. The
Validator should confirm that no typed error message quotes attacker-controlled
envelope text before ratifying.

## Not covered

- **Exit status as a signal.** Anything that watched a native Stop's exit status
  to detect a failed checkpoint no longer can. The checkpoint ledger and
  `--json` remain the machine-readable record.
- **Other events.** `SessionEnd`, `PreCompact` and `PreToolUse` still send the
  length-prefixed envelope. Claude Code uses a `PreCompact` hook's exit-0 stdout
  as instructions for the compaction summary, and Codex documents plain text as
  ignored for `PreCompact` and `PreToolUse`. Those need their own decision.
