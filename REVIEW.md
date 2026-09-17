# Review Checklist — kinbase

## Always check

- **Canonical records vs. host input.** Anything written to a ledger or signed event goes through the canonical writer (`crate::json::try_canonical_bytes`: JCS, NFC, the text rule — no C0/C1 controls, bidi controls or noncharacters, no binary floats). A host envelope (`hooks dispatch` stdin) is data from another authority: parse it with `json::parse_host_envelope` (prose folded, identifiers and paths validated and refused), never with the record parser.
- **Writers refuse; readers skip and report.** A writer refuses a value that fails the canonical rule (`insert_observation`, `log_query`, `append_jsonl`); it never stores `""`. A reader that meets one unreadable row skips it and emits `unreadable-ledger-rows` through `crate::output::report_unreadable_rows`; it never fails the whole read and never stays silent. A zero count with no signal is a bug.
- **Identifiers are validated, never folded.** `session_id`, `id`, `cwd`, `transcript_path`, event names, tool ids: a control character there is a different identity or directory. Refuse with a typed error; only prose is folded.
- **Typed errors and exit codes.** Every failure is a `ContractError` whose code is in `error.rs::CODES` with the exit that code implies (`ContractError::new` turns a mismatch into `RUN_INTEGRITY_FAILED`). The one sanctioned override: host `hooks dispatch` reports exit 2 as 3 (`ContractError::for_host_hook`, spec/cli.md error contract), because a host treats exit 2 as a block. Hook dispatch also puts the reason on stderr in host mode — the host hides stdout.
- **Host hook install is additive.** `hooks install` keeps every foreign handler byte for byte and replaces only this program's own `hooks dispatch <host> <event>` entry; reinstall is idempotent. Never rewrite another tool's hook list.
- **Hook cost is paid every turn.** Stop, SessionEnd, PreToolUse and UserPromptSubmit run on every host event; nothing on that path may materialise a ledger (stream it, prefilter by canonical marker). `SessionStart` has a 2 s p95 budget (`spec/architecture.md`). Measure against the live Personal store's sizes, not fixtures.
- **Signals carry no private bytes.** A diagnostic names a ledger or query, positions and byte counts — never record content, never the Personal root path.
- **Spec is the authority.** Behaviour is authorised by `spec/*.md` (ratified, exact-byte). A change that contradicts a spec passage is a spec defect to raise, not a deviation to ship; cite the section in the commit body.
- **Tests.** Regression probes live in `crates/kinbase/tests/`; run `cargo test --lib --test authority_boundaries --test hook_install_and_ledger` (`tests/repo_init_certificate.rs` does not compile on `main` as of 2026-09-16). `tests/run-acceptance.sh` is the Validator's black-box suite: the Coder neither runs nor edits it. Probes isolate `HOME`, `XDG_CONFIG_HOME`, `XDG_STATE_HOME` and a Personal `data_root` under a temp dir; nothing touches the live store.

## Style

- Sentence-case imperative commit subject with a prose body that names the failure and the fix (see `git log`); `Refs:` / `Spec:` trailers when there is a task or spec item.
- Comments say why and name the failure that motivated the code; no TODO/FIXME/stub/placeholder.
- Do not run `rustfmt` over whole files: `main` carries pre-existing drift. Format only your hunks and compare the count of `cargo fmt --check` diffs in your files before and after.
- Rebuilding `target/release/kinbase` changes the digest pinned by `classifier.executable_sha256` in `~/.config/kinbase/config.toml`; re-pin after a release build or the classifier refuses to run.
- No new dependency for what `std` already does (streaming, byte search, hashing is already vendored).

## Skip

- `target/`, `Cargo.lock` churn.
- `evidence/` (ratification artefacts), `tests/*-REPORT.md`, `tests/RULING-*.json`, `tests/fixtures/` (frozen catalogs).
- `spec/` — ratified; changes there are governance and reviewed separately.
- `docs/` site content.
