# Ruling acceptance rewrite

The offline release build passes. The acceptance suite is **not green**: its final
run reports **218 passed, 117 setup errors, zero assertion failures** in 104.29s.
Every setup error is `PermissionError: [Errno 1] Operation not permitted` while
binding a loopback socket. These nodes never reach their product assertions.

Collection changed from **371 to 335 nodes**: 52 obsolete nodes retired, one raw
retention test renamed/reworked, and 16 ruling-path nodes added. Exact node lists,
binary digest and run details are in [RULING-RESULTS.json](RULING-RESULTS.json).

The suite deletes the eleven-arm outcome protocol, approval-fatigue/operator
exercise gates and their dedicated regressions. Classification, minimization,
partial fan-out, receipt replay, orphan deadlines and crash recovery now use
`session observe` / `session checkpoint` and durable private audit records.
Failure injection precedes automatic admission; crash recovery still requires an
observed transition, SIGKILL and independent concurrent retries. Privacy scanning
covers automatic admission, replay, retention and the retained shared surfaces.
Catalogs, frozen controls, backreferences and the execution census were updated.

The new release-binary cases cover:

- Twelve direct admissions, independently verified signatures/content addresses,
  stable receipts, and shared admission followed by signer revocation.
- Durable ownerless Unknowns and conflicting evidence without answering authority.
- One ratified rule against 256 distinct present events, in both arrival orders.
- Agent provenance against every stronger standing; 32 git commits with agent
  coauthor trailers, compared with unmarked history.
- An existing question followed by an authoritative `shrug`, versus `unruled`,
  across repeated projection and rebuild.
- Absence of the retired CLI commands.

Direct local admission, durable ownerless Unknowns and the CLI-removal case pass.
The other new cases need the Company fixture and remain unverified in this
sandbox. There is no confirmed product finding from those setup errors. The user's
binary-only instruction supersedes the brief's request to call
`model::effective_standing` directly: its behavior is asserted through signed
fixtures and the shipping reducer CLI, without another Cargo project or dependency.

Preserved: three-store/privacy boundaries, temporal/supersession behavior,
signature/content-address integrity, revocation, crash recovery and host hooks.
Host-install consent is still meaningful and remains tested. The service fixture
still supplies `candidate_lifetime_seconds`: the current service config parser
requires that field. It no longer licenses an admission-expiry assertion. Historical
spec/manifest bytes remain as authority for retained contracts; the user's new
contract is recorded in [RULING-CONTRACT.md](RULING-CONTRACT.md).

Validation used only the existing suite and this worktree's release binary:

```sh
cargo build --release --offline --locked
cargo fmt --all -- --check
cd tests
KINBASE_BIN=/Users/jmcentire/WanderRepos/kinbase-work/target/release/kinbase \
  ./.venv/bin/python -m pytest -c pytest.ini -q acceptance/
```

`git diff --check` passes. Changes are unstaged: `git add` and `git commit` cannot
create the worktree's `index.lock`, whose Git metadata is outside the writable
sandbox. No product source files were edited for this suite task.
