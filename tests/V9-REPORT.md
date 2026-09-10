# V9 follow-up

The source run is `/tmp/suite2.txt`: **305 passed, 21 failed, 10 setup errors**.
All ten host lifecycle errors precede product assertions: `KINBASE_HOST_CODEX`
and `KINBASE_HOST_CLAUDE` were unset. Parity failed for the same missing setting.

Changes:

- Host fixtures accept real installed executables on PATH when no explicit pin
  override is supplied. Overrides remain authoritative; executable validation,
  invocation recording and exact version reporting remain required. Version
  probes receive the isolated test environment, and unsuccessful probes fail.
- Raw retention now supplies native Codex `response_item/payload.content` JSONL.
  The former `message/payload.text` fixture produced no observations. The 24-hour
  bound and nonempty withheld-observation assertion are unchanged.
- Canonical admission parity retains standing, provenance, governed paths and
  anchors. Empty optional arrays normalize to `[]`. Full projection equality
  also retains `claimed_standing`; it is not a FactEvent field.

Unresolved finding: the five-run classifier test never reaches scoring because
the configured `ollama:qwen2.5:7b` is unavailable, extraction reports a fallback,
and doctor reports `classifier_pinned=false`. The assertion stays red. No model
was downloaded and no fallback was counted as a live pinned-classifier run.

Verification:

- The exact V9 pytest invocation encounters **12 setup errors** in this sandbox:
  `socket.bind` raises `PermissionError: Operation not permitted`. This is not
  host lifecycle, latency, blackhole or soak evidence.
- The existing retention and both plan/install test functions were also executed
  through the acceptance harness against the worktree release binary, a fresh
  isolated Git repository and a product-installed offline certificate: all pass.
  This supplemental check starts no Company service and does not replace V9.
- Real hosts resolved: `codex-cli 0.153.4`, `2.1.263 (Claude Code)`.
- Existing instrument regression modules: **136 passed**. New PATH/override
  fixture controls: **2 passed**. They are instrument checks, not host proof.
- `cargo fmt --all -- --check` passes. No Rust source edits were needed for the
  diagnosed V9 failures, and no latency, soak or classification floor was lowered.
- `cargo build --release --offline --locked` passes, including the final rebuild
  after the concurrent product changes.

The complete V9 gate still needs an unsandboxed run with these fixture repairs.
Committing is blocked by sandbox denial of the shared worktree's Git `index.lock`.
