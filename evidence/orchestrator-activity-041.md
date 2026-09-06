# Orchestrator activity delta — cursor 41

## Vast recovery requirement and completed synthetic qualification

The founder added a hard operational requirement: completed Coder results must
survive a Vast instance failure. The Validator amended
`spec/amendment-001-rust-vast.md` at commit `498388d`; its new SHA-256 is
`9b2e1f85b0d84ae6c9ccc7aeb13f410654085a77aa748b975f72998391d71c49`.
It remains candidate-only and cannot authorize Coder dispatch.

The candidate now requires:

- a non-ephemeral, resumable local Codex thread;
- a dedicated run-only Codex home;
- local native-session and operator-event journals `fsync`ed before console
  forwarding;
- coherent local Git checkpoints, with no more than fifteen minutes of materially
  changed state carried without a checkpoint;
- same-thread recovery after restoring the pinned serving configuration;
- no remote persistence of repository-bearing prompts, responses, or results;
- explicit treatment of vLLM prefix cache as volatile performance state only; and
- a forced synthetic endpoint-loss drill before any repository prompt.

The synthetic-only receipt is
`evidence/factory-run/vast-glm53-qualification-001.md`, SHA-256
`b97292121176d5eed3be2002493d034ea88015143e1e0b84c6d8c54387d5a1db`.
It records these observed results:

- the pinned BF16-KV server provides 351,488 cache tokens, 1.34 times the bound
  262,144-token request;
- a 262,067-input-token request completed;
- an exact repeat cached 261,952 tokens;
- the Responses function-call protocol and actual local Codex shell loop work;
- cutting the SSH tunnel during a local tool call did not lose the completed tool
  result; the same thread/turn finished after reconnection;
- explicit resumption of that same non-ephemeral thread recovered prior state; and
- the first recovery attempt failed closed when configuration isolation selected
  the wrong provider; a dedicated Codex home corrected the structural cause.

No repository/specification/lane/test/Kindex/credential/Personal/Company/customer
content was transmitted. The host remains inference-only. Credit was USD 263.841
after staging and qualification, from approximately USD 300.014 at route start.

Assess only whether the new requirement, candidate bytes, qualification result, and
remaining route still advance the founder's ultimate goal without goal substitution,
dropped proof functionality, remote-custody regression, or role collapse. Return
`BLOCK` or `NO-OP` only and write nothing. Agy may not revise or ratify the candidate,
authorize repository transmission or spend, inspect Tester work, edit an author
artifact, admit evidence, advance a gate, or issue a Product verdict.
