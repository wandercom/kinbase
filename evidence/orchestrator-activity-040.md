# Orchestrator activity delta — cursor 40

## Exact Rust/Vast amendment candidate

The Validator drafted `spec/amendment-001-rust-vast.md` at commit `2e81285`.
Its SHA-256 is
`f051cfea375ba227876eaaafad5a9f380a454bfdd0fe6a431570d0e9b3798f70`.
It is explicitly candidate-only and cannot authorize a Coder dispatch.

The candidate:

- makes Rust 1.98.1 / edition 2024 the production implementation target while
  retaining all existing Product behavior and proof gates;
- keeps one deployable workspace with distinct non-convertible store handles and
  preserves the ratified process/capability boundaries;
- names the exact official GLM-5.3 model revision and vLLM image digest;
- keeps the agent/tool harness local and the Vast host inference-only, reachable
  only over an SSH tunnel with request/access logging disabled;
- permits only the same GLM Coder to use its unadmitted Python tree as historical
  translation input, and forbids it from the final production artifact;
- preserves Agy, Claude Tester, and Codex Validator roles and the no-Tester-to-Coder
  boundary;
- names the Vast custody limitation, destroy semantics, USD 210 warning point, and
  USD 285 no-new-turn ceiling inside the founder-authorized USD 300;
- requires synthetic Responses/tool-loop, BF16-KV capacity, and prefix-cache probes
  before any repository byte reaches Vast;
- treats the existing Tester rights grant and Detector Review as still blocked.

The public model is staging on Vast instance 50012413. No Kinbase repository byte
has been transmitted to it. The live rate including 1 TB storage is USD 34.0022 per
hour. The old Python Coder tree remains isolated and unadmitted.

Assess whether this exact candidate advances the founder's ultimate goal without
dropped proof functionality, role collapse, or dishonest attribution. Return
`BLOCK` or `NO-OP` only and write nothing. Agy may not revise or ratify the
candidate, authorize repository transmission or spend, inspect Tester work, edit an
author artifact, admit evidence, advance a gate, or issue a verdict.
