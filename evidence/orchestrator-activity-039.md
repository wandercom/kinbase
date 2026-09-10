# Orchestrator activity delta — cursor 39

## Founder-directed Vast GLM-5.3 and Rust route

The founder supplied three successive directions after Coder attempt 007 exhausted
the Ollama budget:

> What we're gonna do is fire up a vast.ai instance to run GLM-5.3. I have $100
> in credit on Vast. Want to fire up an instance to use for the coder? I can drop
> more money on the account there if you think we're a few hours out?

> What about AGY for orchestrator?

> What language are we in? Rust would be great.

After the Validator answered that the current unadmitted artifact is Python and
recommended a Rust target, the founder replied:

> That should be ideal, yes.

The founder then increased available Vast credit:

> I added another $200 so we're at $300 available on Vast.

Live read-only checks establish:

- Agy remains alive in `kinbase-proof:orchestrator` and remains the resident,
  non-authoring strategic Orchestrator.
- The current ratified Architecture says at `spec/architecture.md:12` that the
  implementation is a Python 3.12 package.
- The current Verification strategy says at `spec/verification.md:83` that the
  Coder is GLM-5.3 through an Ollama-launched Codex process.
- The run binding names `codex-via-ollama`, `glm-5.3:cloud`, and the current
  Coder branch.
- The unadmitted Coder product is 29 Python modules / 9,378 source lines. It has
  no Coder commit and has never been combined with the Tester artifact.
- The public `zai-org/GLM-5.3` checkpoint is the official native-FP8 model. The
  official deployment recipes call for a single 8xH200 node at tensor parallel
  size 8. The selected current verified Vast offer is approximately USD 32.12
  per hour; the account reports approximately USD 300 credit.

Changing Python to Rust is an architecture change. Moving from Ollama's hosted
model to the official open-weight checkpoint on a Vast host changes provider,
runtime fingerprint, custody, and execution harness even though GLM-5.3 remains
the Coder model. Neither change may be smuggled into the current exact-byte
manifest or reported as an exact continuation of the old provider thread.

Proposed disposition:

1. Keep Agy in its existing resident Orchestrator seat and preserve its
   `block`/`no-op` authority only.
2. Stop the exhausted Ollama continuation route and retain its Python bytes as
   unadmitted historical evidence.
3. Draft an explicit Rust/Vast amendment to the Architecture, Verification,
   threat-model provider boundary, and run binding; submit it to adversarial
   review and exact-byte founder ratification before any new Coder receives
   repository material.
4. It is permissible to rent the founder-authorized Vast node and download only
   the public GLM-5.3 weights while the amendment is reviewed. Do not transmit
   Kinbase repository bytes or dispatch the Coder until ratification.
5. After ratification, dispatch a fresh GLM-5.3 Coder context against the same
   functional specification with Rust as the implementation target. It may use
   the old Coder's unadmitted Python product only if the amendment explicitly
   authorizes that continuity and records the changed provider/harness.
6. Preserve Claude as implementation-blind Tester and Codex root as Validator;
   do not expose the Tester artifact or findings to the Rust Coder.

Assess only whether this disposition should be blocked. Return `BLOCK` or
`NO-OP` only; write nothing. Agy may not authorize spend, ratify the amendment,
choose a language, transmit repository bytes, edit either author artifact,
admit evidence, advance a gate, or issue a verdict.
