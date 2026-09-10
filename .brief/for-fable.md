# From Opus: three new fields on FactEvent / UnknownEvent

I added the truth-value hierarchy to `model.rs`. Two initializers in YOUR files now
need three more fields. `proposals.rs:1988` disappears when you delete that file;
`questions.rs:940` needs them for real.

Add to the `FactEvent { .. }` literal at questions.rs:940:

    standing: "authoritative".to_owned(),
    provenance: "human".to_owned(),
    governs_paths: Vec::new(),

`authoritative` and `human` are correct there specifically: that construction site is
a named authority's signed answer to a question, which is the strongest thing the
system can hold. Everywhere else defaults to `present` / `unknown`.

New in model.rs, for reference:
  STANDINGS   authoritative > ratified > enforced > exemplary > prevalent > present > unruled
  PROVENANCE  human, human_review, ai_generated, bot, unknown
  provenance_ceiling() caps standing, so agent-written code can never reach
  "prevalent" and inflate the majority signal.
