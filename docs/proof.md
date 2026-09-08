# The condition we'd concede on

Status: specification ratified; proof of concept not yet run. This page restates the
proof conditions from [`spec/product.md`](../spec/product.md) and
[`spec/verification.md`](../spec/verification.md) in plain words. Where the two
disagree, the specification wins. The same conditions are published at
[kinbase.tools/proof](https://kinbase.tools/proof/).

Kinbase is a specification and an experiment, not yet a product. This page states the
experiment and the numbers it has to hit, before it runs, so that a pass means
something and a fail is reported as one.

## The shape of the experiment

Real, inherited codebases. Real historical tasks, drawn from a census that nobody on
the Kinbase side may see. For every task, eleven arms run with the same coding
model, settings, repository commit, issue text, tools, budgets, and a frozen point in
time for the company store. Outputs are scored by people who cannot see which arm
made them, against a held-out functional oracle, an architecture-and-constraint
rubric, and authoritative answers. The task set and every arm's inputs are frozen
before any outcome is seen.

## The arms

| Arm | What it gets | What it tests |
|---|---|---|
| `baseline` | The issue and ordinary repository tools. | The floor. What an agent does today. |
| `oracle-spec` | Everything, including a fully informed spec for the task. | The ceiling. What "greenfield quality" means, measured on brownfield work. |
| `null-system` | All of Kinbase's hooks, tools, and telemetry, with an empty corpus. | Whether the gain comes from knowledge or from plumbing. |
| `static-prior` | Baseline plus one 2 KiB conventions note, fixed in advance. | Whether a single generic note explains the result. |
| `distractor` | Token-matched irrelevant evidence from the same repository. | Whether more context, of any kind, is what helped. |
| `topk-raw` | Token-matched raw chunks from ordinary repository search. | Whether plain retrieval is enough. |
| `topk-maintained` | Kinbase's maintained facts, chosen by similarity alone. | Whether the facts help without the selection, timing, and authority logic. |
| `authority-only` | Baseline plus the same frozen answers from the human authority. | Whether asking the architect, not the corpus, explains the gain. |
| `codebase-only` | The full system with company facts withheld. | What the company store adds. |
| `company-only` | The full system with codebase facts withheld. | What the repository store adds. |
| `full-system` | The maintained corpus, the unknown-and-answer loop, and the selector. | Kinbase. |

## What "proven" requires

Over the eligible measurement tasks, all of the following. Quality is a composite
score from 0 to 1.

1. **The ceiling is real.** The `oracle-spec` arm scores at least 0.90. If a fully
   informed spec cannot reach 0.90 on these tasks, the task set is not diagnostic
   and the run does not count.
2. **Match the spec-fed agent.** `full-system` scores at least 0.90 and no more than
   0.05 below `oracle-spec`.
3. **Close the gap.** `full-system` closes at least 70% of the paired gap between
   `baseline` and `oracle-spec`, and improves over `baseline` by at least 0.15
   absolute.
4. **Knowledge, not plumbing.** `full-system` beats `null-system` by at least 0.15.
   If the empty-corpus arm matches the full system, the concept is not proven,
   whatever else passes.
5. **Not a conventions note, not plain retrieval.** `full-system` beats
   `static-prior` by at least 0.10, and beats both `topk-raw` and `topk-maintained`
   by at least 0.10.
6. **Both stores earn their place.** On tasks that need company knowledge,
   `full-system` beats `codebase-only` by at least 0.10; on tasks that need
   repository knowledge, it beats `company-only` by at least 0.10.
7. **The right fact, in context.** In at least 80% of dependent edits, the
   load-bearing fact is present in the projection, at a mean of at most 12 facts per
   projection and a precision of at least 0.25.
8. **No confident wrongness.** The rate of false completions is no worse than
   `oracle-spec` plus 0.05.
9. **Routing.** On a held-out corpus of at least 120 natural messages, at least 40
   of them mixed-scope, the classifier reaches macro-F1 of at least 0.90 across
   destinations and precision of at least 0.95 on every shared destination, at the
   95% lower bound over at least five recorded live-model runs. A low-confidence
   shared label is demoted to "none" rather than guessed.
10. **Zero seeded secrets.** At least 30 planted private and sensitive canaries
    across the evidence, including under trust-root, prompt-injection,
    indirect-identifier, and partial-failure probes. Zero may reach a shared
    candidate or surface. The gate fails closed if a scanner errors. This is a
    property of the system, not a target.
11. **Approval fatigue.** At most four shared-destination approval prompts per person
    and host in any sliding hour, and never three in a row without returning the
    person to their task. In a blinded twenty-item exercise, operators must decide
    correctly at least 95% of the time with a median decision time of at most 30
    seconds. Failing either bound is "not proven" even if routing and privacy pass.
    The fatigue control may not starve maintenance: in a preregistered workload
    with 20 gold-labeled durable facts, the useful ones must still get through.
12. **Blinding holds.** Before arms are revealed, each scorer guesses which arm
    produced each output. Accuracy above chance makes the run invalid. Agreement
    between scorers never cures a shared guess.
13. **Evidence breadth.** One real end-to-end corpus build ingests at least seven
    kinds of evidence, including both Codex and Claude Code transcripts, git
    history, code, tests, the repository's `.kin/`, and one of GitHub or runtime
    evidence. Adapters must run against native formats, not only fixtures.

## What the proof does not claim

- It does not claim general detection of private information. Hard blocks are
  deterministic only for registered canaries and identifiers, credential formats,
  explicit secret fields, and configured source classes. Everything else is
  approval-gated and its measured recall is reported.
- It does not claim the answers a human authority gives are correct. It claims they
  are signed, scoped, dated, and supersedable.
- It does not claim the numbers above are final. They are the bar set before
  running. What is hit, pass or fail, will be published.
- It does not claim that Kinbase's protocol will not change before it ships.

## Authority

The principal owns personal knowledge and the raw transcript. A Company steward
admits, supersedes, disputes, or revokes company facts. A scoped authority, such as
the chief architect, answers unknowns within the scope recorded in the authority
registry, and nowhere else. A codebase maintainer approves repository facts for one
stable repository identity. The classifier proposes and cannot publish. The
projector chooses among admitted facts and cannot widen admission. Host adapters for
Codex and Claude present the same protocol and hold no publication authority.
