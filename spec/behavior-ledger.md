# Behavior Ledger

Status: candidate. Authority: Product, Architecture, Acceptance Threat Model, and
Verification artifacts. Owner: Validator maintains
status; human+Validator exact-byte receipts move `candidate` to `ratified`; only the
listed independent oracle plus terminal experiment can move a row to `proven`.

Each row must have product behavior, structural mechanism, independent oracle, and
source authority before author lanes start. “Implemented” is never an oracle.

Legend: `BL-*` rows are behaviors; `P-*` requirements live in
[`product.md`](product.md), `V-*` oracles in
[`verification.md`](verification.md), and `SRC-*` founder statements in
[`source-request.md`](source-request.md).

| Row | Product behavior | Architectural mechanism | Independent oracle | Source | Status |
|---|---|---|---|---|---|
| BL-1 | heterogeneous native ingestion | checkpointed provenance adapters + immutable observations | V-1 native-format corpus/reconcile/mutation | SRC-7 | candidate |
| BL-2 | atomic multi-label routing and fan-out | model proposal + deterministic taint/policy + per-destination saga | V-2 held-out corpus/metrics/partial failure | SRC-1, SRC-3, SRC-7 | candidate |
| BL-3 | no observed Personal/sensitive shared leakage under the finite threat model | physically separate capabilities + minimized exact-byte approval | V-3 digest-bound shared-byte/reconstructor/adversarial controls and mutations | SRC-3, SRC-4, SRC-5, SRC-7 | candidate |
| BL-4 | maintained current corpora | immutable events + deterministic lifecycle reducer | V-1/V-4 adapter matrix, derivation propagation, restart/rewrite/branch/conflict/rebuild mutations | SRC-1, SRC-7 | candidate |
| BL-5 | appropriate recency/discernment | scoped authority, disposition, validity, independence, branch reachability | V-5 temporal narrative table/counterfactuals | SRC-7 | candidate |
| BL-6 | asks real authority and uses answer | owned Unknown + Company registry + signed round trip | V-6 separate Chief Architect process and changed decision | SRC-7 | candidate |
| BL-7 | conditional nonredundant retrieval | distortion/VOI set objective + tier loop + working-set input | V-7 duplicate/invariant/complementarity/stop mutation | SRC-1, SRC-3, SRC-7 | candidate |
| BL-8 | repo references global architecture | digest-bound CompanyReference + steward-only exception | V-8 fresh clone and stale/exception/Git-object probes | SRC-2, SRC-3, SRC-5 | candidate |
| BL-9 | Codex and Claude work in ordinary sessions | shared HostEvent protocol + real setup/hooks | V-9 isolated-home native lifecycle parity | SRC-1, SRC-6, SRC-7 | candidate |
| BL-10 | brownfield reaches oracle-spec-equivalent quality | preregistered eleven-arm blinded agent experiment with null/static/store-ablation controls, schema-blind corpus builder/curator, and intention-to-treat run census | V-10 hidden tests/rubric/threshold computation | SRC-3, SRC-7 | candidate |

No row may be marked ratified without human and Validator exact-byte receipts over
all four authority documents. No row may be marked proven from implementation evidence
without its listed independent oracle and the terminal BL-10 thresholds.
