# Validator rulings and judged runs — 2026-09-07

Validator: Claude (Fable 5.1) in the founder's Claude Code session, replacing the Codex
Validator. Mode: AI-rendered verdict, no human signature, per the local `/validate`
operating mode. Framing unrefuted by a human.

## Founder decisions recorded

- F-1. Implementation language is **Rust**. The Python Coder tree in the `coder` lane is
  discarded. Every other clause binds per the ratified baseline (commit `e29f3fe`,
  manifest `ac8a13d1…`); `spec/amendment-001-rust-vast.md` remains unratified.
- F-2. Claude subagents serve as Coder and Tester lanes because GLM-5.3 failed seven
  dispatches on provider capacity/billing. Independence rung: same model family for both
  lanes, separate contexts, separate worktrees, no channel. Recorded as the weaker rung.

## Validator rulings (design changes; unreviewed by a second party as of this writing)

- R-1. Reducer-invoking commands accept an optional `--as-of`; omitted, the command uses
  the recorded proof clock and records the value used. Documented cli.md invocations work.
- R-2. `company serve` creates/migrates its own SQLite schema idempotently at startup;
  `company init` is the steward preview/sign path. The "uninitialized store → exit 2" rule
  applies to client-side stores.
- R-3. Token files hold bare bearer-token bytes (mode 0600); scopes and client-key
  binding are service-side records.
- R-4. A token binds to the first Ed25519 client key that authenticates with it; later use
  under another key is refused indistinguishably. Residual: first-use binding.
- R-5. The HTTP wire contract (header names, signature payload, endpoint paths) and
  document `schema` strings used by the Tester instrument are adopted as the interface
  contract for this generation; they were not frozen in the ratified spec. A full
  interface-contract artifact is issued to the Coder lane.
- R-6. Accepted the Tester's removal of the exit-70 demand from the hostile-bytes probe:
  no black-box input can force a conforming product to raise an internal exception.

These rulings touch the authorization boundary (Critical). Per the Validator doctrine an
unreviewed ruling on a Critical surface blocks promotion; review by a party that did not
make them is outstanding.

## Judged runs (frozen snapshots; `-m "not slow and not soak and not requires_hosts"`)

| run | product | instrument | result |
|---|---|---|---|
| 002 | Python coder tree (uncommitted, Sep 5) | tester 8f23619 | 122 pass / 28 fail / 80 error; daemon refuses documented config |
| 003 | Rust b33b6d9 (+ uncommitted experiment.rs) | tester 8f23619 | 122 / 28 / 80; 73 errors are an instrument bug (`public_hex`) |
| 004 | Rust 9ac903b | tester ece0160 | 127 / 26 / 80; 74 errors: daemon closes socket without response |

Gate vectors: `validator-judge-run-002-gates.json`, `validator-judge-run-004-gates.json`.

## Human items outstanding (founder only)

1. Sign `tests/fixtures/auxiliary/GRANT-TEMPLATE.md` as CC0 rightsholder → `GRANT.md`
   (Detector Reviewer finding 21; V-3 stays `INVALID_HARNESS` until then).
2. Record the 20-item blinded operator exercise (V-9) on the proof machine.

## Vast

At 2026-09-08 ~02:00 UTC the account shows zero instances and USD 44.45 credit.

## Interface contract and conflict rulings

A Validator helper extracted the interface the Tester instrument assumes and found 28
conflicts with the ratified spec (`validator-interface-contract-v1.md` §7 and
`validator-rulings-C1-C28.md`). Rulings issued 2026-09-08; Coder received the contract
(addendum 2 to dispatch 009), Tester received remediation dispatch 007. The rulings are
Critical-surface design changes and remain unreviewed by a second party.

## Packet mode for the GLM Coder (2026-09-08)

The first GLM Ollama dispatch (attempt 008, one 66 KB brief) looped: whole-spec dumps into
context, repeated compaction, restart from the top, 100 commands and no commit. The
Validator switched to bounded packets, one fresh Codex thread per packet
(`control/launch-coder-packet.sh`, packets under `control/coder-packets/`). Packets 01–02
succeeded: 45 compile errors resolved, every cli.md command answers with the closed
exit-code table.

Codex 0.153 workspace-write denies `.git` writes regardless of permission profile (no prior
GLM attempt had ever committed). Rule: the Validator stages and commits the Coder's exact
bytes on its behalf, records the staged-diff SHA-256 in the commit message, and changes no
byte. Commit `92641c4` (staged diff `45c24423…`) is the first such commit.

| 005 | GLM packet 01 (uncommitted) | tester 5c9a7c9 | 134 / 80 / 19; daemon answers; instrument sequencing faults |
| 006 | Rust e5c832d (packet 03) | tester ffe3f75 | 135 / 8 / 97; one blocker: certificate cache (C2) |
| 007 | Rust cf3d040 (packet 04) | tester ffe3f75 | 141 / 70 / 29; full spread; V-8 blocked by instrument date bug |
| 008 | Rust 8240e8b (packet 05) | tester 2e7163b | 170 / 84 / 6; classifier mis-pinned under /tmp by Validator (R-16) |
| 009 | Rust d71c6f1 (packet 07) | tester 2e7163b | 186 / 68 / 6; V-7, V-8, V-10, NF instrument channels PASS; private files leak into tracked .kin (packet 09) |
| 010 | Rust 43b2b87 (packet 09) | tester 2e7163b | 192 / 62 / 6; tracked-.kin leak fixed; classifier spawn pipe deadlock; R-4 key binding conflict (R-17) |
| 011 | Rust 19943cd (packet 10) | tester 2e7163b | 189 / 65 / 6; regression: product never fetches the published authority registry, all planted signers UNVERIFIED (packet 12 item 0) |
| 012 | Rust 8314d8e (packets 11+12+13) | tester 2e7163b | 198 / 62 / 0; first zero-error run; authority cursor compared to the wrong counter (packet 15 A) |
| 013 | Rust 51d09d6 (packets 14-16) | tester 2e7163b | 197 / 63 / 0 |
| 014 | Rust c034ba7 (packets 17A/B, transcript-driven) | tester 2e7163b | 206 / 54 / 0 |
| 015 | Rust 94f374d (packets 18A/B) | tester b7bbb60 (live GLM classifier pinned) | 245 / 51 / 0; systemic: empty re-ingest, wall-clock as_of, fresh-clone unreachable |
| 016 | Rust 8544ea1 (packets 19A/B) | tester b7bbb60 | 243 / 53 / 0; GLM's systemic fixes not observed by the judge |
| 017 | Rust 8544ea1 | tester c9391e6 (Astra classified 52 nodes: 16 instrument, 16 sequencing, 20 product) | 271 / 42 / 0 |
| 018 | Rust 2ff910a (GLM packets 21A/B merged) | tester c9391e6 | 262 / 51 / 0; net regression from GLM packet 21 |

## Founder direction 2026-09-08 (evening): roles collapsed for the final push

The founder directed the Validator to take the Coder seat ("You're coder. Astra can
test. Sim and Advocate can advise but aren't final say, I am."). From commit `2ff910a`
onward the product is authored by the Validator and four Claude coder subagents in
worktrees `w1..w4`, each verifying against the judged nodes directly
(`control/judge-nodes.sh`). Astra (Codex) remains the Tester and never sees product.
Consequences stated for the verdict: Coder/Tester independence remains cross-family
(Claude vs Codex); Coder/Validator certification independence is collapsed and
"oracle independence unproven" applies to every commit after `2ff910a`. Coders may read
the suite but may not edit it or special-case it; that residual is disclosed.
GLM-5.3 (Ollama) consumed ~300M input tokens across 23 packets; the last packet regressed
the vector by nine nodes.

Fast-follows recorded by the founder: `spec/amendment-002-emission-ledger.md`
(candidate) and the rename to Kinbase; neither is in scope for this verdict.
| 019 | Rust 338ac3a (Claude coders w1+w3+w4 merged) | tester c9391e6 | 299 / 14 / 0; V-6, V-7, V-10, NF green |
| 020 | Rust 279bfac (all four Claude coders merged + R-18) | tester c9391e6 (live GLM classifier) | 306 / 7 / 0; remaining = 5 instrument items (Astra 012) + 2 human items |
| 021 | Rust 279bfac | tester 8d9e873 (Astra 012, live GLM classifier) | 317 / 6 / 0; residue: 4 product nodes (matrix cell 55, incremental stage 3, two-certificate fsck, pinned-runs F1 bound 0.877) + 2 human |
| 022 | Rust 019e510 | tester 76ddb30 | 335 / 5 / 0 (fast set only) |
| 024 | Rust a47d8cf | tester 76ddb30 | 337 / 3 / 0 (fast set only) |
| 025 | Rust efd089e (all four coder branches merged) | tester 76ddb30 | **346 / 3 / 0 over the COMPLETE suite, slow and soak included: product channel PASS on every gate V-1..V-10, nonfunctional and evidence.** The three failures are instrument-side, all downstream of the two human items: instrument-debt finding 21, the auxiliary-corpus selection record, and the operator-exercise gold join. |

## Complete-suite milestone (run 025, 2026-09-09)

First execution of all 349 nodes in one pass, with the live GLM classifier pinned and the
founder's recorded operator decisions present. Product channel: PASS on V-1, V-2, V-3, V-4,
V-5, V-6, V-7, V-8, V-9, V-10, NONFUNCTIONAL and EVIDENCE. Earlier runs excluded nine
slow/soak nodes; that exclusion is corrected here and in the verdict.
