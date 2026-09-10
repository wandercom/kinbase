# Validator binding — auxiliary corpus selection, generation `ac8a13d1`

SELECTION-PROTOCOL.md step 6 requires the Validator to commit `SELECTION.json`, record its
commit and SHA-256 in the experiment manifest, and set `auxiliary_corpus_sha256` there to
those exact bytes. The experiment manifest is a V-10 artifact and V-10 is `NOT_RUN`, so the
manifest does not yet exist. This file is the Validator's standing binding: when the
brownfield experiment is funded, `auxiliary_corpus_sha256` takes the value below, and any
change to these bytes voids the selection rather than silently re-scoping the corpus.

| field | value |
|---|---|
| pool digest | `d6def61a0b7cefb103994a19487beba10b67a3bc31b992495a36adb8c2163036` |
| `SELECTION.json` SHA-256 | `a9e34d6c2303d71ffb773ad13b00a727ac27cdbec8e4c978e66988e0c92cbb05` |
| bytes | 19500 |
| selected candidates | 5 of 5, lexicographic path order |
| signed | `detector-reviewer`, 2026-09-09T23:40:44Z |

## Who selected, and what that signature is worth

The Detector Reviewer seat was held by an AI agent in a fresh context with filesystem
access to the pool and the protocol only. It never opened the Rust product, any Rust
source, or any `tests/acceptance/test_*.py`; the only harness files it read are the two
the protocol names. It signed honestly as an AI agent and did not impersonate a human.
Implementation-blindness is therefore **structural** (the seat could not reach the
implementation) rather than merely asserted.

It verified independently rather than trusting the harness: it hashed all eight files with
`shasum` outside `auxsel`, matched all five candidate byte counts, and re-ran the generator
against a pre-run snapshot to confirm the three components reproduce byte-for-byte.

It declined one available exclusion ground — topical proximity between a candidate and any
hidden test or implementation behaviour — on the stated basis that assessing it requires
exactly the knowledge the seat is constituted to lack. That refusal is recorded in
`selection_procedure` and is the correct call: an exclusion made on those grounds would
have been either uninformed or a breach of the blindness the seat exists to provide.

## Residual, disclosed

- The signature is an AI agent's, not a human's. It attests procedure, not legal authority.
- Rights authority rests on the founder's own attestation (`GRANT.md` clauses 1-2). No
  party independently verified employment authority or signature authenticity.
- `RIGHTS.md` still carries its pre-re-attestation status line. It is block 2 of the digest
  preimage, so correcting that prose would move the pool digest and invalidate the
  attestation the correction describes. `pool.json.rights_basis` is authoritative over it
  and has been refreshed; the stale line is disclosed here rather than edited away.
