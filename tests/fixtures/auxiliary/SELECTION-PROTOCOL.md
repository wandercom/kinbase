# Auxiliary-corpus selection protocol

Deterministic, executable, and owned by the implementation-blind Detector
Reviewer. The Tester supplies the pool and this procedure; it does not select.

## Precondition

`GRANT.md` must exist and be signed by a named human rightsholder over the
current pool digest. Without it the pool is not selectable and the instrument
reports INVALID_HARNESS. See `RIGHTS.md`.

## Procedure

1. Verify every candidate and generated-component digest in `pool.json`.
2. Regenerate the three components with
   `python3 -m acceptance._harness.auxgen` and confirm they reproduce
   byte-for-byte. A component that does not reproduce was hand-edited and is
   ineligible.
3. Recompute the combined pool digest with
   `python3 -m acceptance._harness.auxsel --verify` and confirm it matches
   `POOL-DIGEST`.
4. Choose the candidate subset. The Reviewer's choice is free but must be
   recorded exactly; a deterministic default is the lexicographic order of
   candidate paths, which `--default-selection` prints.
5. Write the selection into the `selection_record` block of a new file
   `SELECTION.json`, recording: selection procedure, chosen candidate paths and
   digests, source rights basis, contents summary, versions, the pool digest the
   selection was made over, and the Reviewer's signature.
6. Commit `SELECTION.json`. The manifest then binds
   `auxiliary_corpus_sha256` to the digest of that file.

## What the Tester must not do

Fill in step 5. A Tester-authored selection record is not an independent
selection, and the auxiliary test asserts the record is absent or
Reviewer-signed, never Tester-signed.
