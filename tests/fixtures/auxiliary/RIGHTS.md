# Auxiliary-corpus rights basis

## Status: INCOMPLETE — a named human rightsholder grant is outstanding

Detector Reviewer finding 21 is correct that a Tester assertion of authorship
cannot independently prove authorship or authority to grant a licence. That
gap is stated here rather than papered over, and the pool is **not selectable**
until it is closed.

## What the Tester can and cannot establish

The Tester **can** state, and this repository's history can corroborate, that
every byte under `sources/` first appeared in this lane, authored for this
acceptance instrument, and that no third-party text was reproduced, quoted or
adapted. That is a provenance *claim* with a checkable commit history.

The Tester **cannot** supply what the finding requires:

* a named human rightsholder,
* that person's signature over an exact licence grant, and
* an independently verifiable publication or authorship record.

Authoring any of those would be fabricating a human grant, which the Tester
dispatch forbids outright. So they are left blank, and the fields naming them
are present-but-null in `pool.json` so a Reviewer sees the exact hole.

## What is ready for the Reviewer

* Five candidate documents with recorded versions and per-file digests.
* Three generated components, each reproducible byte-for-byte from a named seed
  by `python3 -m acceptance._harness.auxgen` (see `generation` in `pool.json`).
* A combined digest that binds the complete pool manifest, this file, the rights
  metadata, candidate versions and declared ordering — not only content hashes.
* A deterministic selection protocol the Reviewer executes and signs.

## What is needed to close the finding

A named human with authority over these bytes must sign the exact grant text in
`GRANT-TEMPLATE.md`, and the signed bytes must be committed as `GRANT.md`. The
pool digest then rebinds over it and the Reviewer may select.
