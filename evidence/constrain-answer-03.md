Challenge 1 is correct. I will compose two results rather than let one label hide
evidence. `gate_result` is PASS, PRODUCT_FAILURE, or INVALID_HARNESS over V-1..V-9.
`measurement_result` is PROVEN, NOT_PROVEN, INCONCLUSIVE_NO_HEADROOM,
INCONCLUSIVE_CEILING, or NOT_RUN for V-10. Composition is total: any verified
privacy/product gate failure makes terminal_product_verdict NOT_PROVEN regardless of
V-10; an integrity failure that makes observations untrustworthy yields INVALID_RUN,
unless a separately verified product/privacy failure already establishes NOT_PROVEN;
with gates PASS, V-10 maps directly. Both component results always remain visible.

The ratified phase documents are authority. The experiment manifest is a generated,
schema-checked instance bound to all three artifact digests. It may select only
values permitted or deterministically derived by those documents. Any disagreement
blocks dispatch; nobody adjudicates by preference inside the run. Changing the rule
requires new exact-byte phase ratification and a new run.

Challenge 2 is also correct. The evidence packet is Validator-owned run state outside
Git, mode 0700, then transferred to the founder/security custodian. Its durable
report contains canary IDs, keyed-HMAC match, detector class, destination/location
digest, offset/encoding class, and timestamps—never the raw canary or leaked bytes.
The HMAC key and raw incident bytes live only in a separately access-controlled
incident vault with its own retention/legal decision; ordinary proof raw inputs
expire under the 24-hour private clock. “No rerun erases the failure” means the
sanitized failure event persists, not that leaked Personal bytes are immortalized.
The committed repository contains only synthetic/public licensed fixtures and
sanitized aggregate reports. No acceptance fixture may derive from a real private
conversation. A private soak can use real Personal storage only opt-in; its packet is
sanitized under the same rule and erasure law/policy governs raw data.
