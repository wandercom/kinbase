# Vast SSH documentation observation 001

Status: **external-source observation only; not host attestation or Product evidence**

At `2026-09-06T02:40:00Z`, the Validator fetched Vast's official SSH connection guide
from `https://docs.vast.ai/guides/instances/connect/ssh`. The retrieved HTML was
519,658 bytes with locally computed SHA-256
`f4f35d8579a059642d3fd639af2eed65da2f7a1485e0a398831acf4a8948df01`.

The guide's illustrated SSH session displays an ED25519 fingerprint and then answers
the ordinary first-contact prompt `Are you sure you want to continue connecting
(yes/no/[fingerprint])? yes`. The inspected guide does not provide a separately signed
or control-plane-bound host-key attestation. This supports only the amendment's narrow
claim about Vast's published connection flow; it does not prove a first contact was
free of MITM, identify the actual run host, or authorize repository disclosure.

The live run must record its own first-contact and subsequent fingerprints, Vast API
instance/machine observation, any independent-path observation, and the unresolved
identity limitation.
