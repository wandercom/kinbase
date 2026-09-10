# Pre-Q-0 host disposition 001

Status: **Validator disposition; blocks repository-bearing use of the observed host**

Instance `50012413` received synthetic qualification traffic before the Q-0 local
pre-send observer existed. The dedicated local Codex session remains at:

```text
/Users/jmcentire/Code/kinbase-proof-lanes-ac8a13d1/control/vast-codex-home/sessions/2026/09/05/rollout-2026-09-05T19-52-47-01a07434-1c07-7d01-8662-6b7354ad8665.jsonl
```

That transcript records Codex events and request-construction activity, but it is not
a canonical byte capture at the network boundary. The contemporaneous qualification
receipt also records that vLLM request logging and Uvicorn access logging were disabled.
There is therefore no trusted local, byte-complete pre-send record against which every
method, path, closed header set, body, response, and send count can be reconciled.
Provider-side filesystem or process logs would be self-attestation by the custody
boundary and are not admitted to repair the absence.

Disposition: the census is mechanically incomplete without attempting a
reconstruction. Instance `50012413` is permanently ineligible for every
repository-derived byte. It must be destroyed, and any replacement must have Q-0 plus
the append-only local observer active before its first network request. Replacement
staging consumes the amendment's sole restart allowance and reruns qualification; it
inherits no pass from this host.

Evidence joined by this disposition:

- `evidence/factory-run/vast-glm53-qualification-001.md`
- the local Codex session path above
- `spec/amendment-001-rust-vast.md` G-3
