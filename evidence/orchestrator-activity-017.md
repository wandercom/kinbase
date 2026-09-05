# Orchestrator activity delta — cursor 17

## New observation

The Validator admitted the exact Tester commit into its standalone clone and ran
only the product-independent instrument selector:

```text
tests/run-acceptance.sh -m selftest --tb=line -q
```

It collected 266 tests, selected 83, and returned 12 failures / 71 passes. The
Validator classifies the result as `INVALID_HARNESS`; no product implementation
was present, and the suite's emitted `PRODUCT_FAILURE` labels are rejected.

## Proposed action

Resume the same Claude Opus Tester session in the existing standalone Tester
repository, from exact commit `f8d9cba2cdd3de05663de9d9fffa9d0176f9d747`,
with the causal-prior packet and binding committed at `0749eea`. The repair scope
is only `tests/**`; the Tester may run only product-independent self-validation.
Coder, Validator, and product implementation paths remain forbidden. Authoring
spend is capped at USD 10. The Coder remains stopped and the GLM-to-GPT routing
block remains in force.

## Requested assessment

Assess whether this Tester-only instrument remediation violates Factory role
separation, the frozen manifest, or the product-proof objective. Return `BLOCK`
or `NO-OP` only. You may not approve the instrument, authorize spending, alter
routing, implement, test, or render a verdict.
