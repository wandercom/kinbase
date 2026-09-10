# Vast account control observation 001

Status: **Validator observation; defense in depth, not a provider-liability bound**

At `2026-09-06T04:36:25Z`, an authenticated Vast current-user response was projected
locally to the following non-secret account-control fields:

```text
autobill_amount=None
autobill_threshold=None
balance=0
balance_threshold=-0.01
balance_threshold_enabled=True
billing_creditonly=1
credit=342.8348182854944
has_billing=True
```

No API credential or unrelated account field was retained. The observation says that
the provider represented the account as credit-only and exposed no configured
automatic-billing amount or threshold at that instant. It is not an SLA, does not
prove a bound on stopped-storage or delayed charges, and does not turn Kinbase's USD
400 local authorization ceiling into a provider-liability ceiling. G-2 must sample the
same fields again before launch and close admission if credit-only mode or the absence
of automatic billing changes.
