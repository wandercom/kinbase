# Vast review-window status 005

Status: **Validator observation; budget input, not Product evidence or route authorization**

At `2026-09-06T03:41:03Z`, the authenticated Vast current-user endpoint reported
`344.0965542854942` credit. This is `99.5481465800003` higher than the observation at
`2026-09-06T03:21:16Z`. A follow-up read of Vast's invoice endpoint found a
provider-issued Stripe credit row for exactly USD 100.00 beginning at
`2026-09-06T03:30:02.746Z` (invoice ID `3420078`, service `stripe_payments`). The
approximately USD 0.4519 difference is consistent with the already observed stopped
storage rate over the intervening time. The credit is therefore attributed account
funding rather than an unexplained balance movement. It still does not expand the
Kinbase route ceiling until the founder ratifies the exact amendment proposing that
authorization.

At the same observation, instance `50012413` remained
`actual_status=exited`/`intended_status=stopped` on machine/host
`54969`/`259870`, at running rate `34.00219298245615` USD/hour. Provider fields
`is_bid=false` and `reliability2=0.9992037` were unchanged. The earlier
provider-reported stopped-storage rate remains `1.370614035087719` USD/hour.

Only the privacy-minimized fields above were retained. The API responses were piped
directly into field projections and were not written to disk. G-2 must sample live
again and apply the separately ratified route ceiling before restart. Vast's official
billing API documentation identifies the invoice endpoint as the authority for Stripe
top-ups and other billing transactions; the documentation was observed on
`2026-09-06` at `https://docs.vast.ai/api-reference/billing/show-invoices`.
