# Vast instance risk observation 003

Status: **Validator observation; marketplace signal, not an SLA or Product proof**

At `2026-09-06T03:12:38Z`, the authenticated Vast instance endpoint for instance
`50012413` returned the following privacy-minimized, key-sorted projection. The API
credential and all unrelated response fields were excluded before recording:

```json
{"actual_status":"exited","bid_price":null,"dph_total":34.00219298245615,"duration":2588587.697316885,"end_date":1791252944.793963,"host_id":259870,"id":50012413,"intended_status":"stopped","is_bid":false,"machine_id":54969,"reliability2":0.9992037,"start_date":1788653963.803805}
```

The exact JSON line above, without its displayed trailing LF, has SHA-256
`93b6bf34f56f5324269d9347183021dfc370581e2f13d179239f7f34cad5baee`.

`is_bid=false` is evidence that this is not a bid-priced interruptible instance.
`reliability2=0.9992037` is a provider-reported marketplace field; Guildhall does not
interpret it as an SLA or as the probability of five uninterrupted hours. Host loss,
provider intervention, and ordinary hardware/network failure remain possible, and
the implementation attempt remains non-guaranteed.
