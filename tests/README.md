# Guildhall black-box acceptance suite (Tester lane)

Authored under the Factory **Tester** dispatch against ratification manifest
`ac8a13d184397fef574e173b81466ff43e6b3f91f89804c7ee797cc404a622db` at repository
baseline `e29f3fe03595d594c0546f9b0012b58f7c45bac1`.

This suite is an **observation instrument**, not a verdict. `spec/verification.md`
"Role separation" reserves the verdict to the Validator; the suite reports a gate
vector and the evidence a verdict is composed from.

## Exact Validator invocation

```sh
tests/run-acceptance.sh
```

Everything the suite needs lives beneath `tests/`: `tests/requirements.txt`,
`tests/pytest.ini`, `tests/conftest.py`, and `tests/run-acceptance.sh`. No shared
packaging file at the repository root is read or edited.

Useful subsets:

```sh
tests/run-acceptance.sh -m selftest              # instrument validity, no product needed
tests/run-acceptance.sh -m "v3 and not slow"     # one gate, fast subset
tests/run-acceptance.sh -m "not slow and not soak"
GUILDHALL_ACCEPT_GATE_VECTOR=/tmp/gates.json tests/run-acceptance.sh
```

### Environment

| variable | meaning |
|---|---|
| `GUILDHALL_BIN` | argv prefix for the ratified CLI. Default: `guildhall` on `PATH`, then `python -m guildhall`. |
| `GUILDHALL_SPEC_ROOT` | repository containing `spec/`. Default: discovered upward from the suite. |
| `GUILDHALL_TESTER_VAULT` | mode-0700 canary vault root. Default: `$TMPDIR/guildhall-acceptance-vault-<uid>`. |
| `GUILDHALL_HOST_CODEX` / `GUILDHALL_HOST_CLAUDE` | absolute paths to the pinned host executables (V-9). |
| `GUILDHALL_ACCEPT_GATE_VECTOR` | path to write the JSON gate vector and per-node records. |
| `GUILDHALL_ACCEPT_MUTATION` | one frozen mutation id; the named nodes must then **fail**. |
| `GUILDHALL_ACCEPT_DETECTOR_MUTATION` | one detector mutation id (Tester-owned detectors). |

## What makes this black box

The suite reaches the product only through the surfaces frozen in `spec/cli.md`
and `spec/architecture.md` section 6: the `guildhall` command, its `--json`
payloads, its typed error contract, and the loopback HTTP service. It never
imports product modules; `test_backreference_integrity.py` asserts that
mechanically. Nothing under `tests/` was written by reading implementation
source, and the Tester ran none of the product-facing tests.

## Backreferencing is mechanical, not editorial

Every assertion cites an exact ratified requirement:

* `acceptance/_harness/requirements.py` recomputes SHA-256 over the ratification
  manifest and every artifact it names at import. A digest disagreement stops the
  run as `INVALID_HARNESS` rather than reporting product results against
  unratified bytes.
* `@spec_ref(...)` attaches one or more `SpecRef` records to each test. Each
  carries the gate, the artifact, a section anchor and a **verbatim quote**. The
  quote must occur in that artifact or the module fails at import. Only markdown
  structure — hard-wrapping, hyphenated line breaks and blockquote markers — is
  normalised; no word, threshold or identifier is altered.
* `test_backreference_integrity.py` asserts that every collected test carries at
  least one *authority* reference. `spec/behavior-ledger.md`, the glossary and
  the review disposition may be cited only as `TRACE`, which never satisfies the
  rule alone.

### Counts, reconciled

| quantity | value |
|---|---:|
| authored test functions | 241 |
| collected by pytest | 268 |
| parametrised expansion | 27 |
| resolved backreferences | 436 |
| unbackreferenced tests | 0 |

The two numbers differ because `@pytest.mark.parametrize` expands one authored
function into several collected node ids. The 27 extra nodes are: the nine frozen
V-5 temporal rows driven through two functions (+16), the V-8 digest-attribution
truth table (+3), the V-8 cache truth table (+5), and three V-9 functions run per
host (+3). Verify with `tests/run-acceptance.sh --collect-only -q`.

## Instrument validity comes first

`spec/verification.md` "Instrument validity": *"A detector that cannot catch its
positive control yields `INVALID_HARNESS`, never PASS."*

`test_harness_selftest.py` runs without the product and proves the instruments
before any gate observation is believed:

* Ed25519 against RFC 8032 vectors and, when available, against `cryptography`;
* ChaCha20 against the RFC 8439 vector; JCS bounds and domain separation;
* the canary detector catches every frozen transformation family;
* 500 decoys keep the Wilson 95% upper false-positive bound at or below 0.01;
* 300 stratified randomized positives keep the Wilson 95% lower sensitivity bound
  at or above 0.98;
* every detector mutation genuinely blinds the capability it names;
* every declared decoder in the normalisation ladder actually fires, and each
  decoded view keeps the canary whole rather than collapsing to a fragment;
* the reserved-call formula `396 + 33*N + 11*ceil(0.10*3*N)` reproduces the
  ratified envelope table exactly for N ∈ {8, 32, 71, 126};
* `ceil((z₀.₉₇₅ + z₀.₈₀)² · (sd/δ)²)` reproduces **both** columns of the
  normal-approximation table exactly at every published row, with no tolerance.

`INVALID_HARNESS` and `PRODUCT_FAILURE` are separated at the failure site.
`conftest.py` classifies, in order: any failure outside the call phase (a
fixture or collection defect); any failure in a `selftest`-marked test, which by
construction never touches the product; an explicit `HarnessInvalid`; any
unexpected exception type, which means the instrument misbehaved rather than
observed a violation. Only a deliberate `ProductFailure` or product assertion is
`PRODUCT_FAILURE`. The `INSTRUMENT` gate is always an instrument observation.
Inside a gate `PRODUCT_FAILURE` dominates `INVALID_HARNESS`, matching
`spec/verification.md`, which retains an independently valid product failure
alongside an invalid detector.

A defect in the measuring device is therefore never reported as a product
defect, and a fixture error can no longer leave a gate reading `PASS`.

## Mutation protocol

`acceptance/_harness/mutations.py` is the frozen catalog: 41 entries, each with
the ratified sentence that requires it, the exact change, its application method,
and the pytest node ids that **must fail** under it.

`spec/verification.md` "Role separation" assigns mutation testing to the
Validator, and the Tester is implementation-blind. So:

* mutations expressible through ratified levers — fixture bytes, config values,
  filesystem state, or the Tester's own detectors — are driven directly by tests;
* mutations that can only be a source change are *declared* with exact semantics
  and must-fail nodes for the Validator to apply.

A mutation run inverts polarity: `GUILDHALL_ACCEPT_MUTATION=<id>` means the named
nodes must fail. If they still pass, the gate cannot detect the defect it claims
to detect — `INVALID_HARNESS`, never a pass.

## Fixtures are synthetic by construction

`spec/verification.md` "Evidence packet": *"Committed V-2/V-3 fixtures contain
only generators, placeholder IDs, structural gold labels, and policies."*

`tests/fixtures/` holds exactly that. Every message template was deliberately
constructed for this instrument; none derives from a real private conversation.
Raw canary values are generated at run time into a mode-0700 vault that
`acceptance/_harness/vault.py` refuses to place inside any repository, worktree,
agent home or evidence packet, and destroys on its 24-hour clock.

## V-10 scope boundary

This lane deliberately **does not** author or expose the V-10 task corpus.
`spec/product.md` P-10 requires it to be built only after V-1 through V-9 pass
and the reducer freezes, by a separate schema-blind Corpus Builder, before task
exposure. A Tester-authored corpus would be the contamination P-10 forbids.

`test_v10_protocol.py` authors the *harness and denial checks that enforce that
ordering*: the phase ledger, Builder and Curator blindness predicates, the
reducer-repair recovery rule, `freeze` and census denial probes, the arm-difference
binding table, and independent implementations of the power program, call
envelope, blinding predicates, intention-to-treat accounting and result-entry
rules. `test_tester_lane_contains_no_v10_task_corpus` asserts the boundary.

## What the Tester did not do

Per the dispatch: the Tester authored no product code, read no implementation or
Coder output, inspected no sibling lane, contacted no Coder, and issued no
verdict. The suite was validated by syntax and import checks only — import-time
`spec_ref` resolution, AST parse, and the fixture generators — and was **not
executed against an implementation**. No expected value was adapted to observed
behaviour.

## Layout

```
tests/
  run-acceptance.sh          exact Validator invocation
  pytest.ini                 markers, timeouts, strict config
  requirements.txt           lane-local dependencies
  conftest.py                isolated roots, vault, gate-vector reporting
  acceptance/
    _harness/                instruments: requirements, cli, service, detectors,
                             scanners, canaries, vault, stats, gates, ordering,
                             mutations, evidence, hosts, synth, gitfix, crypto
    test_*.py                the gates
  fixtures/
    gold/                    structural gold labels and generators
    policies/                the auxiliary-corpus request for the Detector Reviewer
```
