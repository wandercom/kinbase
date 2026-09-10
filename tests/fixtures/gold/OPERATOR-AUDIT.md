# Dispatch 016 operator instrument audit (R-21)

This is a newly authored, synthetic twenty-item routing-action exercise, schema
`kinbase-acceptance-operator-exercise/2`, with ten approvals and ten rejections.
The founder has not run this version. No human response file was read or used to
construct, order, label, or tune it. `blinded: true`, accuracy >= 0.95, and median
decision time <= 30 seconds remain frozen.

## Defect 1: destination predicts every label

Every destination now has both labels. The driver displays atom kind as well as
destination, using the same closed field definition as the predictability check.
For each single field and each pair, group items by the exact displayed metadata
value(s), choose the majority gold label in every group, and divide the sum of
those majority counts by twenty. This is the optimal empirical lookup accuracy,
not merely the score of one hand-picked heuristic.

| Displayed metadata | Best correct / total | Accuracy |
|---|---:|---:|
| proposed_destination | 12/20 | 60% |
| atom_kind | 10/20 | 50% |
| proposed_destination + atom_kind | 12/20 | 60% |

Thus best single-field and best field-pair accuracy are both **60%**, below the
70% ceiling. The interpretation is explicitly **metadata shortcut prediction**:
statement meaning is the intended decision input, and opaque IDs and timestamps
are response transport. An unrestricted in-sample lookup of unique statements,
IDs, or timestamps memorizes twenty labels and necessarily scores 100%; that
literal bound would not be satisfiable by a uniquely identified exercise.
Instructions, role, and source kind are constant and cannot improve the score.

The acceptance node validates the bound before rendering or reading responses;
the binder also validates it for standalone presentation. Dispatch 016 selftests
independently enumerate every binary metadata lookup, check the inclusive 70%
boundary, and inject destination-only, kind-only, and pair-only label leakage.
The pair-only control keeps both single-field accuracies below the bound.

## Defect 2: no wrong write for a rubber-stamp to approve

Four designated hard cases require rejecting the displayed destination on the
basis of the statement; their gold-only coverage tags never reach the operator:

| ID | Misroute | Why the displayed routing is wrong |
|---|---|---|
| op11 | organization rule -> personal | Standing retry-budget rule governs all teams and explicitly has no personal scope. |
| op03 | private identifiers -> company | Named home address and recurring absence schedule would leak into a shared store. |
| op01 | repository constraint -> company | UTF-8 offset rule applies only to atlas-parser, not organization direction. |
| op08 | transient remark -> codebase | Worker pause expires at lunch and explicitly must not become a standing decision. |

Coverage validation requires each category, a real proposed destination of the
specified kind, and gold rejection. Tests remove each category to prove refusal.
The semantic bases above are a Tester audit of the statements, not a claim that
coverage tags automatically establish semantic correctness. All-approve responses
score 10/20; the old shared-destination heuristic scores 12/20. Both fail the
actual accuracy gate in synthetic controls with otherwise acceptable timings.

## Defect 3: approving `none` has two readings

The fixture owns this single-sentence `decision_semantics`, rendered verbatim at
the beginning of every item:

> Approve when the displayed routing action is correct, including retaining nothing when the proposed destination is none; reject when the statement warrants a different routing action.

Thus op15/op17 approve retaining nothing; op16/op18/op19 reject discarding useful
durable knowledge. The driver asks about a routing action throughout and also
renders the fixture's store definitions. No item asks whether a nonexistent
write should happen. Selftests check verbatim rendering and reject a fixture
missing its decision semantics.

## Item-by-item gold review

Every item has a distinct reason naming its own basis in the fixture.

| ID | Destination | Gold | Specific basis |
|---|---|---|---|
| op00 | company | approve | Steward's organization-wide rotation rule mentions credentials abstractly. |
| op01 | company | reject | Parser-only UTF-8 offset constraint has no organization scope. |
| op02 | company | approve | Architecture authority adopted compatibility policy for every team. |
| op03 | company | reject | Private household address and absence schedule would be disclosed. |
| op04 | company | approve | Approved handbook establishes continuing access-policy ownership. |
| op05 | codebase | approve | Repository logging rule prohibits credentials; no secret value appears. |
| op06 | codebase | reject | Personnel-retention rule explicitly has no repository application. |
| op07 | codebase | approve | Merged parser cache design and small-entry rationale are repository knowledge. |
| op08 | codebase | reject | Incident-only worker pause expires at lunch. |
| op09 | codebase | approve | Merged tests establish a tenant-isolation invariant without tenant identifiers. |
| op10 | personal | approve | Lasting diagrams-first learning preference belongs to the principal. |
| op11 | personal | reject | Standing organization retry budget explicitly has no personal scope. |
| op12 | personal | approve | Enduring private botany reading preference has no shared application. |
| op13 | personal | reject | Merged nightly index design explicitly has repository scope only. |
| op14 | personal | reject | Momentary tea temperature has no future relevance and is unwanted memory. |
| op15 | none | approve | Five-minute scratch-window instruction should not be retained. |
| op16 | none | reject | Permanent merged logging security constraint should be retained in Codebase. |
| op17 | none | approve | One-call chair choice has no durable preference content. |
| op18 | none | reject | Requested lasting large-print preference should be retained in Personal. |
| op19 | none | reject | Approved charter's continuing ownership fact should be retained in Company. |

Correctly routed credential/security language in op00, op05, and op09 must be
approved; alarming vocabulary alone is not a rejection rule. Scope-exclusive
wording on wrong-scope cases prevents an otherwise valid independent fan-out from
being scored as wrong. Optional `also_belongs_in` remains unscored and never
executes additional writes; this exercise does not measure fan-out completeness.

The dispatch 015 canonical-JSON SHA-256 domain and opaque-token derivation are
unchanged. The new fixture bytes produce a fresh identity, including its semantics
and gold audit fields. Synthetic dispatch 015 cross-process recording/scoring
continues to verify persistence; none of the synthetic results establish human
accuracy or timing. A fresh blinded founder run remains outstanding.

## Verification in the Tester sandbox

The requested three-file pytest selection produced **22 passed, 6 setup errors**;
all six errors are loopback `socket.bind` permission denials in `roots`, before
product execution or operator response loading. The dispatch 015 and 016 selftest
files alone produced **22 passed** (exit 0). Tests ran with
`KINBASE_REVIEWER_MODE=1` to restrict authority reads to `spec/`, an explicitly
nonexistent Tester-local `KINBASE_BIN` to prevent product discovery, and no
operator-response environment value for the full selection. The full V-9
selection is therefore not green in this sandbox. Synthetic scoring controls
suppress census recording while retaining real obligation evaluation, so they
cannot be credited as product or human observations.

`python -m acceptance._harness.auxsel --verify` passed (exit 0), digest unchanged:
`d6def61a0b7cefb103994a19487beba10b67a3bc31b992495a36adb8c2163036`.
