//! P-7: deterministic, inspectable set-conditional projection.
//!
//! The selector is deliberately arithmetic-only: every reported term is a
//! signed integer in basis points. It never claims a causal quantity; it is
//! an additive approximation over admitted facts and explicit Unknowns.
//!
//! ```text
//! marginal(a | S, d) =
//!     newly_covered_distortion(d, a, S)
//!   + authority_and_validity_gain(a)
//!   + complementarity_gain(a, S)
//!   + uncertainty_reduction(a, d, S)
//!   - redundancy(a, S)
//!   - retrieval_and_residency_cost(a)
//!   - stale_or_conflict_risk(a)
//! ```
//!
//! `S` is the current set: the caller-declared working set already resident
//! at the dependent edit plus everything selected so far. Penalty terms are
//! reported as the positive magnitudes the formula subtracts.

use crate::error::ContractError;
use crate::launcher::Launcher;
use crate::model::{CurrentFact, FactEvent};
use crate::reducer::{CurrentView, ReducerInput};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const PROJECTION_LIMIT: usize = 32;
pub const PROJECTION_BYTE_LIMIT: usize = 128 * 1024;
/// How many rejected evaluations of the stopping round the trace retains.
const STOP_ROUND_TRACE_LIMIT: usize = 16;
const TIERS: [(&str, i64, i64); 7] = [
    ("facts_and_unknowns", 0, 100),
    ("summary", 500, 100),
    ("exact_code_span", 1_200, 200),
    ("history_adr", 800, 150),
    ("test_runtime_evidence", 1_500, 200),
    ("authority_answer", 0, 300),
    ("broad_search", 250, 250),
];

#[derive(Debug, Clone)]
pub(crate) struct UnknownOut {
    pub(crate) unknown_id: String,
    pub(crate) logical_key: String,
    pub(crate) scope: String,
    pub(crate) decision_blocked: String,
    pub(crate) owner_role: String,
    pub(crate) owner_identity: String,
    pub(crate) question: String,
    pub(crate) evidence: Vec<String>,
    pub(crate) loss_if_absent: u16,
    pub(crate) status: String,
    pub(crate) kind: String,
}

/// One candidate scored against the current set. Gains are non-negative;
/// `redundancy`, `retrieval_and_residency_cost` and `stale_or_conflict_risk`
/// are the non-negative magnitudes the marginal subtracts.
#[derive(Debug, Clone)]
struct Evaluation {
    marginal_value: i64,
    newly_covered_distortion: i64,
    authority_and_validity_gain: i64,
    complementarity_gain: i64,
    uncertainty_reduction: i64,
    redundancy: i64,
    retrieval_and_residency_cost: i64,
    stale_or_conflict_risk: i64,
    redundancy_basis: String,
    complementarity_basis: String,
}

impl Evaluation {
    fn terms(&self) -> Value {
        json!({
            "newly_covered_distortion": self.newly_covered_distortion,
            "authority_and_validity_gain": self.authority_and_validity_gain,
            "complementarity_gain": self.complementarity_gain,
            "uncertainty_reduction": self.uncertainty_reduction,
            "redundancy": self.redundancy,
            "retrieval_and_residency_cost": self.retrieval_and_residency_cost,
            "stale_or_conflict_risk": self.stale_or_conflict_risk
        })
    }
}

fn trace_step(
    fact: &CurrentFact,
    evaluation: &Evaluation,
    current_set_size: usize,
    action: &str,
    reason: &str,
) -> Value {
    json!({
        "fact_id": fact.fact_id,
        "logical_key": fact.logical_key,
        "action": action,
        "selected": action == "selected",
        "selection_reason": reason,
        "marginal_value": evaluation.marginal_value,
        "current_set_size": current_set_size,
        "redundancy_basis": evaluation.redundancy_basis,
        "complementarity_basis": evaluation.complementarity_basis,
        "marginal_terms": evaluation.terms()
    })
}

pub fn run(
    launcher: &Launcher,
    repo: &Path,
    task: &str,
    decision: &str,
    working_set: &[String],
    as_of: &crate::time::AsOf,
    json: bool,
) -> Result<(), ContractError> {
    // Authority refresh is an optimization, not a command gate. When Company
    // is unavailable, the cached projection is still emitted and the explicit
    // degraded policy withholds the dependent decision.
    let _ = crate::repository::ensure_authority_snapshot(launcher, None, &as_of.as_of);
    let mut facts = Vec::new();
    let mut ingested_events = Vec::new();
    let mut conflict_event_ids = BTreeSet::new();
    let mut view_unknowns = Vec::new();
    let mut references = Vec::new();
    for store in [crate::StoreKind::Company, crate::StoreKind::Codebase] {
        let store_view = load_view(launcher, repo, store, as_of)?;
        conflict_event_ids.extend(
            store_view
                .view
                .traces
                .iter()
                .flat_map(|trace| trace.conflict_event_ids.iter().cloned()),
        );
        facts.extend(store_view.view.facts);
        view_unknowns.extend(store_view.view.unknowns);
        ingested_events.extend(store_view.events);
        references.extend(store_view.references);
    }
    // A closure record is authoritative across stores: the original Unknown
    // remains in append-only history, but no later projection may treat it as
    // still blocking after the signed answer.
    let closed_unknown_ids: BTreeSet<String> =
        [crate::StoreKind::Company, crate::StoreKind::Codebase]
            .into_iter()
            .filter_map(|store| crate::store::read_records(store, repo, "unknowns.jsonl").ok())
            .flatten()
            .filter(|record| {
                matches!(
                    record.get("status").and_then(Value::as_str),
                    Some("closed") | Some("superseded")
                )
            })
            .filter_map(|record| {
                record
                    .get("fact_id")
                    .or_else(|| record.get("unknown_id"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect();
    view_unknowns.retain(|unknown| !closed_unknown_ids.contains(&unknown.unknown_id));
    facts.sort_by(|left, right| left.fact_id.cmp(&right.fact_id));

    // A `question` atom is an open Unknown owned by the authority that asserted
    // it. It is never trusted guidance and never enters the selectable set.
    let (question_facts, facts): (Vec<CurrentFact>, Vec<CurrentFact>) = facts
        .into_iter()
        .partition(|fact| fact.atom_kind == "question");
    let question_unknowns: Vec<UnknownOut> = question_facts
        .iter()
        .filter(|fact| !closed_unknown_ids.contains(&question_unknown_id(fact)))
        .map(question_unknown)
        .collect();

    let working: BTreeSet<&str> = working_set.iter().map(String::as_str).collect();
    let candidates: Vec<&CurrentFact> = facts
        .iter()
        .filter(|fact| {
            fact.status == "current"
                && fact.trust == "trusted"
                && fact.stale_reasons.is_empty()
                && !matches!(
                    fact.disposition.as_str(),
                    "disputed" | "expired" | "conflict"
                )
        })
        .collect();
    let unknowns = unknown_outputs(&facts, &view_unknowns, &question_unknowns);
    let roles = Roles::derive(&facts);
    let mut candidate_documents: Vec<(String, Value)> = facts
        .iter()
        .map(|fact| (fact.fact_id.clone(), candidate_value(fact, &roles)))
        .collect();
    // Byte accounting for the ceilings: each candidate's canonical size once;
    // a JSON array of k values costs their sizes plus k-1 commas and two
    // brackets.
    let value_bytes: BTreeMap<String, usize> = candidate_documents
        .iter()
        .map(|(id, value)| (id.clone(), crate::json::canonical_text(value).len()))
        .collect();
    let mut represented_ids: BTreeSet<String> = candidate_documents
        .iter()
        .map(|(id, _)| id.clone())
        .chain(question_facts.iter().map(|fact| fact.fact_id.clone()))
        .collect();
    for event in ingested_events {
        if represented_ids.contains(&event.fact_id) {
            continue;
        }
        represented_ids.insert(event.fact_id.clone());
        candidate_documents.push((
            event.fact_id.clone(),
            event_candidate_value(&event, &conflict_event_ids, &as_of.as_of),
        ));
    }
    candidate_documents.sort_by(|left, right| left.0.cmp(&right.0));
    let candidate_values: Vec<Value> = candidate_documents
        .into_iter()
        .map(|(_, value)| value)
        .collect();
    let open_unknowns: Vec<_> = unknowns
        .iter()
        .filter(|unknown| {
            unknown.status == "open"
                || unknown.status == "asked"
                // A conflict whose scope has no registered authority carries
                // UNKNOWN_OWNER_UNRESOLVED rather than "open". Excluding it here is
                // how contested keys went silent: the absence of an owner became the
                // reason nobody was ever asked to become one. It is still an open
                // question -- it is the question of who should answer it.
                || (unknown.status == "UNKNOWN_OWNER_UNRESOLVED" && unknown.kind == "conflict")
        })
        .cloned()
        .collect();
    // Low-distortion Unknowns are represented, but only a high-distortion
    // Unknown blocks dependent trusted guidance.
    // An Unknown blocks this projection when it names the task or the
    // decision as the decision it blocks, when its own precise question is
    // the decision at stake, or when it is architecture-owned.
    let has_blocking_unknown = open_unknowns.iter().any(|unknown| {
        unknown.loss_if_absent >= 7_000
            && (unknown.decision_blocked == decision
                || unknown.decision_blocked == task
                || unknown.question == decision
                || unknown.scope.starts_with("architecture:")
                || unknown.owner_role == "chief-architect")
    });

    // The current set S starts as the caller-declared working set: facts
    // already resident at the dependent edit. They condition every marginal
    // but are never re-selected; re-adding a resident fact has zero value.
    // A working-set entry is either a fact id or a file path. Requiring fact ids
    // only was unusable from the seat that matters: an agent about to edit
    // `src/pay/reconcile.ts` knows the path and not which facts describe it, and
    // had to be told "unresolved" for every entry. A path entry resolves to every
    // fact anchored in that file or under that directory.
    let resolves = |fact: &CurrentFact, entry: &str| -> bool {
        fact.fact_id == entry
            || fact.anchors.iter().any(|anchor| {
                anchor.path == entry
                    // A directory entry covers the files beneath it; a file entry
                    // covers anchors into that file. Both need the separator so
                    // `src/pay` never reaches `src/payments-legacy`.
                    || anchor.path.starts_with(&format!("{}/", entry.trim_end_matches('/')))
            })
    };
    let residents: Vec<CurrentFact> = candidates
        .iter()
        .filter(|fact| working.iter().any(|entry| resolves(fact, entry)))
        .map(|fact| (*fact).clone())
        .collect();
    let resident_ids: BTreeSet<String> =
        residents.iter().map(|fact| fact.fact_id.clone()).collect();
    let working_set_unresolved: Vec<&str> = working_set
        .iter()
        .map(String::as_str)
        .filter(|entry| !residents.iter().any(|fact| resolves(fact, entry)))
        .collect();
    let mut context: Vec<CurrentFact> = residents.clone();
    let mut selected: Vec<CurrentFact> = Vec::new();
    let mut selection_trace = Vec::new();
    for fact in &residents {
        let evaluation = resident_evaluation();
        selection_trace.push(trace_step(
            fact,
            &evaluation,
            context.len(),
            "resident",
            "working_set_resident",
        ));
    }
    let context_bytes = |set: &[CurrentFact], extra: Option<&CurrentFact>| -> usize {
        let count = set.len() + usize::from(extra.is_some());
        let total: usize = set
            .iter()
            .chain(extra)
            .map(|fact| value_bytes.get(fact.fact_id.as_str()).copied().unwrap_or(0))
            .sum();
        total + count.saturating_sub(1) + 2
    };
    let mut sufficiency = false;
    let mut byte_ceiling_hit = false;
    let mut stop_round: Vec<(&CurrentFact, Evaluation)> = Vec::new();
    while context.len() < PROJECTION_LIMIT {
        let mut round: Vec<(&CurrentFact, Evaluation)> = Vec::new();
        for fact in &candidates {
            if context
                .iter()
                .any(|existing| existing.fact_id == fact.fact_id)
            {
                continue;
            }
            let evaluation = evaluate(fact, &context, task, decision);
            if context_bytes(&context, Some(fact)) > PROJECTION_BYTE_LIMIT {
                if evaluation.marginal_value > 0 {
                    byte_ceiling_hit = true;
                }
                continue;
            }
            round.push((fact, evaluation));
        }
        // Deterministic order: marginal value, then role priority, then id.
        round.sort_by(|(left, left_value), (right, right_value)| {
            right_value
                .marginal_value
                .cmp(&left_value.marginal_value)
                .then_with(|| {
                    candidate_priority(roles.name(right)).cmp(&candidate_priority(roles.name(left)))
                })
                .then_with(|| left.fact_id.cmp(&right.fact_id))
        });
        let Some((fact, evaluation)) = round.first().cloned() else {
            break;
        };
        if evaluation.marginal_value <= 0 {
            // The loop stops on net marginal value: record why every
            // remaining candidate was left out, best first.
            stop_round = round;
            break;
        }
        selection_trace.push(trace_step(
            fact,
            &evaluation,
            context.len(),
            "selected",
            "positive_conditional_marginal_value",
        ));
        selected.push(fact.clone());
        context.push(fact.clone());
        if is_authority_answer(fact) && !has_blocking_unknown {
            sufficiency = true;
            break;
        }
    }
    let rejected_count = stop_round.len();
    for (fact, evaluation) in stop_round.iter().take(STOP_ROUND_TRACE_LIMIT) {
        selection_trace.push(trace_step(
            fact,
            evaluation,
            context.len(),
            "rejected",
            "nonpositive_conditional_marginal_value",
        ));
    }

    let question_id = if !has_blocking_unknown {
        None
    } else {
        let evidence: Vec<String> = context
            .iter()
            .map(|fact| fact.fact_id.clone())
            .chain(
                open_unknowns
                    .iter()
                    .flat_map(|unknown| unknown.evidence.clone()),
            )
            .collect();
        let remaining: Vec<String> = candidates
            .iter()
            .filter_map(|fact| {
                if context
                    .iter()
                    .any(|selected| selected.fact_id == fact.fact_id)
                {
                    None
                } else {
                    Some(fact.statement.clone())
                }
            })
            .collect();
        let mut raised = None;
        // A contested key always asks, whatever its computed loss.
        //
        // The loss threshold is right for uncertainty that might not matter: do not
        // interrupt a person over a gap the projection can live without. A conflict
        // is the opposite case. Two incompatible statements are both being carried,
        // and every session that reads this key will pick one by accident until
        // somebody rules. "Which of these five implementations?" is the question the
        // loop exists to ask, and it is worth a minute of an architect's time even
        // when the individual fact looks cheap.
        //
        // This holds especially when no authority is registered for the scope: that
        // unknown carries UNKNOWN_OWNER_UNRESOLVED, and suppressing it would make
        // the absence of an owner the reason nobody is ever asked to become one.
        for unknown in open_unknowns
            .iter()
            .filter(|unknown| unknown.loss_if_absent >= 7_000 || unknown.kind == "conflict")
        {
            if let Some(id) =
                crate::questions::ensure_question(repo, unknown, decision, &evidence, &remaining)?
            {
                raised = Some(id);
                break;
            }
        }
        raised
    };

    let stopping_reason = if question_id.is_some() {
        "authority_question_raised"
    } else if sufficiency {
        "sufficiency_predicate_met"
    } else {
        "nonpositive_net_marginal_value"
    };
    let item_ceiling_hit = context.len() == PROJECTION_LIMIT
        && candidates.iter().any(|fact| {
            !context
                .iter()
                .any(|existing| existing.fact_id == fact.fact_id)
                && evaluate(fact, &context, task, decision).marginal_value > 0
        });
    let omitted_count = if byte_ceiling_hit || item_ceiling_hit {
        candidates.len().saturating_sub(context.len())
    } else {
        0
    };
    let tier_escalation: Vec<Value> = TIERS
        .iter()
        .map(|(tier, value, cost)| {
            json!({"tier": tier, "estimated_value": value, "estimated_cost": cost, "action": "visited"})
        })
        .collect();
    let invariant_selected = context
        .iter()
        .any(|fact| roles.name(fact) == "high_distortion_compatibility_invariant");
    let projection_bytes = context_bytes(&selected, None);
    let resident_bytes = context_bytes(&residents, None);
    let company_reference = company_reference(&context, &facts);
    let context_ids: BTreeSet<&str> = context.iter().map(|fact| fact.fact_id.as_str()).collect();
    let selected_reference = references
        .iter()
        .filter(|record| {
            crate::json::get_str(record, "fact_id")
                .is_some_and(|fact_id| context_ids.contains(fact_id))
        })
        .find(|record| crate::json::get_str(record, "resolution") == Some("resolved"))
        .cloned();
    let effective_reference = selected_reference
        .clone()
        .or_else(|| references.first().cloned());
    let company_owner = effective_reference
        .as_ref()
        .and_then(|record| crate::json::get_str(record, "company_owner").map(str::to_owned));
    let local_owner = effective_reference
        .as_ref()
        .and_then(|record| crate::json::get_str(record, "local_owner").map(str::to_owned));
    let effective_criticality = effective_reference.as_ref().and_then(|record| {
        crate::json::get_str(record, "effective_dependence_class").map(str::to_owned)
    });
    let dominating_input = effective_reference
        .as_ref()
        .and_then(|record| crate::json::get_str(record, "dominating_input").map(str::to_owned));
    let cache_state_constructed = launcher.company_cache()?.is_some();
    // Trusted guidance is released only once no high-distortion Unknown
    // blocks the decision, and it cites the admitted answer it rests on
    // (question, answer and fact identities) rather than restating prose.
    let recommendation_fact = if !has_blocking_unknown {
        selected
            .iter()
            .find(|fact| is_authority_answer(fact))
            .or_else(|| context.iter().find(|fact| is_authority_answer(fact)))
    } else {
        None
    };
    let recommendation = recommendation_fact.map(|fact| fact.statement.clone());
    let recommendation_basis = recommendation_fact.map(|fact| {
        json!({
            "fact_id": fact.fact_id,
            "event_id": fact.event_id,
            "authority_id": fact.authority_id,
            "authority_scope": fact.authority_scope,
            "cites": fact.evidence_refs,
            "authority_snapshot_cursor": fact.authority_snapshot_cursor
        })
    });
    let safety_is_degraded = facts.iter().any(|fact| {
        crate::model::criticality_is_safety(
            fact.effective_dependence_class
                .as_deref()
                .unwrap_or(&fact.criticality),
        ) && fact.trust != "trusted"
            && fact
                .stale_reasons
                .iter()
                .any(|reason| reason == "CACHE_EXPIRED" || reason == "REVOCATION_STALE")
    });
    let advisory_is_degraded = facts.iter().any(|fact| {
        !crate::model::criticality_is_safety(
            fact.effective_dependence_class
                .as_deref()
                .unwrap_or(&fact.criticality),
        ) && fact.trust == "excluded"
    });
    // Architecture §6: an expired or revocation-stale safety dependency
    // withholds the projection; an open high-distortion Unknown does too.
    let projection_withheld = has_blocking_unknown || safety_is_degraded;
    let degraded_policy = if safety_is_degraded
        || open_unknowns
            .iter()
            .any(|unknown| unknown.loss_if_absent >= 7_500)
    {
        "block_dependent_decision"
    } else if !has_blocking_unknown && !advisory_is_degraded {
        "block_dependent_decision"
    } else {
        "reversible_sandbox_only_experiment"
    };
    let selected_value = |fact: &CurrentFact| {
        json!({
            "fact_id": fact.fact_id,
            "logical_key": fact.logical_key,
            "role": roles.name(fact),
            "store_kind": fact.store_kind,
            // The point of selecting a fact is to act on it, and how much weight
            // it carries is the first thing the caller needs. Without these the
            // consumer sees a flat list and cannot tell a ratified architecture
            // ruling from the majority pattern in a directory being retired --
            // which is the entire distinction this system exists to draw.
            "atom_kind": fact.atom_kind,
            "standing": fact.standing,
            "provenance": fact.provenance,
            "governs_paths": fact.governs_paths,
            "anchors": fact.anchors,
            "resident": resident_ids.contains(&fact.fact_id),
            "selection_reason": if resident_ids.contains(&fact.fact_id) { "working_set_resident" } else { "positive_conditional_marginal_value" }
        })
    };
    let result = json!({
        "decision": decision,
        "task": task,
        "as_of": as_of.as_of,
        "as_of_source": as_of.as_of_source,
        "ambient_clock_read": false,
        "candidates": candidate_values.into_iter().chain(unknowns.iter().map(unknown_value)).collect::<Vec<_>>(),
        "working_set": working_set,
        "resident_working_set": residents.iter().map(selected_value).collect::<Vec<_>>(),
        "working_set_unresolved": working_set_unresolved,
        "selected": selected.iter().map(selected_value).collect::<Vec<_>>(),
        "current_set": context.iter().map(|fact| fact.fact_id.clone()).collect::<Vec<_>>(),
        "selection_trace": selection_trace,
        "rejected_count": rejected_count,
        "tier_escalation": tier_escalation,
        "projection_bytes": projection_bytes,
        "resident_bytes": resident_bytes,
        "invariant_selected": invariant_selected,
        "stopping_reason": stopping_reason,
        "unknowns": unknowns.iter().map(unknown_value).collect::<Vec<_>>(),
        "voi_approximation": "additive deterministic basis-point approximation over conditional distortion, authority, complementarity, uncertainty, redundancy, retrieval, and staleness",
        "trusted_recommendation": recommendation,
        "trusted_recommendation_basis": recommendation_basis,
        "degraded_policy": degraded_policy,
        "cache_state_constructed": cache_state_constructed,
        "company_reference_resolved": selected_reference.is_some(),
        "reference_resolved": selected_reference.is_some(),
        "company_statement": selected_reference
            .as_ref()
            .and_then(|record| crate::json::get_str(record, "company_statement"))
            .or(company_reference.as_deref())
            .unwrap_or_default(),
        "effective_criticality": effective_criticality,
        "company_owner": company_owner,
        "local_owner": local_owner,
        "max_rule": effective_reference
            .as_ref()
            .and_then(|record| crate::json::get_str(record, "max_rule")),
        "dominating_input": dominating_input,
        "projection_state": if projection_withheld { "withheld" } else { "projected" },
        "question_id": question_id,
        "omitted_count": omitted_count
    });

    let query_record = json!({
        "requested": TIERS.iter().map(|(tier, _, _)| *tier).collect::<Vec<_>>(),
        "returned": candidates.iter().map(|fact| fact.fact_id.clone()).collect::<Vec<_>>(),
        "selected": selected.iter().map(|fact| fact.fact_id.clone()).collect::<Vec<_>>(),
        "selected_ids": selected.iter().map(|fact| fact.fact_id.clone()).collect::<Vec<_>>(),
        "working_set": working_set,
        "resident_at_dependent_edit": working_set,
        "resident_ids": residents.iter().map(|fact| fact.fact_id.clone()).collect::<Vec<_>>(),
        "declared_use": decision,
        "task": task,
        "stopping_reason": stopping_reason,
        "outcome": stopping_reason,
        "question_id": question_id,
        "task_outcome": "pending",
        "cost": TIERS.iter().map(|(_, _, cost)| *cost).sum::<i64>(),
        "marginal_gain": selection_trace
            .iter()
            .filter(|row| row.get("selected") == Some(&Value::Bool(true)))
            .filter_map(|row| row.get("marginal_value"))
            .filter_map(Value::as_i64)
            .sum::<i64>(),
        "selection_trace": selection_trace.clone(),
        "as_of": as_of.as_of
    });
    launcher
        .private_store()?
        .log_query(Some(decision), &query_record)?;

    if json {
        println!("{}", crate::json::canonical_text(&result));
    } else {
        println!("decision: {decision}");
        println!("selected_count: {}", selected.len());
        println!("omitted_count: {omitted_count}");
        println!("stopping_reason: {stopping_reason}");
    }
    Ok(())
}

fn question_unknown_id(fact: &CurrentFact) -> String {
    format!("unknown_{}", &fact.fact_id[5.min(fact.fact_id.len())..])
}

/// A `question` atom asserted by an authority is an open Unknown that
/// authority owns; the question text is the fact statement.
fn question_unknown(fact: &CurrentFact) -> UnknownOut {
    UnknownOut {
        unknown_id: question_unknown_id(fact),
        logical_key: fact.logical_key.clone(),
        scope: fact.authority_scope.clone(),
        decision_blocked: fact.distortion.trigger.clone(),
        owner_role: owner_role_for(&fact.authority_scope, &fact.store_kind).to_owned(),
        owner_identity: fact.authority_id.clone(),
        question: fact.statement.clone(),
        evidence: fact.evidence_refs.clone(),
        loss_if_absent: fact.distortion.loss_if_absent,
        status: "open".to_owned(),
        kind: "question".to_owned(),
    }
}

fn owner_role_for(scope: &str, store_kind: &str) -> &'static str {
    if scope.starts_with("architecture:") {
        "chief-architect"
    } else if store_kind == "company" || scope.starts_with("company:") {
        "company-steward"
    } else if scope.starts_with("environment:") {
        "deploy-owner"
    } else {
        "repository-maintainer"
    }
}

struct StoreView {
    view: CurrentView,
    events: Vec<FactEvent>,
    references: Vec<Value>,
}

/// The Company store's current view from the verified cache alone (no
/// network): what a host start may project as trusted Company context.
pub(crate) fn company_view(
    launcher: &Launcher,
    repo: &Path,
    as_of: &crate::time::AsOf,
) -> Result<CurrentView, ContractError> {
    load_view(launcher, repo, crate::StoreKind::Company, as_of).map(|store| store.view)
}

fn load_view(
    launcher: &Launcher,
    repo: &Path,
    store: crate::StoreKind,
    as_of: &crate::time::AsOf,
) -> Result<StoreView, ContractError> {
    let mut data = crate::corpus::load_store(launcher, repo, store)?;
    let mut references = Vec::new();
    if store == crate::StoreKind::Codebase {
        if let Ok(repository) = crate::codebase::Repository::discover(repo) {
            let repository_uuid = repository.uuid_hint().map(str::to_owned);
            data.events.retain(|admitted| {
                admitted
                    .event
                    .repository_id
                    .as_deref()
                    .map(|bound| repository_uuid.as_deref().is_some_and(|uuid| bound == uuid))
                    .unwrap_or(true)
            });
            let ingested_events: Vec<FactEvent> = data
                .events
                .iter()
                .map(|admitted| admitted.event.clone())
                .collect();
            let context = crate::repository::RepoContext::load(
                crate::launcher::Launcher::load()?,
                repo,
                true,
                Some(&as_of.as_of),
            )?;
            let (view, _counts, store_references) = context.current_view(&as_of.as_of, None)?;
            references = store_references;
            return Ok(StoreView {
                view,
                events: ingested_events,
                references,
            });
        }
    }

    let store_name_value = match store {
        crate::StoreKind::Company => "company",
        crate::StoreKind::Personal => "personal",
        crate::StoreKind::Codebase => "codebase",
    };
    let ingested_events: Vec<FactEvent> = data
        .events
        .iter()
        .map(|admitted| admitted.event.clone())
        .collect();
    let cache_freshness = launcher
        .company_cache()?
        .map(|(cache, _root)| cache.freshness(&as_of.as_of));
    let input = ReducerInput {
        store_kind: store_name_value.to_owned(),
        events: data.events,
        unknowns: data.unknowns,
        tombstones: data.tombstones,
        revocations: data.revocations,
        as_of: as_of.as_of.clone(),
        authority_cursor: data.authority_cursor,
        revocation_fresh: cache_freshness
            .as_ref()
            .map(|freshness| freshness.revocation_fresh)
            .unwrap_or(true),
        fact_valid_until: cache_freshness.and_then(|freshness| freshness.fact_valid_until),
        certificate_valid: data.certificate_valid,
        authority_owner_by_scope: data.authority_owner_by_scope,
        steward_authority_id: data.steward_authority_id,
    };
    Ok(StoreView {
        view: crate::reducer::reduce(&input),
        events: ingested_events,
        references,
    })
}

fn event_candidate_value(
    event: &FactEvent,
    conflict_event_ids: &BTreeSet<String>,
    as_of: &str,
) -> Value {
    let expired = event
        .effective_until
        .as_deref()
        .is_some_and(|until| until <= as_of);
    let invariant = event.distortion.loss_if_absent >= 7_000
        && matches!(event.atom_kind.as_str(), "constraint" | "decision");
    let (role, reason) = if conflict_event_ids.contains(&event.event_id) {
        (
            "conflict",
            "event participates in a logical-key conflict".to_owned(),
        )
    } else if invariant {
        (
            "high_distortion_compatibility_invariant",
            "high-loss durable invariant constrains compatible implementations".to_owned(),
        )
    } else if expired || event.disposition == "expired" {
        ("stale", format!("fact is expired as of {as_of}"))
    } else {
        (
            "stale",
            "event was superseded or otherwise not represented by the current view".to_owned(),
        )
    };
    json!({
        "logical_key": event.logical_key,
        "fact_id": event.fact_id,
        "atom_kind": event.atom_kind,
        "standing": crate::model::effective_standing(&event.standing, &event.provenance),
        "claimed_standing": event.standing,
        "provenance": event.provenance,
        "governs_paths": event.governs_paths,
        "anchors": event.anchors,
        "statement": event.statement,
        "scope": event.scope,
        "authority_scope": event.authority_scope,
        "distortion": event.distortion,
        "validity": {
            "status": if expired { "expired" } else { "admitted" },
            "effective_from": event.effective_from,
            "effective_until": event.effective_until
        },
        "role": role,
        "roles": if role == "stale" {
            vec!["stale_fact".to_owned()]
        } else if invariant && role != "conflict" {
            vec![role.to_owned(), "current".to_owned()]
        } else {
            vec![role.to_owned()]
        },
        "derived_role": role,
        "reason": reason,
        "authority_id": event.authority_id,
        "owner_role": if event.store_kind == "company" { "company-steward".to_owned() } else { "repository-maintainer".to_owned() },
        "owner_identity": event.authority_id
    })
}

/// Every fact's derived role, computed once: the paraphrase test needs the
/// set of statements that recur under distinct logical keys, not a scan of
/// every other fact per call.
struct Roles {
    by_id: BTreeMap<String, (&'static str, String)>,
}

impl Roles {
    fn derive(facts: &[CurrentFact]) -> Self {
        let mut keys_by_statement: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
        for fact in facts {
            keys_by_statement
                .entry(normalized_statement(&fact.statement))
                .or_default()
                .insert(fact.logical_key.as_str());
        }
        let duplicated: BTreeSet<String> = keys_by_statement
            .into_iter()
            .filter(|(_, keys)| keys.len() > 1)
            .map(|(statement, _)| statement)
            .collect();
        let by_id = facts
            .iter()
            .map(|fact| {
                let restated = duplicated.contains(&normalized_statement(&fact.statement));
                (fact.fact_id.clone(), candidate_role(fact, restated))
            })
            .collect();
        Self { by_id }
    }

    fn of(&self, fact: &CurrentFact) -> (&'static str, String) {
        self.by_id
            .get(&fact.fact_id)
            .cloned()
            .unwrap_or_else(|| candidate_role(fact, false))
    }

    fn name(&self, fact: &CurrentFact) -> &'static str {
        self.of(fact).0
    }
}

fn candidate_role(fact: &CurrentFact, restated_elsewhere: bool) -> (&'static str, String) {
    if !fact.stale_reasons.is_empty() {
        return ("stale_fact", fact.stale_reasons.join(","));
    }
    if fact.disposition == "conflict" {
        return ("conflict", "fact disposition is conflict".to_owned());
    }
    if fact.disposition == "expired" || fact.disposition == "disputed" {
        return (
            "stale_fact",
            format!("fact disposition is {}", fact.disposition),
        );
    }
    if fact.distortion.loss_if_absent >= 7_000
        && matches!(fact.atom_kind.as_str(), "constraint" | "decision")
    {
        return (
            "high_distortion_compatibility_invariant",
            "high-loss durable invariant constrains compatible implementations".to_owned(),
        );
    }
    match fact.atom_kind.as_str() {
        "test" | "runtime_trace" | "test_runtime_evidence" => {
            return (
                "test",
                "runtime or test evidence validates the decision".to_owned(),
            );
        }
        "rationale" => {
            return (
                "rationale",
                "rationale explains the compatibility invariant".to_owned(),
            );
        }
        _ => {}
    }
    let paraphrase = !fact.redundancy_with.is_empty() || restated_elsewhere;
    if paraphrase {
        return (
            "high_scoring_paraphrase",
            "edge or semantic duplicate restates an already scoreable fact".to_owned(),
        );
    }
    ("current", "selectable current trusted fact".to_owned())
}

fn candidate_priority(role: &str) -> i64 {
    match role {
        "high_distortion_compatibility_invariant" => 4,
        "test" | "rationale" => 3,
        "high_scoring_paraphrase" => 2,
        "high_distortion_unknown" => 1,
        _ => 0,
    }
}

fn normalized_statement(statement: &str) -> String {
    statement
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn candidate_value(fact: &CurrentFact, roles: &Roles) -> Value {
    let (derived_role, reason) = roles.of(fact);
    let primary_role = if derived_role == "high_distortion_compatibility_invariant"
        || derived_role == "high_scoring_paraphrase"
        || derived_role == "test"
        || derived_role == "rationale"
    {
        "current"
    } else {
        derived_role
    };
    let mut roles = vec![derived_role];
    if primary_role != derived_role {
        roles.push(primary_role);
    }
    json!({
        "logical_key": fact.logical_key,
        "fact_id": fact.fact_id,
        "atom_kind": fact.atom_kind,
        "standing": fact.standing,
        "claimed_standing": fact.standing,
        "provenance": fact.provenance,
        "governs_paths": fact.governs_paths,
        "anchors": fact.anchors,
        "statement": fact.statement,
        "scope": fact.scope,
        "authority_scope": fact.authority_scope,
        "distortion": fact.distortion,
        "validity": {
            "status": fact.status,
            "effective_from": fact.effective_from,
            "effective_until": fact.effective_until
        },
        "role": primary_role,
        "roles": roles,
        "derived_role": derived_role,
        "reason": reason,
        "trust": fact.trust,
        "stale_reasons": fact.stale_reasons,
        "store_kind": fact.store_kind,
        "authority_id": fact.authority_id
    })
}

fn unknown_value(unknown: &UnknownOut) -> Value {
    let role = if unknown.loss_if_absent >= 7_000 {
        "high_distortion_unknown"
    } else {
        "unknown"
    };
    json!({
        "role": role,
        "roles": [role],
        "derived_role": role,
        "owner_role": unknown.owner_role,
        "owner_identity": unknown.owner_identity,
        "logical_key": unknown.logical_key,
        "unknown_id": unknown.unknown_id,
        "status": unknown.status,
        "kind": unknown.kind,
        "loss_if_absent": unknown.loss_if_absent,
        "decision_blocked": unknown.decision_blocked,
        "reason": if unknown.kind == "explicit" { format!("{}: {}", unknown.status, unknown.question) } else { format!("{}: {}", unknown.status, unknown.kind) }
    })
}

fn unknown_outputs(
    facts: &[CurrentFact],
    view_unknowns: &[crate::reducer::DerivedUnknown],
    question_unknowns: &[UnknownOut],
) -> Vec<UnknownOut> {
    // Keyed by Unknown id: one logical key may carry several owned Unknowns
    // (the Company fact's own expiry and the repository reference to it).
    let mut by_key: BTreeMap<String, UnknownOut> = BTreeMap::new();
    for unknown in question_unknowns {
        by_key.insert(unknown.unknown_id.clone(), unknown.clone());
    }
    for unknown in view_unknowns {
        if unknown.status != "open" && unknown.status != "asked" {
            continue;
        }
        by_key.insert(
            unknown.unknown_id.clone(),
            UnknownOut {
                unknown_id: unknown.unknown_id.clone(),
                logical_key: unknown.logical_key.clone(),
                scope: unknown.scope.clone(),
                decision_blocked: unknown.decision_blocked.clone(),
                owner_role: unknown.owner_role.clone(),
                owner_identity: unknown.owner_identity.clone(),
                question: unknown.question.clone(),
                evidence: unknown.discriminating_evidence.clone(),
                loss_if_absent: unknown.loss_if_absent,
                status: unknown.status.clone(),
                kind: unknown.kind.clone(),
            },
        );
    }
    let represented_keys: BTreeSet<String> = by_key
        .values()
        .map(|unknown| unknown.logical_key.clone())
        .collect();
    for fact in facts {
        let ineligible = fact.status != "current"
            || fact.trust != "trusted"
            || !fact.stale_reasons.is_empty()
            || matches!(
                fact.disposition.as_str(),
                "disputed" | "expired" | "conflict"
            );
        if ineligible && !represented_keys.contains(&fact.logical_key) {
            let owner_role = if fact.store_kind == "company" {
                "company-steward"
            } else {
                "repository-maintainer"
            };
            let unknown_id = format!("unknown_{}", &fact.fact_id[5.min(fact.fact_id.len())..]);
            if by_key.contains_key(&unknown_id) {
                continue;
            }
            by_key.insert(
                unknown_id.clone(),
                UnknownOut {
                    unknown_id,
                    logical_key: fact.logical_key.clone(),
                    scope: fact.scope.clone(),
                    decision_blocked: fact.distortion.trigger.clone(),
                    owner_role: owner_role.to_owned(),
                    owner_identity: fact.authority_id.clone(),
                    question: format!(
                        "Fact {} is not selectable; refresh or supersede its evidence.",
                        fact.fact_id
                    ),
                    evidence: fact.evidence_refs.clone(),
                    loss_if_absent: fact.distortion.loss_if_absent,
                    status: "open".to_owned(),
                    kind: if fact.stale_reasons.is_empty() {
                        fact.disposition.clone()
                    } else {
                        "stale".to_owned()
                    },
                },
            );
        }
    }
    let mut values: Vec<_> = by_key.into_values().collect();
    values.sort_by(|left, right| {
        right
            .loss_if_absent
            .cmp(&left.loss_if_absent)
            .then_with(|| left.unknown_id.cmp(&right.unknown_id))
    });
    values
}

/// A resident working-set fact re-added to its own set: every gain is already
/// realised, nothing is retrieved, and nothing new is displaced.
fn resident_evaluation() -> Evaluation {
    Evaluation {
        marginal_value: 0,
        newly_covered_distortion: 0,
        authority_and_validity_gain: 0,
        complementarity_gain: 0,
        uncertainty_reduction: 0,
        redundancy: 0,
        retrieval_and_residency_cost: 0,
        stale_or_conflict_risk: 0,
        redundancy_basis: "resident_in_working_set".to_owned(),
        complementarity_basis: "none".to_owned(),
    }
}

/// Score one candidate against the current set `S` (residents plus the
/// facts selected so far) for the declared task and decision.
fn evaluate(
    fact: &CurrentFact,
    current_set: &[CurrentFact],
    task: &str,
    decision: &str,
) -> Evaluation {
    let decision_terms = terms(decision);
    let task_terms = terms(task);
    let statement_terms = terms(&fact.statement);
    let decision_overlap = statement_terms.intersection(&decision_terms).count().min(4) as i64;
    let task_overlap = statement_terms.intersection(&task_terms).count().min(4) as i64;
    let relevance =
        3_000 + decision_overlap.saturating_mul(1_000) + task_overlap.saturating_mul(500);
    // Distortion already covered by an equivalent member of S is not newly
    // covered: a paraphrase of a resident fact covers nothing new.
    let covered_by_set = current_set.iter().any(|existing| {
        existing.logical_key == fact.logical_key
            || normalized_statement(&existing.statement) == normalized_statement(&fact.statement)
    });
    let newly_covered = if covered_by_set {
        0
    } else if covers_own_trigger(fact) {
        i64::from(fact.distortion.loss_if_absent)
    } else {
        i64::from(fact.distortion.loss_if_absent)
            .saturating_mul(relevance)
            .saturating_div(10_000)
    };
    let authority_gain = {
        let base =
            if fact.authority_scope.starts_with("architecture") || fact.store_kind == "company" {
                800
            } else {
                300
            };
        base + (i64::from(fact.confidence) / 20).min(500)
    };
    let (complementarity, complementarity_basis) = complementarity(fact, current_set);
    let uncertainty = (i64::try_from(fact.independent_support_count)
        .unwrap_or(i64::MAX)
        .saturating_mul(250))
    .min(1_000)
        + if fact.company_refs.is_empty() { 0 } else { 250 };
    let (redundancy, redundancy_basis) = redundancy(fact, current_set);
    let cost = 250;
    let stale = 0;
    Evaluation {
        marginal_value: newly_covered + authority_gain + complementarity + uncertainty
            - redundancy
            - cost
            - stale,
        newly_covered_distortion: newly_covered,
        authority_and_validity_gain: authority_gain,
        complementarity_gain: complementarity,
        uncertainty_reduction: uncertainty,
        redundancy,
        retrieval_and_residency_cost: cost,
        stale_or_conflict_risk: stale,
        redundancy_basis,
        complementarity_basis,
    }
}

fn covers_own_trigger(fact: &CurrentFact) -> bool {
    let trigger = terms(&fact.distortion.trigger);
    if trigger.is_empty() {
        return false;
    }
    let statement = terms(&fact.statement);
    trigger.iter().all(|term| statement.contains(term))
}

/// Evidence class of an atom: test/runtime/observation evidence versus the
/// rationale, constraint or decision it can evidence. Complementarity needs
/// one of each.
fn evidence_class(atom_kind: &str) -> Option<&'static str> {
    match atom_kind {
        "observation" | "test" | "runtime_trace" | "test_runtime_evidence" => Some("evidence"),
        "rationale" | "constraint" | "decision" => Some("explanation"),
        _ => None,
    }
}

/// The subject a hierarchical logical key names: its last path segment.
fn key_subject(logical_key: &str) -> Option<&str> {
    let (_, subject) = logical_key.rsplit_once('/')?;
    if subject.is_empty() {
        None
    } else {
        Some(subject)
    }
}

const STOPWORDS: [&str; 44] = [
    "this", "that", "with", "from", "than", "then", "they", "them", "have", "been", "were", "will",
    "must", "into", "when", "which", "what", "where", "while", "also", "only", "over", "under",
    "about", "because", "cannot", "remain", "should", "would", "could", "their", "there", "these",
    "those", "here", "such", "each", "other", "some", "more", "most", "very", "after", "before",
];

fn distinctive_terms(statement: &str) -> BTreeSet<String> {
    terms(statement)
        .into_iter()
        .filter(|term| term.len() >= 4 && !STOPWORDS.contains(&term.as_str()))
        .collect()
}

/// Complementarity: a test/runtime/observation and the rationale, constraint
/// or decision it evidences are jointly useful when they address one subject.
/// The subject link is an explicit `complements` edge, a shared logical-key
/// subject, or shared distinctive vocabulary; the trace names which.
fn complementarity(fact: &CurrentFact, current_set: &[CurrentFact]) -> (i64, String) {
    const GAIN: i64 = 2_500;
    let fact_terms = distinctive_terms(&fact.statement);
    for existing in current_set {
        if fact.complements.contains(&existing.fact_id)
            || existing.complements.contains(&fact.fact_id)
        {
            return (GAIN, format!("explicit_edge:{}", existing.fact_id));
        }
        let (Some(left), Some(right)) = (
            evidence_class(&fact.atom_kind),
            evidence_class(&existing.atom_kind),
        ) else {
            continue;
        };
        if left == right {
            continue;
        }
        if let (Some(subject), Some(other)) = (
            key_subject(&fact.logical_key),
            key_subject(&existing.logical_key),
        ) {
            if subject == other && fact.logical_key != existing.logical_key {
                return (GAIN, format!("shared_subject_key:{subject}"));
            }
        }
        let existing_terms = distinctive_terms(&existing.statement);
        let shared: Vec<&str> = fact_terms
            .intersection(&existing_terms)
            .map(String::as_str)
            .collect();
        if shared.len() >= 2 {
            return (GAIN, format!("shared_subject_terms:{}", shared.join(",")));
        }
    }
    (0, "none".to_owned())
}

/// Redundancy against the current set: explicit edges, shared provenance,
/// then lexical similarity. Returns the positive penalty and its basis.
fn redundancy(fact: &CurrentFact, current_set: &[CurrentFact]) -> (i64, String) {
    let protected_invariant = fact.distortion.loss_if_absent >= 7_000
        && matches!(fact.atom_kind.as_str(), "constraint" | "decision");
    for existing in current_set {
        let explicit = fact.redundancy_with.contains(&existing.fact_id)
            || existing.redundancy_with.contains(&fact.fact_id);
        if explicit {
            return if protected_invariant {
                (
                    2_000,
                    format!("protected_invariant_explicit_edge:{}", existing.fact_id),
                )
            } else {
                (8_000, format!("explicit_edge:{}", existing.fact_id))
            };
        }
        let fact_support: BTreeSet<&str> = fact
            .support_event_ids
            .iter()
            .chain(fact.evidence_refs.iter())
            .map(String::as_str)
            .collect();
        let existing_support: BTreeSet<&str> = existing
            .support_event_ids
            .iter()
            .chain(existing.evidence_refs.iter())
            .map(String::as_str)
            .collect();
        if !fact_support
            .intersection(&existing_support)
            .collect::<BTreeSet<_>>()
            .is_empty()
        {
            return if protected_invariant {
                (
                    1_000,
                    format!("protected_invariant_shared_provenance:{}", existing.fact_id),
                )
            } else {
                (3_000, format!("shared_provenance:{}", existing.fact_id))
            };
        }
    }
    let fact_terms = terms(&fact.statement);
    let mut best = (0i64, "none".to_owned());
    for existing in current_set {
        let existing_terms = terms(&existing.statement);
        let intersection = fact_terms.intersection(&existing_terms).count() as i64;
        let total = fact_terms.len() as i64 + existing_terms.len() as i64;
        if total == 0 {
            continue;
        }
        let similarity = intersection
            .saturating_mul(2)
            .saturating_mul(10_000)
            .saturating_div(total);
        if similarity >= 6_000 {
            // A near-duplicate may reduce value, but a distinct high-loss
            // invariant must remain recoverable. Complementary test/rationale
            // evidence is likewise capped so its gain is reported
            // separately instead of being erased by lexical redundancy.
            let complementary = evidence_class(&fact.atom_kind).is_some()
                && evidence_class(&existing.atom_kind).is_some()
                && evidence_class(&fact.atom_kind) != evidence_class(&existing.atom_kind);
            let ceiling = if protected_invariant || complementary {
                2_000
            } else {
                10_000
            };
            let penalty = similarity.min(ceiling);
            if penalty > best.0 {
                best = (
                    penalty,
                    format!("lexical_similarity:{similarity}:{}", existing.fact_id),
                );
            }
        }
    }
    best
}

fn is_authority_answer(fact: &CurrentFact) -> bool {
    fact.store_kind == "company"
        && fact.atom_kind == "decision"
        && fact
            .evidence_refs
            .iter()
            .any(|reference| reference.starts_with("answer_"))
}

fn company_reference(selected: &[CurrentFact], all_facts: &[CurrentFact]) -> Option<String> {
    let company_facts: BTreeMap<&str, &CurrentFact> = all_facts
        .iter()
        .filter(|fact| fact.store_kind == "company")
        .map(|fact| (fact.fact_id.as_str(), fact))
        .collect();
    for fact in selected {
        for reference in &fact.company_refs {
            if let Some(company_fact) = company_facts.get(reference.fact_id.as_str()) {
                return Some(company_fact.statement.clone());
            }
        }
    }
    None
}

fn terms(value: &str) -> BTreeSet<String> {
    value
        .to_lowercase()
        .split(|character: char| !character.is_alphanumeric())
        .filter(|part| part.len() > 2)
        .map(str::to_owned)
        .collect()
}
