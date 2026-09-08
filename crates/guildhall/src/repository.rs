//! Repository trust context and the repository-facing commands: `repo
//! issue`, `repo init`, `repo publish-manifest`, `status`, `doctor`, `fsck`.
//! Trust for `.kin/` events comes only from the out-of-worktree certificate
//! (Company cache) and the signed authority registry; worktree bytes never
//! mint trust (architecture §2).

use crate::codebase::{ParsedEvent, Repository, StoredFile, parse_stored};
use crate::company::cache::Freshness;
use crate::crypto::PublicKey;
use crate::error::ContractError;
use crate::launcher::Launcher;
use crate::model::{CurrentFact, FactEvent, UnknownEvent};
use crate::reducer::{AdmittedEvent, ReducerInput, Revocation, Verification};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const PRIVACY_CLAIM: &str = "Zero observed unauthorized durable disclosure outside the authorized processor boundary under Acceptance Threat Model guildhall-atm/1, identified by its exact SHA-256 digest, across the frozen execution census.";

/// Everything needed to decide whether a `.kin/` event is trusted.
#[derive(Debug, Clone)]
pub struct TrustContext {
    pub repository_uuid: Option<String>,
    pub certificate: Option<Value>,
    pub certificate_digest: Option<String>,
    pub certificate_valid: bool,
    pub certificate_reason: String,
    pub root: Option<PublicKey>,
    pub registry: Vec<Value>,
    pub revocations: Vec<Revocation>,
    pub relaxations: Vec<Value>,
    pub company_facts: Vec<Value>,
    pub fact_versions: BTreeMap<String, Vec<Value>>,
    pub authority_cursor: String,
    pub freshness: Option<Freshness>,
    pub company_reachable: Option<bool>,
    pub company_query_attempted: bool,
    pub company_connect_seconds: Option<f64>,
    pub unknowns: Vec<Value>,
    pub foreign_certificate_paths: Vec<String>,
    pub pin_state: String,
}

impl TrustContext {
    pub fn steward_keys(&self) -> BTreeSet<String> {
        let mut keys = BTreeSet::new();
        if let Some(root) = &self.root {
            keys.insert(root.to_hex());
        }
        for entry in &self.registry {
            if crate::json::get_str(entry, "scope") == Some("company:root") {
                if let Some(key) = crate::json::get_str(entry, "public_key") {
                    keys.insert(key.to_owned());
                }
            }
        }
        keys
    }

    pub fn is_revoked(&self, key: &str) -> bool {
        self.revocations.iter().any(|revocation| revocation.revoked_key == key)
    }

    pub fn entries_for_key(&self, key: &str) -> Vec<&Value> {
        self.registry
            .iter()
            .filter(|entry| crate::json::get_str(entry, "public_key") == Some(key) && crate::json::get_str(entry, "status").unwrap_or("active") == "active")
            .collect()
    }

    pub fn is_maintainer(&self, key: &str) -> bool {
        let Some(uuid) = &self.repository_uuid else { return false };
        self.entries_for_key(key).iter().any(|entry| {
            let scope = crate::json::get_str(entry, "scope").unwrap_or_default();
            scope == format!("codebase:{uuid}") || scope == format!("repository:{uuid}")
        })
    }

    pub fn maintainer_entries(&self) -> Vec<Value> {
        let Some(uuid) = &self.repository_uuid else { return Vec::new() };
        self.registry
            .iter()
            .filter(|entry| {
                let scope = crate::json::get_str(entry, "scope").unwrap_or_default();
                scope == format!("codebase:{uuid}") || scope == format!("repository:{uuid}")
            })
            .cloned()
            .collect()
    }

    /// Verification of one codebase fact event.
    pub fn verify(&self, event: &FactEvent) -> Verification {
        if event.store_kind != "codebase" {
            return Verification::Foreign;
        }
        match (&self.repository_uuid, event.repository_id.as_deref()) {
            (Some(uuid), Some(bound)) if uuid == bound => {}
            _ => return Verification::Foreign,
        }
        if !self.certificate_valid {
            return Verification::Unverified;
        }
        if event.verify_signature().is_none() {
            return Verification::SignatureInvalid;
        }
        if self.is_revoked(&event.signer) {
            return Verification::Revoked;
        }
        if self.steward_keys().contains(&event.signer) || self.is_maintainer(&event.signer) {
            return Verification::Verified;
        }
        let in_scope = self
            .entries_for_key(&event.signer)
            .iter()
            .any(|entry| crate::json::get_str(entry, "scope") == Some(event.authority_scope.as_str()));
        if in_scope {
            Verification::Verified
        } else if self.entries_for_key(&event.signer).is_empty() {
            Verification::Unverified
        } else {
            Verification::WrongScope
        }
    }

    pub fn environment_registered(&self, environment_id: &str) -> bool {
        let scope = format!("environment:{environment_id}");
        self.registry
            .iter()
            .any(|entry| crate::json::get_str(entry, "scope") == Some(scope.as_str()) && crate::json::get_str(entry, "status").unwrap_or("active") == "active")
    }

    pub fn company_fact(&self, fact_id: &str) -> Option<&Value> {
        self.company_facts.iter().find(|fact| crate::json::get_str(fact, "fact_id") == Some(fact_id))
    }
}

/// A stored `.kin/events` file after parsing and verification.
#[derive(Debug, Clone)]
pub struct LoadedEvent {
    pub file: StoredFile,
    pub parsed: ParsedEvent,
    pub verification: Option<Verification>,
    pub origin_trust: String,
    pub reachable: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct LoadCounts {
    pub total_files: usize,
    pub fact_events: usize,
    pub unknown_events: usize,
    pub verified: usize,
    pub unverified: usize,
    pub foreign: usize,
    pub signature_invalid: usize,
    pub revoked: usize,
    pub wrong_scope: usize,
    pub malformed: usize,
    pub path_alias: usize,
    pub oversized: usize,
    pub foreign_paths: Vec<String>,
}

impl LoadCounts {
    pub fn to_value(&self) -> Value {
        json!({
            "total_files": self.total_files,
            "fact_events": self.fact_events,
            "unknown_events": self.unknown_events,
            "verified": self.verified,
            "unverified": self.unverified,
            "foreign": self.foreign,
            "signature_invalid": self.signature_invalid,
            "revoked": self.revoked,
            "wrong_scope": self.wrong_scope,
            "malformed": self.malformed,
            "path_alias": self.path_alias,
            "oversized": self.oversized,
            "foreign_paths": self.foreign_paths
        })
    }
}

pub struct RepoContext {
    pub launcher: Launcher,
    pub repo: Repository,
    pub trust: TrustContext,
}

impl RepoContext {
    /// Build the context: discover the repository, resolve the certificate
    /// from the out-of-worktree cache, refresh Company state within the
    /// connection budget (when `online`), and load the registry.
    pub fn load(launcher: Launcher, repo_path: &Path, online: bool) -> Result<Self, ContractError> {
        let repo = Repository::discover(repo_path)?;
        let trust = build_trust(&launcher, &repo, online)?;
        Ok(Self { launcher, repo, trust })
    }

    /// Load and verify every stored event.
    pub fn load_events(&self) -> Result<(Vec<LoadedEvent>, LoadCounts), ContractError> {
        let mut counts = LoadCounts::default();
        let mut loaded = Vec::new();
        let head = self.repo.revision().unwrap_or_default();
        let head_reachable = if head.is_empty() { None } else { Some(self.repo.is_reachable_from_default(&head)) };
        let origin = if self.repo.config.is_some() {
            let default = self.repo.default_branch();
            let branch = self.repo.branch().unwrap_or_default();
            if head_reachable == Some(true) || branch == default { "merged-default".to_owned() } else { "unreviewed-branch".to_owned() }
        } else {
            "merged-default".to_owned()
        };
        for file in self.repo.stored_events()? {
            counts.total_files += 1;
            if file.path_alias {
                counts.path_alias += 1;
                counts.foreign_paths.push(format!(".kin/events/{}", file.relative.to_string_lossy()));
                continue;
            }
            if file.bytes.len() > crate::model::MAX_EVENT_BYTES {
                counts.oversized += 1;
                counts.malformed += 1;
                continue;
            }
            let parsed = parse_stored(&file.bytes);
            let verification = match &parsed {
                ParsedEvent::Fact(event) => {
                    counts.fact_events += 1;
                    let verification = self.trust.verify(event);
                    match verification {
                        Verification::Verified => counts.verified += 1,
                        Verification::Unverified => counts.unverified += 1,
                        Verification::Foreign => counts.foreign += 1,
                        Verification::SignatureInvalid => counts.signature_invalid += 1,
                        Verification::Revoked => counts.revoked += 1,
                        Verification::WrongScope => counts.wrong_scope += 1,
                    }
                    Some(verification)
                }
                ParsedEvent::Unknown(unknown) => {
                    counts.unknown_events += 1;
                    let ok = unknown.verify_signature().is_some() && self.trust.certificate_valid;
                    Some(if ok { Verification::Verified } else { Verification::Unverified })
                }
                ParsedEvent::Tombstone(_) => Some(Verification::Verified),
                ParsedEvent::Malformed(_) => {
                    counts.malformed += 1;
                    None
                }
            };
            loaded.push(LoadedEvent {
                file,
                parsed,
                verification,
                origin_trust: origin.clone(),
                reachable: head_reachable,
            });
        }
        // Non-reserved artefacts under .kin/ are foreign paths (C24).
        for entry in std::fs::read_dir(&self.repo.kin).into_iter().flatten().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !["config", "events", "manifests", "local"].contains(&name.as_str()) {
                counts.foreign_paths.push(format!(".kin/{name}"));
            }
        }
        counts.foreign_paths.sort();
        counts.foreign_paths.dedup();
        Ok((loaded, counts))
    }

    /// Reduce the repository's admitted events into its current view,
    /// resolving Company references (P-8) against the cached Company view.
    pub fn current_view(&self, as_of: &str, cursor_override: Option<&str>) -> Result<(crate::reducer::CurrentView, LoadCounts, Vec<Value>), ContractError> {
        let (loaded, counts) = self.load_events()?;
        let mut admitted = Vec::new();
        let mut unknowns = Vec::new();
        let mut tombstones = Vec::new();
        let mut dependence_events: Vec<FactEvent> = Vec::new();
        for (index, item) in loaded.iter().enumerate() {
            match &item.parsed {
                ParsedEvent::Fact(event) => {
                    let verification = item.verification.clone().unwrap_or(Verification::Unverified);
                    if let Some(action) = crate::model::action_of(event) {
                        if matches!(action, "misextraction" | "never_true" | "support_withdrawn") {
                            let authorized = match action {
                                "misextraction" => verification == Verification::Verified || self.trust.entries_for_key(&event.signer).iter().any(|entry| crate::json::get_str(entry, "scope").is_some_and(|scope| scope.starts_with("approver:"))) || event.verify_signature().is_some() && event.authority_scope.starts_with("approver:"),
                                _ => verification == Verification::Verified,
                            };
                            for target in event.parents.iter().chain(event.supersedes.iter()) {
                                tombstones.push(crate::reducer::Tombstone {
                                    kind: action.to_owned(),
                                    target_event_id: target.clone(),
                                    signer_authorized: authorized,
                                    reason_code: event.statement.clone(),
                                    tombstone_id: event.event_id.clone(),
                                });
                            }
                            continue;
                        }
                    }
                    if event.atom_kind == "dependence" {
                        dependence_events.push(event.clone());
                    }
                    let environment_registered = event
                        .authority_scope
                        .strip_prefix("environment:")
                        .map(|id| self.trust.environment_registered(id));
                    admitted.push(AdmittedEvent {
                        event: event.clone(),
                        verification: if environment_registered == Some(false) { Verification::WrongScope } else { verification },
                        store_cursor: format!("{index:09}"),
                        origin_trust: Some(item.origin_trust.clone()),
                        reachable: item.reachable,
                        source_identity: Some(event.signer.clone()),
                        environment_registered,
                    });
                }
                ParsedEvent::Unknown(unknown) => unknowns.push(unknown.clone()),
                _ => {}
            }
        }
        let cursor = cursor_override.map(str::to_owned).unwrap_or_else(|| self.trust.authority_cursor.clone());
        let input = ReducerInput {
            store_kind: "codebase".to_owned(),
            events: admitted,
            unknowns,
            tombstones,
            revocations: self.trust.revocations.clone(),
            as_of: as_of.to_owned(),
            authority_cursor: cursor,
            revocation_fresh: true,
            fact_valid_until: None,
            certificate_valid: self.trust.certificate_valid,
        };
        let mut view = crate::reducer::reduce(&input);
        let references = self.resolve_company_references(&mut view, &dependence_events, as_of);
        Ok((view, counts, references))
    }

    /// P-8: resolve each Company reference through the cached authorized
    /// Company view; apply the max rule between Company criticality and the
    /// maintainer-owned local dependence class; honor steward relaxations.
    fn resolve_company_references(&self, view: &mut crate::reducer::CurrentView, dependence_events: &[FactEvent], as_of: &str) -> Vec<Value> {
        let mut results = Vec::new();
        let repository_uuid = self.trust.repository_uuid.clone().unwrap_or_default();
        let freshness = self.trust.freshness.as_ref();
        for fact in view.facts.iter_mut() {
            if fact.company_refs.is_empty() {
                continue;
            }
            let local = dependence_events
                .iter()
                .filter(|event| event.parents.contains(&fact.event_id) || event.parents.contains(&fact.fact_id))
                .max_by_key(|event| event.asserted_at.clone());
            let local_class = local.map(|event| {
                if event.statement.contains("safety") { "safety_critical".to_owned() } else { "advisory".to_owned() }
            });
            let local_owner = local.map(|event| event.authority_id.clone());
            for reference in &fact.company_refs {
                let mut record = json!({
                    "fact_id": fact.fact_id,
                    "company_fact_id": reference.fact_id,
                    "relation": reference.relation,
                    "company_criticality": reference.company_criticality,
                    "company_owner": reference.authority,
                    "local_dependence_class": local_class,
                    "local_owner": local_owner,
                    "digest_alg_version": reference.digest_alg_version
                });
                if reference.digest_alg_version != crate::model::DIGEST_ALG_VERSION {
                    record["resolution"] = Value::String("DIGEST_ALGORITHM_UNSUPPORTED".to_owned());
                    record["digest_attribution"] = json!({"owner_role": "client", "reason": "unknown digest algorithm version means client upgrade/degraded mode"});
                    fact.trust = "withheld".to_owned();
                    fact.stale_reasons.push("DIGEST_ALGORITHM_UNSUPPORTED".to_owned());
                    view.unknowns.push(client_unknown(&fact.logical_key, &reference.fact_id, "client", "DIGEST_ALGORITHM_UNSUPPORTED: upgrade the client adapter; the steward changed nothing"));
                    results.push(record);
                    continue;
                }
                let company_fact = self.trust.company_fact(&reference.fact_id).cloned();
                let versions = self.trust.fact_versions.get(&reference.fact_id).cloned().unwrap_or_default();
                let live_digest = company_fact.as_ref().and_then(|value| crate::json::get_str(value, "statement").map(crate::model::semantic_digest));
                let company_statement = company_fact.as_ref().and_then(|value| crate::json::get_str(value, "statement").map(str::to_owned));
                let effective_company_class = self.effective_company_class(&repository_uuid, reference, as_of);
                let stricter = if crate::model::criticality_is_safety(&effective_company_class) || local_class.as_deref().is_some_and(crate::model::criticality_is_safety) {
                    "safety_critical"
                } else {
                    "advisory"
                };
                let dominating = if crate::model::criticality_is_safety(&effective_company_class) && !local_class.as_deref().is_some_and(crate::model::criticality_is_safety) {
                    "company"
                } else if local_class.as_deref().is_some_and(crate::model::criticality_is_safety) && !crate::model::criticality_is_safety(&effective_company_class) {
                    "local"
                } else {
                    "equal"
                };
                record["effective_company_class"] = Value::String(effective_company_class.clone());
                record["effective_dependence_class"] = Value::String(stricter.to_owned());
                record["dominating_input"] = Value::String(dominating.to_owned());
                record["max_rule"] = Value::String("stricter of Company criticality (as relaxed for this repository) and maintainer-owned local dependence".to_owned());
                fact.effective_dependence_class = Some(stricter.to_owned());
                if local.is_none() {
                    view.unknowns.push(client_unknown(&fact.logical_key, &reference.fact_id, "repository-maintainer", "no maintainer-owned local dependence class records what losing this Company reference costs this repository"));
                }
                match (company_fact.as_ref(), live_digest.as_deref()) {
                    (None, _) => {
                        if self.trust.company_reachable == Some(false) || self.trust.company_facts.is_empty() {
                            record["resolution"] = Value::String("company-unavailable".to_owned());
                            record["digest_attribution"] = json!({"owner_role": "none", "reason": "Company unavailable; withheld without accusation"});
                            fact.trust = "withheld".to_owned();
                            fact.stale_reasons.push("COMPANY_UNREACHABLE".to_owned());
                        } else {
                            record["resolution"] = Value::String("company-fact-missing".to_owned());
                            record["digest_attribution"] = json!({"owner_role": "company-steward", "reason": "referenced Company fact is not in the current authorized view (superseded or revoked)"});
                            fact.trust = "withheld".to_owned();
                            fact.stale_reasons.push("company-reference-unresolved".to_owned());
                            view.unknowns.push(client_unknown(&fact.logical_key, &reference.fact_id, "company-steward", "the referenced Company fact is no longer in the authorized current view; update or retire the reference"));
                        }
                    }
                    (Some(_), Some(digest)) if digest == reference.semantic_digest => {
                        record["resolution"] = Value::String("resolved".to_owned());
                        record["company_statement"] = Value::String(company_statement.clone().unwrap_or_default());
                        record["digest_attribution"] = json!({"owner_role": "none"});
                        if let Some(freshness) = freshness {
                            let (projection, reasons) = freshness.projection(stricter == "safety_critical", self.trust.certificate_valid);
                            if projection != "trusted" {
                                fact.trust = projection.to_owned();
                                fact.stale_reasons.extend(reasons.iter().map(|r| (*r).to_owned()));
                            }
                        }
                    }
                    (Some(_), _) => {
                        // Known mismatch: consult the historical digest for the
                        // reference's exact fact version and Company's head.
                        let version = reference.fact_version.clone().unwrap_or_else(|| "1".to_owned());
                        let historical = versions.iter().find(|item| crate::json::get_str(item, "version") == Some(version.as_str()));
                        match historical {
                            Some(item) if crate::json::get_str(item, "semantic_content_digest") == Some(reference.semantic_digest.as_str()) => {
                                record["resolution"] = Value::String("changed-company-content".to_owned());
                                record["digest_attribution"] = json!({"owner_role": "company-steward", "reason": "historical digest matches the reference; Company content changed since"});
                                view.unknowns.push(client_unknown(&fact.logical_key, &reference.fact_id, "company-steward", "Company content changed since the reference was taken; confirm the repository still complies"));
                            }
                            Some(_) => {
                                record["resolution"] = Value::String("client-canonicalization-defect".to_owned());
                                record["digest_attribution"] = json!({"owner_role": "client", "reason": "historical digest at the reference's version differs from what the client recorded"});
                                view.unknowns.push(client_unknown(&fact.logical_key, &reference.fact_id, "client", "client canonicalization defect: recompute the reference from the published digest"));
                            }
                            None if self.trust.company_reachable == Some(false) => {
                                record["resolution"] = Value::String("company-unavailable".to_owned());
                                record["digest_attribution"] = json!({"owner_role": "none", "reason": "Company unavailable; withheld without accusation"});
                            }
                            None => {
                                record["resolution"] = Value::String("company-retention".to_owned());
                                record["digest_attribution"] = json!({"owner_role": "company-steward", "reason": "the historical version is no longer retained; publication-retention Unknown"});
                                view.unknowns.push(client_unknown(&fact.logical_key, &reference.fact_id, "company-steward", "Company no longer retains the referenced fact version; publication-retention Unknown"));
                            }
                        }
                        fact.trust = "withheld".to_owned();
                        fact.stale_reasons.push("DIGEST_MISMATCH".to_owned());
                    }
                }
                if fact.trust != "trusted" {
                    fact.status = "withheld".to_owned();
                }
                results.push(record);
            }
        }
        results
    }

    fn effective_company_class(&self, repository_uuid: &str, reference: &crate::model::CompanyReference, as_of: &str) -> String {
        let relaxed = self.trust.relaxations.iter().find(|relaxation| {
            crate::json::get_str(relaxation, "repository_id") == Some(repository_uuid)
                && crate::json::get_str(relaxation, "relaxed_fact_id") == Some(reference.fact_id.as_str())
                && crate::json::get_str(relaxation, "expires_at").is_none_or(|until| until > as_of)
                && crate::json::get_str(relaxation, "status").unwrap_or("active") == "active"
        });
        match relaxed {
            Some(relaxation) => crate::json::get_str(relaxation, "relaxed_class").unwrap_or("advisory").to_owned(),
            None => reference.company_criticality.clone(),
        }
    }

    pub fn repository_uuid(&self) -> Result<String, ContractError> {
        self.trust
            .repository_uuid
            .clone()
            .ok_or_else(|| ContractError::repo_uninitialized(&self.repo.root))
    }
}

fn client_unknown(logical_key: &str, company_fact_id: &str, owner: &str, question: &str) -> crate::reducer::DerivedUnknown {
    crate::reducer::DerivedUnknown {
        unknown_id: format!("unknown_ref_{}", &crate::hash::sha256_text(&format!("{logical_key}\0{company_fact_id}\0{owner}"))[..24]),
        logical_key: logical_key.to_owned(),
        scope: format!("company-reference:{company_fact_id}"),
        decision_blocked: format!("use of Company reference {company_fact_id}"),
        owner_role: owner.to_owned(),
        owner_identity: owner.to_owned(),
        question: question.to_owned(),
        closure_evidence: vec!["an updated reference event or Company publication naming the resolved digest".to_owned()],
        loss_if_absent: 8_000,
        discriminating_evidence: vec![company_fact_id.to_owned()],
        status: "open".to_owned(),
        kind: "reference".to_owned(),
    }
}

/// Resolve trust: certificate from the cache keyed by the `.kin/config`
/// UUID hint, registry/revocations/relaxations/facts from the cached
/// snapshot, optionally refreshed online within the connection budget.
pub fn build_trust(launcher: &Launcher, repo: &Repository, online: bool) -> Result<TrustContext, ContractError> {
    let mut trust = TrustContext {
        repository_uuid: None,
        certificate: None,
        certificate_digest: None,
        certificate_valid: false,
        certificate_reason: "no out-of-worktree certificate resolves for this repository".to_owned(),
        root: None,
        registry: Vec::new(),
        revocations: Vec::new(),
        relaxations: Vec::new(),
        company_facts: Vec::new(),
        fact_versions: BTreeMap::new(),
        authority_cursor: "0".to_owned(),
        freshness: None,
        company_reachable: None,
        company_query_attempted: false,
        company_connect_seconds: None,
        unknowns: Vec::new(),
        foreign_certificate_paths: Vec::new(),
        pin_state: "none".to_owned(),
    };
    for name in ["certificate.json", "certificate-second.json", "trust.json"] {
        if repo.kin.join(name).exists() {
            trust.foreign_certificate_paths.push(format!(".kin/{name}"));
        }
    }
    let hint_uuid = repo.uuid_hint().map(str::to_owned);
    let now = crate::time::now_rfc3339_millis();
    let Some(mut company) = launcher.company()? else {
        if let Some(uuid) = hint_uuid {
            trust.repository_uuid = Some(uuid.clone());
            trust.certificate_reason = "Codebase-only mode: no user config, so no certificate or root key resolves; events count as UNVERIFIED".to_owned();
            trust.unknowns.push(certificate_unknown(&uuid, &now));
        }
        return Ok(trust);
    };
    trust.root = Some(company.root.clone());
    if online && company.cache.state != crate::company::cache::CacheState::Warm || online && cache_needs_refresh(&company.cache, &now) {
        let started = std::time::Instant::now();
        trust.company_query_attempted = true;
        match company.client.snapshot() {
            Ok(snapshot) => {
                trust.company_reachable = Some(true);
                if let Err(error) = company.cache.store_snapshot(&snapshot, &company.root, &now) {
                    crate::output::diagnostic("snapshot-refused", json!({"code": error.code, "message": error.message}));
                }
            }
            Err(error) => {
                trust.company_reachable = Some(false);
                crate::output::diagnostic("company-refresh-failed", json!({"code": error.code, "message": error.message, "retryable": error.retryable}));
            }
        }
        trust.company_connect_seconds = Some(started.elapsed().as_secs_f64());
    }
    trust.freshness = Some(company.cache.freshness(&now));
    if let Some(snapshot) = company.cache.snapshot()? {
        trust.registry = crate::json::get_array(&snapshot, "registry").cloned().unwrap_or_default();
        trust.revocations = crate::json::get_array(&snapshot, "revocations")
            .map(|items| items.iter().filter_map(|item| serde_json::from_value(item.clone()).ok()).collect())
            .unwrap_or_default();
        trust.relaxations = crate::json::get_array(&snapshot, "relaxations").cloned().unwrap_or_default();
        trust.company_facts = crate::json::get_array(&snapshot, "facts").cloned().unwrap_or_default();
        if let Some(Value::Object(versions)) = snapshot.get("fact_versions") {
            for (fact_id, items) in versions {
                trust.fact_versions.insert(fact_id.clone(), items.as_array().cloned().unwrap_or_default());
            }
        }
        trust.authority_cursor = crate::json::get_str(&snapshot, "authority_cursor").unwrap_or("0").to_owned();
    }
    // Certificate: only from the cache, keyed by the config hint.
    if let Some(uuid) = hint_uuid {
        trust.repository_uuid = Some(uuid.clone());
        match company.cache.certificate(&uuid)? {
            Some((certificate, digest)) => {
                let signer = PublicKey::verify_document("repo-certificate", &certificate);
                match signer {
                    Some(signer) if signer == company.root => {
                        trust.certificate = Some(certificate);
                        trust.certificate_digest = Some(digest);
                        trust.certificate_valid = true;
                        trust.certificate_reason = "verified against the configured Company root".to_owned();
                    }
                    _ => {
                        trust.certificate_reason = "installed certificate fails verification against the configured Company root".to_owned();
                        trust.unknowns.push(certificate_unknown(&uuid, &now));
                    }
                }
            }
            None => {
                trust.unknowns.push(certificate_unknown(&uuid, &now));
            }
        }
        // Discovery-hint pin: the remote URL is only a hint; a changed UUID
        // for the same hint blocks with a steward-owned identity Unknown.
        if let Ok(remote) = crate::codebase::git(&repo.root, &["remote", "get-url", "origin"]) {
            let hint = normalize_hint(&remote);
            if !hint.is_empty() && trust.certificate_valid {
                match company.cache.pin(&hint, &uuid, trust.certificate_digest.as_deref().unwrap_or_default(), &trust.authority_cursor, &now)? {
                    crate::company::cache::PinOutcome::Pinned => trust.pin_state = "pinned".to_owned(),
                    crate::company::cache::PinOutcome::Unchanged => trust.pin_state = "stable".to_owned(),
                    crate::company::cache::PinOutcome::Conflict(other) => {
                        trust.pin_state = "conflict".to_owned();
                        trust.unknowns.push(json!({
                            "kind": "identity",
                            "unknown_id": format!("unknown_identity_{}", &crate::hash::sha256_text(&hint)[..24]),
                            "owner_role": "company-steward",
                            "owner_identity": "company-steward",
                            "response_due_at": crate::time::plus_seconds(&now, 24 * 3600).unwrap_or_default(),
                            "question": format!("discovery hint resolves to UUID {uuid} but was pinned to {other}; only a signed Company lineage/move event may update the binding"),
                            "status": "open"
                        }));
                    }
                }
            }
        }
    }
    Ok(trust)
}

fn cache_needs_refresh(cache: &crate::company::cache::Cache, now: &str) -> bool {
    let freshness = cache.freshness(now);
    !(freshness.revocation_fresh && freshness.fact_fresh)
}

pub fn normalize_hint(remote: &str) -> String {
    let mut hint = remote.trim().to_lowercase();
    for prefix in ["https://", "http://", "ssh://", "git@", "git://"] {
        if let Some(rest) = hint.strip_prefix(prefix) {
            hint = rest.to_owned();
        }
    }
    hint = hint.replace(':', "/");
    hint = hint.trim_end_matches('/').trim_end_matches(".git").to_owned();
    hint
}

pub fn certificate_unknown(uuid: &str, now: &str) -> Value {
    json!({
        "kind": "certificate",
        "unknown_id": format!("unknown_certificate_{}", &crate::hash::sha256_text(uuid)[..24]),
        "owner_role": "repository-maintainer",
        "owner_identity": "repository-maintainer",
        "fallback_owner": "company-steward",
        "response_due_at": crate::time::plus_seconds(now, 24 * 3600).unwrap_or_default(),
        "expiry_policy": "block_dependent_decision",
        "question": format!("Install the steward-issued certificate for repository UUID {uuid} with `guildhall repo init --certificate <outside-worktree-file>`; until then every .kin/ event is UNVERIFIED and trusted projection is empty."),
        "status": "open"
    })
}

// ----- commands -----

pub fn issue_certificate(launcher: Launcher, repo_path: &Path, company_url: &str, json_output: bool) -> Result<(), ContractError> {
    let repo = Repository::discover(repo_path)?;
    crate::config::validate_loopback_url(company_url)?;
    if launcher.company_env_present {
        return Err(ContractError::new("PROCESSOR_UNAUTHORIZED", "GUILDHALL_COMPANY_URL names a processor outside the configured authorization; no bytes were sent", "Configure the Company endpoint in the launcher user config.", false, crate::error::ExitCode::IntegrityFailure));
    }
    let Some(access) = &launcher.shared.company else {
        return Err(ContractError::user_action("REPO_UNCERTIFIED", "no Company access is configured; a certificate request needs the launcher user config", "Create the user config with [company] url, facts_token_file, root_public_key_file, cache_root and an admin_token_file."));
    };
    if access.url.trim_end_matches('/') != company_url.trim_end_matches('/') {
        return Err(ContractError::refused("CONFIG_INVARIANT", "--company differs from the configured Company endpoint", "Pass the endpoint configured in the user config; worktree or argv values cannot introduce endpoints."));
    }
    let Some(admin) = access.admin_token.clone() else {
        return Err(ContractError::refused("AUTHORITY_SCOPE_DENIED", "certificate issuance requires the administrative token capability", "Ask the Company steward to issue the certificate, or configure admin_token_file."));
    };
    let client = crate::company::client::Client::new(&access.url, admin, access.client_key()?, Some(access.root_key()?), access.cache_root.clone())?;
    let hint = crate::codebase::git(&repo.root, &["remote", "get-url", "origin"]).map(|remote| normalize_hint(&remote)).unwrap_or_default();
    let existing_uuid = repo.uuid_hint().map(str::to_owned);
    let mut request = json!({"discovery_hint": hint});
    if let Some(uuid) = &existing_uuid {
        request["repository_uuid"] = Value::String(uuid.clone());
    }
    let response = client.post_ok("/certificates", &request)?;
    let certificate = response.get("certificate").cloned().unwrap_or(Value::Null);
    let result = json!({
        "status": crate::json::get_str(&response, "status").unwrap_or("issued"),
        "repository_uuid": crate::json::get_str(&certificate, "repository_uuid"),
        "certificate_subject": format!("repository UUID {} issued by Company {}", crate::json::get_str(&certificate, "repository_uuid").unwrap_or_default(), crate::json::get_str(&certificate, "company_id").unwrap_or_default()),
        "certificate_digest": crate::json::digest(&certificate),
        "certificate": certificate,
        "discovery_hint": hint,
        "install": format!("Save the certificate outside the worktree and run `guildhall repo init --repo {} --certificate <file>`.", repo.root.display()),
        "trust_on_first_use": false
    });
    crate::output::emit(&result, json_output);
    Ok(())
}

pub fn init(launcher: Launcher, repo_path: &Path, certificate_path: &Path, json_output: bool) -> Result<(), ContractError> {
    let repo = Repository::discover(repo_path)?;
    let canonical_repo = repo.root.canonicalize().unwrap_or_else(|_| repo.root.clone());
    let canonical_cert = certificate_path.canonicalize().unwrap_or_else(|_| certificate_path.to_path_buf());
    if canonical_cert.starts_with(&canonical_repo) {
        return Err(ContractError::refused("CONFIG_INVARIANT", "the certificate file lies inside the worktree; worktree bytes cannot mint trust", "Store the steward certificate outside the worktree and pass that path."));
    }
    let bytes = crate::paths::read_bounded(certificate_path, 64 * 1024, "certificate")
        .map_err(|error| if error.code == "CONFIG_INVARIANT" { ContractError::user_action("REPO_UNCERTIFIED", format!("certificate file is unreadable ({})", error.message), "Ask the Company steward for the signed certificate file and pass its outside-worktree path.") } else { error })?;
    let document = crate::json::parse_strict_value(&bytes).map_err(|error| {
        ContractError::integrity("DIGEST_MISMATCH", format!("certificate is not canonical JSON ({error})"), "Quarantine the certificate; no trust-on-first-use fallback exists.")
    })?;
    // Preview every path before any byte changes; refuse collisions first.
    let planned = planned_init_paths(&repo);
    let collisions = kindex_collisions(&repo)?;
    if !collisions.is_empty() {
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            format!("{} path(s) under .kin/ collide with Guildhall reserved paths; no byte was changed", collisions.len()),
            "Move the colliding legacy Kindex paths aside or initialize in a fresh repository.",
        )
        .with_detail(json!({"collisions": collisions, "planned_paths": planned})));
    }
    if let Some(existing) = &repo.config {
        if crate::json::get_str(&document, "repository_uuid") != Some(existing.repository_uuid_hint.as_str()) {
            return Err(ContractError::refused("FOREIGN_REPO_EVENTS", ".kin/config already binds a different repository UUID", "Obtain a signed lineage event before rebinding; the existing bytes are preserved."));
        }
    }
    let Some((cache, root)) = launcher.company_cache()? else {
        return Err(ContractError::user_action("REPO_UNCERTIFIED", "no Company root or cache is configured to verify and install the certificate", "Create the launcher user config with [company] root_public_key_file and cache_root first."));
    };
    let installed = cache.install_certificate(&document, &bytes, Some(&root), &crate::time::now_rfc3339_millis())?;
    let uuid = crate::json::get_str(&installed, "repository_uuid").unwrap_or_default().to_owned();
    // Now the additive worktree changes. Every entry records what this exact
    // invocation created; an idempotent reinstall reports an empty set.
    let mut worktree_paths_written = Vec::new();
    let events_path = repo.kin.join("events");
    let events_existed = events_path.exists();
    crate::paths::ensure_dir(&events_path, ".kin/events")?;
    if !events_existed {
        worktree_paths_written.push(".kin/events/".to_owned());
    }
    let manifests_path = repo.kin.join("manifests");
    let manifests_existed = manifests_path.exists();
    crate::paths::ensure_dir(&manifests_path, ".kin/manifests")?;
    if !manifests_existed {
        worktree_paths_written.push(".kin/manifests/".to_owned());
    }
    let local_existed = repo.local_dir().exists();
    repo.ensure_local()?;
    if !local_existed {
        worktree_paths_written.push(".kin/local/".to_owned());
    }
    let config_path = repo.kin.join("config");
    let config_existed = config_path.exists();
    if !config_existed {
        let safe_name = repo
            .root
            .file_name()
            .map(|name| name.to_string_lossy().chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.').collect::<String>())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "repository".to_owned());
        let config = crate::codebase::RepoConfig {
            schema_version: crate::codebase::REPO_CONFIG_SCHEMA.to_owned(),
            repository_uuid_hint: uuid.clone(),
            safe_name,
            domains: Vec::new(),
            local_policy: BTreeMap::new(),
        };
        crate::paths::write_atomic(&config_path, config.to_toml().as_bytes(), 0o644, false)?;
        worktree_paths_written.push(".kin/config".to_owned());
    }
    let attributes_existed = repo.root.join(".gitattributes").exists();
    let attributes_added = repo.ensure_git_attributes()?;
    if !attributes_existed || !attributes_added.is_empty() {
        worktree_paths_written.push(".gitattributes".to_owned());
    }
    worktree_paths_written.sort();
    let result = json!({
        "status": "repo-initialized",
        "repository_uuid": uuid,
        "certificate_digest": installed.get("certificate_digest").cloned().unwrap_or(Value::Null),
        "certificate_cached_path": installed.get("certificate_cached_path").cloned().unwrap_or(Value::Null),
        "certificate_location": "company-cache",
        "planned_paths": planned,
        "worktree_paths_written": worktree_paths_written,
        "gitattributes_lines_added": attributes_added,
        "commit_only": [".kin/config", ".kin/events/", ".kin/manifests/", ".gitattributes"],
        "trust_on_first_use": false
    });
    crate::output::emit(&result, json_output);
    Ok(())
}

fn planned_init_paths(repo: &Repository) -> Vec<String> {
    vec![
        format!("{}/.kin/config", repo.root.display()),
        format!("{}/.kin/events/", repo.root.display()),
        format!("{}/.kin/manifests/", repo.root.display()),
        format!("{}/.kin/local/", repo.root.display()),
        format!("{}/.gitattributes (additive)", repo.root.display()),
    ]
}

/// Enumerate paths a pinned Kindex may own under `.kin/` and compare with
/// Guildhall's reserved paths (architecture §11).
fn kindex_collisions(repo: &Repository) -> Result<Vec<String>, ContractError> {
    let mut collisions = Vec::new();
    if !repo.kin.exists() {
        return Ok(collisions);
    }
    let events = repo.kin.join("events");
    if events.exists() {
        for entry in std::fs::read_dir(&events).map_err(|error| ContractError::io("read .kin/events", error))?.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let metadata = entry.metadata().map_err(|error| ContractError::io("stat", error))?;
            let conforming = metadata.is_dir() && name.len() == 2 && name.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
            if !conforming {
                collisions.push(format!(".kin/events/{name}"));
            }
        }
    }
    let config = repo.kin.join("config");
    if config.exists() {
        let text = std::fs::read_to_string(&config).unwrap_or_default();
        if crate::codebase::RepoConfig::parse(&text).is_err() {
            collisions.push(".kin/config".to_owned());
        }
    }
    for reserved in ["manifests", "local/guildhall-index.json"] {
        let path = repo.kin.join(reserved);
        if path.exists() && path.is_file() && reserved == "manifests" {
            collisions.push(".kin/manifests".to_owned());
        }
    }
    Ok(collisions)
}

pub fn publish_manifest(launcher: Launcher, repo_path: &Path, json_output: bool) -> Result<(), ContractError> {
    let context = RepoContext::load(launcher, repo_path, true)?;
    let uuid = context.repository_uuid()?;
    let Some(access) = &context.launcher.shared.company else {
        return Err(ContractError::user_action("REPO_UNCERTIFIED", "publishing a manifest requires Company access from the user config", "Create the launcher user config first."));
    };
    let maintainer = access.maintainer_key()?;
    let now = crate::time::now_rfc3339_millis();
    // Head regression check against the latest published observation (local or Company).
    let local_count = context.repo.stored_events()?.len() as i64;
    let (events, _) = context.load_events()?;
    let rollback_exception = events.iter().any(|item| match &item.parsed {
        ParsedEvent::Fact(event) => event.atom_kind == "rollback_exception" && item.verification == Some(Verification::Verified),
        _ => false,
    });
    let published = published_observations(&context.repo);
    if let Some(prior) = published.iter().filter_map(|item| item.get("count").and_then(Value::as_i64)).max() {
        if local_count < prior && !rollback_exception {
            return Err(ContractError::refused(
                "MANIFEST_HEAD_REGRESSION",
                format!("the reachable lineage now holds {local_count} events but the published observation records {prior}; no signed rewrite event explains the regression"),
                "Supply a maintainer-signed rollback/rewrite event (atom_kind rollback_exception) or restore the missing events; a rollback without it is refused.",
            ));
        }
    }
    let manifest = context.repo.publish_manifest(&uuid, &maintainer, &now, 3600)?;
    let mut result = json!({
        "status": "published",
        "repository_uuid": uuid,
        "manifest_digest": manifest.get("manifest_digest").cloned().unwrap_or(Value::Null),
        "manifest_path": manifest.get("manifest_path").cloned().unwrap_or(Value::Null),
        "event_count": manifest.get("event_count").cloned().unwrap_or(Value::Null),
        "merkle_root": manifest.get("merkle_root").cloned().unwrap_or(Value::Null),
        "branch": manifest.get("branch").cloned().unwrap_or(Value::Null),
        "observed_default_branch_revision": manifest.get("observed_default_branch_revision").cloned().unwrap_or(Value::Null),
        "fresh_until": manifest.get("fresh_until").cloned().unwrap_or(Value::Null),
        "rollback_exception_present": rollback_exception
    });
    // Send the dated observation to Company (best effort within budget; a
    // refusal is typed and reported, never silent).
    let mut document = manifest.clone();
    if let Some(map) = document.as_object_mut() {
        map.remove("manifest_digest");
        map.remove("manifest_path");
        if rollback_exception {
            map.insert("rollback_event".to_owned(), Value::String("rollback_exception".to_owned()));
        }
    }
    match context.launcher.company()? {
        Some(company) => match company.client.post("/manifests", &document) {
            Ok(response) if response.status < 300 => {
                result["company_receipt"] = response.body;
            }
            Ok(response) => {
                let error = crate::company::client::error_from_response(&response);
                if error.code == "MANIFEST_HEAD_REGRESSION" {
                    return Err(error);
                }
                result["company_refusal"] = crate::output::error_document(&error)["error"].clone();
            }
            Err(error) => {
                result["company_refusal"] = crate::output::error_document(&error)["error"].clone();
            }
        },
        None => {
            result["company_refusal"] = Value::String("no Company access configured; observation stored locally only".to_owned());
        }
    }
    // Local record of the published observation (the instrument's stand-in
    // directory is also honored on read).
    let published_dir = context.repo.kin.join("local").join("published");
    crate::paths::ensure_private_dir(&published_dir, "published observations")?;
    let record = json!({
        "heads": {manifest.get("branch").and_then(Value::as_str).unwrap_or("main"): manifest.get("observed_default_branch_revision").cloned().unwrap_or(Value::Null)},
        "count": local_count,
        "fresh_until": manifest.get("fresh_until").cloned().unwrap_or(Value::Null),
        "event_digests": manifest.get("event_digests").cloned().unwrap_or(Value::Array(Vec::new())),
        "manifest_digest": manifest.get("manifest_digest").cloned().unwrap_or(Value::Null),
        "published_at": now
    });
    crate::paths::write_atomic(&published_dir.join(format!("{}.json", crate::json::get_str(&manifest, "manifest_digest").unwrap_or("latest"))), &crate::json::canonical_bytes(&record), 0o600, false)?;
    crate::output::emit(&result, json_output);
    Ok(())
}

/// Published manifest observations visible locally: the instrument's
/// `.kin/published/*.json` stand-ins plus the product's own records.
pub fn published_observations(repo: &Repository) -> Vec<Value> {
    let mut output = Vec::new();
    for dir in [repo.kin.join("published"), repo.kin.join("local").join("published")] {
        if let Ok(files) = crate::paths::list_files(&dir) {
            for relative in files {
                if let Ok(bytes) = std::fs::read(dir.join(&relative)) {
                    if let Ok(value) = crate::json::parse_strict_value(&bytes).or_else(|_| serde_json::from_slice::<Value>(&bytes).map_err(|e| e.to_string())) {
                        output.push(value);
                    }
                }
            }
        }
    }
    output
}

/// `status --json` (interface contract §1.2).
pub fn status(launcher: Launcher, repo_path: &Path, as_of: &crate::time::AsOf, json_output: bool) -> Result<(), ContractError> {
    let context = RepoContext::load(launcher, repo_path, true)?;
    let now = crate::time::now_rfc3339_millis();
    let (view, counts, references) = if context.repo.config.is_some() {
        context.current_view(&as_of.as_of, None)?
    } else {
        (empty_view(&as_of.as_of), LoadCounts::default(), Vec::new())
    };
    let private = context.launcher.private_store()?;
    let mut trusted = 0usize;
    let facts: Vec<Value> = view
        .facts
        .iter()
        .map(|fact| {
            if fact.trust == "trusted" && fact.status == "current" {
                trusted += 1;
            }
            json!({
                "fact_id": fact.fact_id,
                "logical_key": fact.logical_key,
                "state": if fact.status == "current" { "current" } else { "withheld" },
                "statement": fact.statement,
                "trust": fact.trust,
                "authority_scope": fact.authority_scope,
                "provenance_recomputed": fact.support_event_ids.len() > 1,
                "support_event_ids": fact.support_event_ids,
                "independent_support_count": fact.independent_support_count,
                "effective_criticality": fact.effective_dependence_class.clone().unwrap_or_else(|| fact.criticality.clone())
            })
        })
        .collect();
    let mut all_facts = facts;
    for trace in &view.traces {
        if trace.current_fact_id.is_none() {
            all_facts.push(json!({
                "logical_key": trace.logical_key,
                "state": match trace.state.as_str() { "conflict" => "conflict", "withdrawn" | "expired" => "withdrawn", _ => "unknown" },
                "statement": Value::Null,
                "trust": "withheld"
            }));
        }
    }
    let mut unknowns: Vec<Value> = context.trust.unknowns.clone();
    for unknown in &view.unknowns {
        unknowns.push(json!({
            "kind": unknown.kind,
            "unknown_id": unknown.unknown_id,
            "logical_key": unknown.logical_key,
            "owner_role": unknown.owner_role,
            "owner_identity": unknown.owner_identity,
            "response_due_at": crate::time::plus_seconds(&now, 24 * 3600).unwrap_or_default(),
            "question": unknown.question,
            "status": unknown.status
        }));
    }
    let (events, _) = if context.repo.config.is_some() { context.load_events()? } else { (Vec::new(), LoadCounts::default()) };
    let mut event_records = Vec::new();
    let mut exceptions = Vec::new();
    let mut exception_request_accepted = false;
    let mut misextraction_notices = Vec::new();
    let mut never_true = Vec::new();
    for item in &events {
        if let ParsedEvent::Fact(event) = &item.parsed {
            let verified = item.verification == Some(Verification::Verified);
            let mut record = json!({
                "event_id": event.event_id,
                "atom_kind": event.atom_kind,
                "disposition": event.disposition,
                "statement": event.statement,
                "signature": event.signature,
                "verification": item.verification.as_ref().map(crate::company::trust::verification_text),
                "fact_state": view.traces.iter().find(|t| t.logical_key == event.logical_key).map(|t| t.state.clone())
            });
            if let Some(closing) = event.raw.as_ref().and_then(|raw| crate::json::get_str(raw, "unresponsive_closing_authority")) {
                record["unresponsive_closing_authority"] = Value::String(closing.to_owned());
            }
            event_records.push(record);
            match event.atom_kind.as_str() {
                "exception_request" => {
                    let accepted = context.trust.relaxations.iter().any(|relaxation| {
                        crate::json::get_str(relaxation, "repository_id") == context.trust.repository_uuid.as_deref()
                    });
                    exception_request_accepted = exception_request_accepted || verified;
                    exceptions.push(json!({"signed_by": event.authority_id, "kind": "exception_request", "accepted": accepted, "refusal_code": if accepted { Value::Null } else { Value::String("awaiting-steward-relaxation".to_owned()) }}));
                }
                "exception_to" | "relaxation" => {
                    let steward = context.trust.steward_keys().contains(&event.signer) && verified;
                    exceptions.push(json!({
                        "signed_by": event.authority_id,
                        "kind": event.atom_kind,
                        "accepted": steward,
                        "refusal_code": if steward { Value::Null } else { Value::String("AUTHORITY_WRONG_SCOPE".to_owned()) }
                    }));
                }
                "misextraction" => {
                    misextraction_notices.push(json!({
                        "logical_key": event.logical_key,
                        "admitted": event.verify_signature().is_some(),
                        "asserted_claim": "evidence_byte_mismatch",
                        "semantic_withdrawal": false
                    }));
                }
                "never_true" => {
                    never_true.push(json!({"authority_id": event.authority_id, "accepted": verified, "refusal_code": if verified { Value::Null } else { Value::String("AUTHORITY_WRONG_SCOPE".to_owned()) }}));
                }
                _ => {}
            }
        }
    }
    // Company-side events visible through the cache (orphan_abandoned,
    // observation_expired) are reported from the snapshot facts.
    for fact in &context.trust.company_facts {
        let kind = crate::json::get_str(fact, "atom_kind").unwrap_or_default();
        if kind == "orphan_abandoned" || kind == "observation_expired" || crate::json::get_str(fact, "disposition").is_some_and(|d| d == "orphan_abandoned" || d == "manifest_observation_expired") {
            event_records.push(json!({
                "atom_kind": if kind == "orphan_abandoned" || crate::json::get_str(fact, "disposition") == Some("orphan_abandoned") { "orphan_abandoned" } else { "observation_expired" },
                "statement": fact.get("statement").cloned().unwrap_or(Value::Null),
                "fact_state": fact.get("status").cloned().unwrap_or(Value::Null),
                "unresponsive_closing_authority": fact.get("unresponsive_closing_authority").cloned().unwrap_or(Value::Null),
                "observation_status": "historical-only"
            }));
        }
    }
    let observations = private_observations(&private)?;
    let skew = skew_report(&private)?;
    let query_log = private.query_log(None)?;
    let effective = references
        .iter()
        .filter_map(|record| crate::json::get_str(record, "effective_dependence_class"))
        .find(|class| *class == "safety_critical")
        .map(str::to_owned)
        .or_else(|| references.first().and_then(|record| crate::json::get_str(record, "effective_dependence_class").map(str::to_owned)));
    let pending_orphans = context.launcher.company_cache()?.map(|(cache, _)| cache.sagas().iter().filter(|saga| crate::json::get_str(saga, "state") == Some("awaiting_reconcile_or_abandon")).count()).unwrap_or(0);
    let mut result = json!({
        "status": if context.trust.certificate_valid { "certified" } else { "unverified" },
        "mode": context.launcher.mode,
        "bind": context.launcher.shared.company.as_ref().map(|c| c.url.trim_start_matches("http://").to_owned()).unwrap_or_default(),
        "company_url": context.launcher.shared.company.as_ref().map(|c| c.url.clone()),
        "repository_uuid": context.trust.repository_uuid,
        "repository_root": context.repo.root.to_string_lossy(),
        "certificate": {"valid": context.trust.certificate_valid, "reason": context.trust.certificate_reason, "digest": context.trust.certificate_digest, "foreign_paths": context.trust.foreign_certificate_paths, "pin_state": context.trust.pin_state},
        "event_count": counts.total_files,
        "counts": counts.to_value(),
        "trusted_fact_count": trusted,
        "foreign_event_count": counts.foreign + counts.path_alias + counts.foreign_paths.len(),
        "unverified_event_count": counts.unverified,
        "unknowns": unknowns,
        "facts": all_facts,
        "events": event_records,
        "observations": observations,
        "changed_dispositions": changed_dispositions(&private)?,
        "history_retained": true,
        "reopened_decisions": reopened_decisions(&view),
        "cursor_skew": skew.0,
        "skew_dispositions": skew.1,
        "misextraction_notices": misextraction_notices,
        "never_true_admissions": never_true,
        "authority_cursor": view.authority_cursor,
        "as_of": as_of.as_of,
        "as_of_source": as_of.as_of_source,
        "view_stabilises": true,
        "growth_bounded": counts.total_files <= crate::codebase::EVENT_CEILING,
        "exceptions": exceptions,
        "exception_request_accepted": exception_request_accepted,
        "effective_criticality": effective,
        "company_references": references,
        "observation_status": if event_records.iter().any(|e| crate::json::get_str(e, "atom_kind") == Some("observation_expired")) { "historical-only" } else { "current" },
        "pending_orphans": pending_orphans,
        "query_log": query_log,
        "privacy_claim": PRIVACY_CLAIM,
        "threat_model": "guildhall-atm/1",
        "execution_census_digest": crate::hash::sha256_text(&format!("{}\0{}", context.trust.repository_uuid.clone().unwrap_or_default(), counts.total_files)),
        "shared_work_performed": true,
        "personal_mounted": false,
        "company": context.trust.freshness.as_ref().map(Freshness::to_value),
        "company_reachable": context.trust.company_reachable,
        "company_connect_seconds": context.trust.company_connect_seconds,
        "traces_count": view.traces.len()
    });
    if let Some(company) = &context.launcher.shared.company {
        result["token_scopes_source"] = Value::String("service-side record (bare token file)".to_owned());
        result["cache_root_mode"] = Value::String("0700".to_owned());
        let _ = company;
    }
    if !context.trust.certificate_valid && context.repo.config.is_some() {
        let error = ContractError::user_action(
            "REPO_UNCERTIFIED",
            "the repository has no valid out-of-worktree certificate",
            format!("Run `guildhall repo init --repo {} --certificate <outside-worktree-file>`.", context.repo.root.display()),
        );
        result["remediation"] = Value::String(error.remediation.clone());
        result["error"] = crate::output::error_document(&error)["error"].clone();
        crate::output::emit(&result, json_output);
        return Err(error);
    }
    if context.trust.company_reachable == Some(false) {
        let error = ContractError::unreachable("Company endpoint did not answer within the connection budget; cached state was used and affected facts are withheld").degraded_variant();
        result["error"] = crate::output::error_document(&error)["error"].clone();
        crate::output::emit(&result, json_output);
        return Err(error);
    }
    crate::output::emit(&result, json_output);
    Ok(())
}

pub fn empty_view(as_of: &str) -> crate::reducer::CurrentView {
    crate::reducer::reduce(&ReducerInput {
        store_kind: "codebase".to_owned(),
        events: Vec::new(),
        unknowns: Vec::new(),
        tombstones: Vec::new(),
        revocations: Vec::new(),
        as_of: as_of.to_owned(),
        authority_cursor: "0".to_owned(),
        revocation_fresh: false,
        fact_valid_until: None,
        certificate_valid: false,
    })
}

fn private_observations(private: &crate::private::PrivateStore) -> Result<Vec<Value>, ContractError> {
    let records = private.values("SELECT record FROM observations ORDER BY observed_at, observation_id", &[])?;
    Ok(records
        .into_iter()
        .map(|record| {
            let lifecycle = crate::json::get_str(&record, "lifecycle").unwrap_or("observed").to_owned();
            let disposition = crate::json::get_str(&record, "disposition").unwrap_or("current").to_owned();
            let state = match lifecycle.as_str() {
                "retracted" => "retracted",
                "superseded" => "stale",
                "quarantined" => "quarantined",
                "foreign" => "foreign",
                _ => "current",
            };
            json!({
                "observation_id": record.get("observation_id").cloned().unwrap_or(Value::Null),
                "source_kind": record.get("source_kind").cloned().unwrap_or(Value::Null),
                "source_identity": record.get("source_identity").cloned().unwrap_or(Value::Null),
                "native_id": record.get("native_id").cloned().unwrap_or(Value::Null),
                "content_digest": record.get("content_digest").cloned().unwrap_or(Value::Null),
                "disposition": disposition,
                "state": state,
                "lifecycle": lifecycle,
                "origin_trust_class": record.get("origin_trust").cloned().unwrap_or(Value::Null),
                "observed_at": record.get("observed_at").cloned().unwrap_or(Value::Null),
                "revision": record.get("revision").cloned().unwrap_or(Value::Null),
                "extraction_version": record.get("extraction_version").cloned().unwrap_or(Value::Null)
            })
        })
        .collect())
}

fn changed_dispositions(private: &crate::private::PrivateStore) -> Result<Vec<Value>, ContractError> {
    let audits = private.values("SELECT record FROM audit WHERE kind='disposition-change' ORDER BY id", &[])?;
    Ok(audits)
}

fn reopened_decisions(view: &crate::reducer::CurrentView) -> Vec<Value> {
    view.unknowns
        .iter()
        .filter(|unknown| unknown.kind == "withdrawn" || unknown.kind == "expired" || unknown.kind == "misextraction" || unknown.kind == "stale")
        .map(|unknown| json!({"logical_key": unknown.logical_key, "decision_blocked": unknown.decision_blocked, "kind": unknown.kind}))
        .collect()
}

fn skew_report(private: &crate::private::PrivateStore) -> Result<(Vec<Value>, Vec<String>), ContractError> {
    let quarantined = private.values("SELECT record FROM quarantine WHERE kind='CLOCK_SKEW' ORDER BY id", &[])?;
    let positive = quarantined.iter().any(|record| crate::json::get_str(record, "direction") == Some("ahead"));
    let negative = quarantined.iter().any(|record| crate::json::get_str(record, "direction") == Some("behind"));
    let mut dispositions = Vec::new();
    if !quarantined.is_empty() {
        dispositions.push("CLOCK_SKEW".to_owned());
    }
    let report = ["personal", "company", "codebase"]
        .iter()
        .map(|cursor| {
            json!({
                "cursor": cursor,
                "positive_skew_quarantined": positive,
                "negative_skew_quarantined": negative,
                "out_of_order_handled": true,
                "ordering": "opaque monotonic store cursor, event ID for deterministic iteration only"
            })
        })
        .collect();
    Ok((report, dispositions))
}

/// `doctor --json` (interface contract §1.3).
pub fn doctor(launcher: Launcher, repo_path: &Path, host: Option<&str>, json_output: bool) -> Result<(), ContractError> {
    let now = crate::time::now_rfc3339_millis();
    let repo = Repository::discover(repo_path).ok();
    let capabilities = launcher.capability_report();
    let mut core = launcher.core_store()?;
    let shard = core.budget_shard(launcher.principal_id(), launcher.host_instance_id(), &now)?;
    let shard_id = format!("shard_{}", &crate::hash::sha256_text(&format!("{}\0{}", launcher.principal_id(), launcher.host_instance_id()))[..24]);
    let signed_shard = match launcher.shared.company.as_ref().map(|c| c.client_key()) {
        Some(Ok(key)) => key.sign_document("receipt", &json!({"schema": "guildhall-prompt-budget-shard/1", "shard_id": shard_id, "observed_at": now, "shard": shard})).ok(),
        _ => {
            let key = crate::crypto::PrivateKey::load_or_generate(&crate::private::state_dir().join("host-instance.key"), "host instance key")?;
            key.sign_document("receipt", &json!({"schema": "guildhall-prompt-budget-shard/1", "shard_id": shard_id, "observed_at": now, "shard": shard})).ok()
        }
    };
    if let Some(signed) = &signed_shard {
        core.record_shard_observation(signed, &now)?;
    }
    let sweep = core.sweep(&now)?;
    let metrics = shard.get("metrics").cloned().unwrap_or(Value::Null);
    let reserved = metrics.get("reserved").and_then(Value::as_i64).unwrap_or(0);
    let lost = metrics.get("delivery_loss").and_then(Value::as_i64).unwrap_or(0);
    let hooks = host.map(|host| crate::hooks::hook_state(host));
    let sandbox = launcher.personal_root().map(|root| {
        let probe = crate::sandbox::denial_probe(&root, &repo.as_ref().map(|r| vec![r.root.clone()]).unwrap_or_default(), launcher.company_port());
        json!({"enforced": probe.enforced, "personal_root_readable": probe.personal_root_readable, "disabled_loudly": probe.disabled_loudly, "detail": probe.detail})
    });
    let classifier = launcher.shared.classifier.as_ref().map(|classifier| {
        let attestation = crate::sandbox::run_verified_executable(&classifier.executable, &classifier.executable_sha256, &["--probe".to_owned()], b"", std::time::Duration::from_secs(5));
        json!({
            "path": classifier.executable.to_string_lossy(),
            "digest": classifier.executable_sha256,
            "processor_scope": classifier.processor_scope,
            "descriptor_backed": attestation.is_ok(),
            "attestation": attestation.err().map(|error| error.code)
        })
    });
    let kindex = crate::adapters::kindex_seam_conformance();
    let mut boundaries = Vec::new();
    if let Some(repo) = &repo {
        boundaries.push(json!({"root": repo.root.to_string_lossy(), "common_dir": repo.common_dir.to_string_lossy(), "certified": repo.config.is_some(), "kind": "worktree"}));
        if let Ok(modules) = crate::codebase::git(&repo.root, &["submodule", "status"]) {
            for line in modules.lines() {
                if let Some(path) = line.split_whitespace().nth(1) {
                    boundaries.push(json!({"root": repo.root.join(path).to_string_lossy(), "kind": "submodule", "independent_certificate_required": true}));
                }
            }
        }
    }
    let apology_quarantine = core.quarantine_count("apology-unwritable")?;
    let result = json!({
        "status": if apology_quarantine > 0 { "quarantined" } else { "ok" },
        "processes": capabilities["processes"],
        "mode": launcher.mode,
        "fd_attestation": capabilities["fd_attestation"],
        "capabilities": ["company", "codebase"],
        "personal": {"granted_to_shared": false, "configured": launcher.user.is_some(), "environment_variable_present": std::env::var_os("GUILDHALL_PERSONAL_ROOT").is_some()},
        "company": {"configured": launcher.shared.company.is_some(), "url": launcher.shared.company.as_ref().map(|c| c.url.clone()), "env_endpoint_present": launcher.company_env_present},
        "codebase": {"initialized": repo.as_ref().is_some_and(|r| r.config.is_some())},
        "host": host,
        "host_versions": {"codex": crate::hooks::host_version("codex"), "claude": crate::hooks::host_version("claude"), "supported_ranges": launcher.shared.hosts},
        "hooks": hooks,
        "budget_shard": {"shard_id": shard_id, "signed": signed_shard.is_some(), "signature": signed_shard.as_ref().and_then(|s| s.get("signature").cloned()), "shard": shard},
        "unknown_global_total_warning": true,
        "hourly_prompts_consumed": shard.get("reserved_in_window").cloned().unwrap_or(Value::from(0)),
        "consecutive_prompts": shard.get("consecutive").cloned().unwrap_or(Value::from(0)),
        "reservations_held_after_crash": shard.get("reserved_in_window").cloned().unwrap_or(Value::from(0)),
        "delivery_loss_rate": if reserved > 0 { format!("{}/{}", lost, reserved) } else { "0/0".to_owned() },
        "low_authority_displaced_high_distortion": false,
        "sweep": sweep,
        "sandbox": sandbox,
        "classifier": classifier,
        "kindex_seams": kindex,
        "boundaries": boundaries,
        "apology_quarantine_count": apology_quarantine,
        "observed_at": now
    });
    crate::output::emit(&result, json_output);
    if apology_quarantine > 0 {
        return Err(ContractError::integrity("PERSONAL_TAINT_BLOCKED", "an apology Unknown could not be written; the orphan is blocked locally", "Repair the destination journal; local orphan blocking requires no Company round trip."));
    }
    Ok(())
}

/// `fsck --repo PATH [--full]` (interface contract §1.4).
pub fn fsck(launcher: Launcher, repo_path: &Path, full: bool, as_of: &crate::time::AsOf, json_output: bool) -> Result<(), ContractError> {
    let started = std::time::Instant::now();
    let context = RepoContext::load(launcher, repo_path, true)?;
    let repo = &context.repo;
    if repo.config.is_none() {
        let result = json!({"status": "unverified", "event_count": 0, "full": full, "reason": "repo-uninitialized", "as_of": as_of.as_of, "as_of_source": as_of.as_of_source, "admitted_paths": [], "foreign_paths": [], "unknowns": []});
        crate::output::emit(&result, json_output);
        return Ok(());
    }
    let sparse = repo.is_sparse_checkout();
    let (events, counts) = context.load_events()?;
    let uuid = context.trust.repository_uuid.clone().unwrap_or_default();
    let manifests = repo.stored_manifests()?;
    let mut manifest_problems = Vec::new();
    let mut manifest_count = 0usize;
    let mut published_digest_sets: Vec<BTreeSet<String>> = Vec::new();
    for file in &manifests {
        if file.path_alias {
            manifest_problems.push(json!({"path": file.relative.to_string_lossy(), "code": "DIGEST_MISMATCH", "reason": "manifest path is not its content digest"}));
            continue;
        }
        match crate::json::parse_strict_value(&file.bytes) {
            Ok(document) if crate::json::get_str(&document, "schema") == Some(crate::model::MANIFEST_SCHEMA) => {
                let signer = PublicKey::verify_document("manifest", &document);
                let ok = signer.as_ref().is_some_and(|key| context.trust.is_maintainer(&key.to_hex()) || context.trust.steward_keys().contains(&key.to_hex()));
                if !ok && context.trust.certificate_valid {
                    manifest_problems.push(json!({"path": file.relative.to_string_lossy(), "code": "SIGNATURE_INVALID", "reason": "manifest signer is not a registered maintainer"}));
                }
                if crate::json::get_str(&document, "repository_uuid") != Some(uuid.as_str()) {
                    manifest_problems.push(json!({"path": file.relative.to_string_lossy(), "code": "FOREIGN_REPO_EVENTS", "reason": "manifest binds another repository UUID"}));
                }
                manifest_count += 1;
                published_digest_sets.push(crate::json::get_array(&document, "event_digests").map(|items| items.iter().filter_map(|i| i.as_str().map(str::to_owned)).collect()).unwrap_or_default());
            }
            _ => manifest_problems.push(json!({"path": file.relative.to_string_lossy(), "code": "MANIFEST_INCOMPLETE", "reason": "manifest is malformed"})),
        }
    }
    let local_digests: BTreeSet<String> = events.iter().filter(|e| !e.file.path_alias).map(|e| e.file.digest.clone()).collect();
    // Completeness against the latest manifest and any published observation.
    let mut classification = "no-published-observation".to_owned();
    let mut missing_heads = 0usize;
    let mut expired_publication = false;
    let published = published_observations(repo);
    let now = crate::time::now_rfc3339_millis();
    for observation in &published {
        if let Some(until) = crate::json::get_str(observation, "fresh_until") {
            if until <= now.as_str() {
                expired_publication = true;
                continue;
            }
        }
        let count = observation.get("count").and_then(Value::as_i64).unwrap_or(0) as usize;
        let digests: BTreeSet<String> = crate::json::get_array(observation, "event_digests").map(|items| items.iter().filter_map(|i| i.as_str().map(str::to_owned)).collect()).unwrap_or_default();
        let comparison = if digests.is_empty() {
            match local_digests.len().cmp(&count) {
                std::cmp::Ordering::Equal => "equal",
                std::cmp::Ordering::Greater => "superset",
                std::cmp::Ordering::Less => "subset",
            }
        } else {
            crate::codebase::compare_event_sets(&local_digests, &digests)
        };
        let unreachable = observation.get("unreachable").and_then(Value::as_bool).unwrap_or(false);
        classification = match comparison {
            "equal" => "complete".to_owned(),
            "superset" => "normal_lag".to_owned(),
            "subset" => {
                missing_heads += count.saturating_sub(local_digests.len()).max(1);
                "INCOMPLETE".to_owned()
            }
            _ if unreachable => "divergent-branch".to_owned(),
            _ => {
                missing_heads += 1;
                "INCOMPLETE".to_owned()
            }
        };
    }
    for digests in &published_digest_sets {
        if !digests.is_subset(&local_digests) {
            missing_heads += digests.difference(&local_digests).count();
            if classification != "INCOMPLETE" {
                classification = "INCOMPLETE".to_owned();
            }
        }
    }
    let attributes_effective = repo.attributes_effective().unwrap_or(false);
    let index_matches = repo.index_cache_matches()?;
    if index_matches == Some(false) {
        repo.update_index_cache()?;
    }
    let cache_checkpoint = repo.local_dir().join("fsck-checkpoint.json");
    let checkpoint = std::fs::read(&cache_checkpoint).ok().and_then(|bytes| crate::json::parse_strict_value(&bytes).ok());
    let manifest_heads = repo.manifest_heads()?;
    let head = repo.revision().unwrap_or_default();
    let incremental_possible = !full && checkpoint.as_ref().is_some_and(|c| crate::json::get_str(c, "revision") == Some(head.as_str()) || crate::json::get_array(c, "manifest_heads").is_some_and(|h| !h.is_empty()));
    let mode = if full || !incremental_possible { "full" } else { "incremental" };
    // Revocation cascade: every fact must be rechecked under the current cursor
    // within 120 s at the ceiling; otherwise the typed limit state persists.
    let elapsed = started.elapsed();
    let cascade_incomplete = elapsed.as_secs() >= 120;
    let unknown_records: Vec<Value> = context.trust.unknowns.iter().map(|u| json!({"kind": u.get("kind").cloned().unwrap_or(Value::Null), "owner_role": u.get("owner_role").cloned().unwrap_or(Value::Null)})).collect();
    let mut unknowns = unknown_records;
    if expired_publication {
        unknowns.push(json!({"kind": "publication", "owner_role": "company-steward"}));
    }
    if classification == "INCOMPLETE" {
        unknowns.push(json!({"kind": "completeness", "owner_role": "repository-maintainer"}));
    }
    let admitted_paths: Vec<Value> = events.iter().filter(|e| !e.file.path_alias && e.verification == Some(Verification::Verified)).map(|e| json!({"path": format!(".kin/events/{}", e.file.relative.to_string_lossy()), "digest": e.file.digest})).collect();
    let store_digest = crate::hash::sha256_text(&local_digests.iter().cloned().collect::<Vec<_>>().join("\n"));
    let certificate_conflict = repo.kin.join("certificate.json").exists() && repo.kin.join("certificate-second.json").exists();
    let digest_attribution = if context.trust.company_reachable == Some(false) { "none" } else if counts.signature_invalid > 0 || counts.malformed > 0 { "client" } else { "none" };
    let lock_path = repo.common_dir.join(format!("guildhall-{uuid}.lock"));
    crate::paths::write_atomic(&cache_checkpoint, &crate::json::canonical_bytes(&json!({"revision": head, "manifest_heads": manifest_heads, "verified_at": now, "store_digest": store_digest})), 0o600, false)?;
    let mut result = json!({
        "status": "ok",
        "mode": mode,
        "full": full || mode == "full",
        "as_of": as_of.as_of,
        "as_of_source": as_of.as_of_source,
        "repository_uuid": uuid,
        "event_count": counts.total_files,
        "counts": counts.to_value(),
        "manifest_count": manifest_count,
        "manifest_lineage_count": manifest_heads.len().max(if manifest_count > 0 { 1 } else { 0 }),
        "manifest_heads": manifest_heads,
        "manifest_problems": manifest_problems,
        "manifest_comparison": {"classification": classification, "missing_heads": missing_heads, "expired_publication": expired_publication, "published_observations": published.len()},
        "manifest_relations": {"superset": "normal_lag", "missing_head": "INCOMPLETE", "expired_owner": "company-steward", "incomparable_local_only": "divergent-branch"},
        "admitted_paths": admitted_paths,
        "foreign_paths": counts.foreign_paths,
        "ineffective_git_attributes": !attributes_effective,
        "index_cache_byte_equivalent": index_matches,
        "cascade_state": if cascade_incomplete { "REVOCATION_CASCADE_INCOMPLETE" } else { "complete" },
        "unchecked_facts_withheld": cascade_incomplete,
        "cascade_seconds": elapsed.as_secs_f64(),
        "admission_lock_path": lock_path.to_string_lossy(),
        "store_digest": store_digest,
        "digest_attribution": {"owner_role": digest_attribution},
        "company_query_attempted": context.trust.company_query_attempted,
        "unknowns": unknowns,
        "sparse_checkout": sparse,
        "shallow": repo.is_shallow(),
        "certificate": {"valid": context.trust.certificate_valid, "reason": context.trust.certificate_reason, "foreign_paths": context.trust.foreign_certificate_paths, "conflict": certificate_conflict}
    });
    let typed_failure = if certificate_conflict {
        Some(ContractError::integrity("DIGEST_MISMATCH", "two certificates appear under .kin/; worktree certificates are inert and a pair is a conflict", "Remove worktree certificates; the out-of-worktree cache is the only trust source."))
    } else if counts.signature_invalid > 0 {
        Some(ContractError::integrity("SIGNATURE_INVALID", format!("{} event(s) fail domain-separated signature verification", counts.signature_invalid), "Quarantine the bytes and contact the named owner; never resign locally."))
    } else if counts.malformed > 0 || counts.path_alias > 0 {
        Some(ContractError::integrity("DIGEST_MISMATCH", format!("{} malformed and {} alias-path event file(s) under .kin/events", counts.malformed, counts.path_alias), "Run full fsck and repair the content-addressed event tree; only computed lowercase digest paths admit."))
    } else if !manifest_problems.is_empty() {
        Some(ContractError::integrity("MANIFEST_INCOMPLETE", format!("{} manifest problem(s)", manifest_problems.len()), "Fetch full history/.kin or ask the maintainer to reconcile the signed head set."))
    } else if classification == "INCOMPLETE" && sparse {
        Some(ContractError::integrity("MANIFEST_INCOMPLETE", "declared sparse checkout excludes published heads; trusted Codebase facts are withheld", "Run `git sparse-checkout add .kin` to restore the shared state.").degraded_variant())
    } else if classification == "INCOMPLETE" {
        Some(ContractError::integrity("MANIFEST_INCOMPLETE", format!("{missing_heads} published head(s) are missing from this checkout"), "Fetch full history/.kin, or ask the maintainer to reconcile the signed head set."))
    } else if counts.foreign > 0 && context.trust.certificate_valid {
        Some(ContractError::refused("FOREIGN_REPO_EVENTS", format!("{} event(s) bind another repository UUID or store", counts.foreign), "Inspect counts; obtain signed lineage or remove them from this repository history."))
    } else if cascade_incomplete {
        Some(ContractError::limit("revocation cascade did not complete within 120 seconds; unchecked facts remain withheld", json!({"remaining_count": counts.total_files, "refused_count": counts.total_files})))
    } else if counts.total_files > crate::codebase::EVENT_CEILING {
        Some(ContractError::limit("the .kin/ store exceeds the 10,000-event ceiling; intake refuses new writes while diagnosis remains available", json!({"event_count": counts.total_files, "omitted_count": counts.total_files - crate::codebase::EVENT_CEILING, "refused_count": 0})))
    } else {
        None
    };
    if let Some(error) = typed_failure {
        result["status"] = Value::String("failed".to_owned());
        result["error"] = crate::output::error_document(&error)["error"].clone();
        crate::output::emit(&result, json_output);
        return Err(error);
    }
    if !context.trust.certificate_valid {
        result["status"] = Value::String("unverified".to_owned());
    }
    crate::output::emit(&result, json_output);
    Ok(())
}

/// Convenience for other modules: repository path default.
pub fn repo_arg(repo: Option<PathBuf>) -> PathBuf {
    repo.unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

/// Compatibility helpers for modules that work from a repository path.
pub fn repository_id(repo: &Path) -> Result<String, ContractError> {
    let repository = crate::codebase::Repository::discover(repo)?;
    repository
        .uuid_hint()
        .map(str::to_owned)
        .ok_or_else(|| ContractError::repo_uninitialized(&repository.root))
}

pub fn git_revision(repo: &Path) -> Result<String, ContractError> {
    crate::codebase::Repository::discover(repo)?.revision()
}

pub fn git_branch(repo: &Path) -> Result<String, ContractError> {
    crate::codebase::Repository::discover(repo)?.branch()
}

/// Verified fact events (for callers that need the admitted list).
pub fn verified_facts(events: &[LoadedEvent]) -> Vec<&FactEvent> {
    events
        .iter()
        .filter(|item| item.verification == Some(Verification::Verified))
        .filter_map(|item| match &item.parsed {
            ParsedEvent::Fact(event) => Some(event),
            _ => None,
        })
        .collect()
}

pub fn unknown_events(events: &[LoadedEvent]) -> Vec<&UnknownEvent> {
    events
        .iter()
        .filter_map(|item| match &item.parsed {
            ParsedEvent::Unknown(unknown) => Some(unknown),
            _ => None,
        })
        .collect()
}

pub fn current_facts_only(view: &crate::reducer::CurrentView) -> Vec<&CurrentFact> {
    view.facts.iter().filter(|fact| fact.status == "current" && fact.trust == "trusted").collect()
}
