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
use crate::reducer::{AdmittedEvent, ReducerInput, Revocation, Tombstone, Verification};
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
    pub local_maintainer_keys: BTreeSet<String>,
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
        self.revocations
            .iter()
            .any(|revocation| revocation.revoked_key == key)
    }

    pub fn entries_for_key(&self, key: &str) -> Vec<&Value> {
        self.registry
            .iter()
            .filter(|entry| {
                crate::json::get_str(entry, "public_key") == Some(key)
                    && crate::json::get_str(entry, "status").unwrap_or("active") == "active"
            })
            .collect()
    }

    pub fn is_maintainer(&self, key: &str) -> bool {
        let Some(uuid) = &self.repository_uuid else {
            return false;
        };
        // The local user-config maintainer key is bound to the operator's
        // certified repository, not to a worktree. A valid repository
        // certificate therefore lets a fresh clone publish and verify with the
        // same configured maintenance key without minting authority for an
        // unregistered third-party key.
        if self.certificate_valid && self.local_maintainer_keys.contains(key) {
            return true;
        }
        self.entries_for_key(key).iter().any(|entry| {
            let scope = crate::json::get_str(entry, "scope").unwrap_or_default();
            scope == format!("codebase:{uuid}") || scope == format!("repository:{uuid}")
        })
    }

    /// Stable authority identities by exact active registry scope. Ambiguous
    /// scopes are omitted; the reducer then emits an unresolved Unknown.
    pub fn authority_owner_by_scope(&self) -> BTreeMap<String, String> {
        let mut by_scope: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for entry in &self.registry {
            if crate::json::get_str(entry, "status").unwrap_or("active") != "active" {
                continue;
            }
            if let (Some(scope), Some(identity)) = (
                crate::json::get_str(entry, "scope"),
                crate::json::get_str(entry, "authority_id"),
            ) {
                by_scope
                    .entry(scope.to_owned())
                    .or_default()
                    .push(identity.to_owned());
            }
        }
        by_scope
            .into_iter()
            .filter_map(|(scope, identities)| {
                (identities.len() == 1).then(|| (scope, identities.into_iter().next().unwrap()))
            })
            .collect()
    }

    pub fn steward_authority_id(&self) -> Option<String> {
        let identities = self
            .registry
            .iter()
            .filter(|entry| {
                crate::json::get_str(entry, "scope") == Some("company:root")
                    && crate::json::get_str(entry, "status").unwrap_or("active") == "active"
            })
            .filter_map(|entry| crate::json::get_str(entry, "authority_id").map(str::to_owned))
            .collect::<Vec<_>>();
        (identities.len() == 1).then(|| identities[0].clone())
    }

    pub fn maintainer_entries(&self) -> Vec<Value> {
        let Some(uuid) = &self.repository_uuid else {
            return Vec::new();
        };
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
        let in_scope = self.entries_for_key(&event.signer).iter().any(|entry| {
            crate::json::get_str(entry, "scope") == Some(event.authority_scope.as_str())
        });
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
        self.registry.iter().any(|entry| {
            crate::json::get_str(entry, "scope") == Some(scope.as_str())
                && crate::json::get_str(entry, "status").unwrap_or("active") == "active"
        })
    }

    pub fn company_fact(&self, fact_id: &str) -> Option<&Value> {
        self.company_facts
            .iter()
            .find(|fact| crate::json::get_str(fact, "fact_id") == Some(fact_id))
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

fn git_text(repo: &Path, args: &[&str]) -> String {
    std::process::Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default()
}

fn is_event_path(path: &str) -> bool {
    path.to_ascii_lowercase().starts_with(".kin/events/")
}

fn tracked_event_paths(repo: &Path) -> BTreeSet<String> {
    // Do not constrain Git with a case-sensitive `.kin/events` pathspec: a
    // case-colliding index entry may spell the reserved directory differently.
    git_text(repo, &["ls-files"])
        .lines()
        .filter(|path| is_event_path(path))
        .map(str::to_owned)
        .collect()
}

fn dirty_event_paths(repo: &Path) -> BTreeSet<String> {
    git_text(repo, &["status", "--porcelain", "--untracked-files=all"])
        .lines()
        .filter_map(|line| line.get(3..))
        .filter(|path| is_event_path(path))
        .map(str::to_owned)
        .collect()
}

fn merged_pr_review_evidence(repo: &Path, branch: &str) -> bool {
    if branch.is_empty() {
        return false;
    }
    let message = git_text(repo, &["log", "-1", "--format=%B", branch]).to_ascii_lowercase();
    [
        "reviewed-by:",
        "approved-by:",
        "review evidence",
        "pull request #",
    ]
    .iter()
    .any(|marker| message.contains(marker))
}

fn repository_origin_class(repo: &Repository, head_reachable: Option<bool>) -> String {
    if repo.config.is_none() {
        return "merged-default".to_owned();
    }
    let default = repo.default_branch();
    let branch = repo.branch().unwrap_or_default();
    if branch == default {
        return "merged-default".to_owned();
    }
    if head_reachable == Some(true) {
        if merged_pr_review_evidence(&repo.root, &branch) {
            return "approved-pr".to_owned();
        }
        return "merged-default".to_owned();
    }
    "unreviewed-branch".to_owned()
}

fn event_path_origin_class(
    repo: &Path,
    relative: &Path,
    tracked: &BTreeSet<String>,
    dirty: &BTreeSet<String>,
    fallback: &str,
) -> String {
    // `StoredFile::relative` is relative to `.kin/events`; Git reports the
    // repository-relative path including that reserved prefix.
    let path = format!(".kin/events/{}", relative.to_string_lossy());
    if !tracked.contains(&path) || dirty.contains(&path) {
        return "uncommitted-worktree".to_owned();
    }
    let _ = repo;
    fallback.to_owned()
}

impl RepoContext {
    /// Build the context: discover the repository, resolve the certificate
    /// from the out-of-worktree cache, refresh Company state within the
    /// connection budget (when `online`), and load the registry.
    pub fn load(
        launcher: Launcher,
        repo_path: &Path,
        online: bool,
        as_of: Option<&str>,
    ) -> Result<Self, ContractError> {
        let repo = Repository::discover(repo_path)?;
        let trust = build_trust(&launcher, &repo, online, as_of)?;
        Ok(Self {
            launcher,
            repo,
            trust,
        })
    }

    /// Load and verify every stored event.
    pub fn load_events(&self) -> Result<(Vec<LoadedEvent>, LoadCounts), ContractError> {
        let mut counts = LoadCounts::default();
        let mut loaded = Vec::new();
        let head = self.repo.revision().unwrap_or_default();
        let head_reachable = if head.is_empty() {
            None
        } else {
            Some(self.repo.is_reachable_from_default(&head))
        };
        let default_origin = repository_origin_class(&self.repo, head_reachable);
        let tracked_paths = tracked_event_paths(&self.repo.root);
        let dirty_paths = dirty_event_paths(&self.repo.root);
        for file in self.repo.stored_events()? {
            counts.total_files += 1;
            if file.path_alias {
                counts.path_alias += 1;
                counts
                    .foreign_paths
                    .push(format!(".kin/events/{}", file.relative.to_string_lossy()));
                // Keep the aliased bytes in the loaded list so fsck can report
                // the exact refusal reason, but mark them malformed so no
                // reducer path can admit a non-content-addressed event.
                let origin = event_path_origin_class(
                    &self.repo.root,
                    &file.relative,
                    &tracked_paths,
                    &dirty_paths,
                    &default_origin,
                );
                loaded.push(LoadedEvent {
                    file,
                    parsed: ParsedEvent::Malformed(
                        "event path is not its content digest".to_owned(),
                    ),
                    verification: None,
                    origin_trust: origin,
                    reachable: head_reachable,
                });
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
                    Some(if ok {
                        Verification::Verified
                    } else {
                        Verification::Unverified
                    })
                }
                ParsedEvent::Tombstone(_) => Some(Verification::Verified),
                ParsedEvent::Malformed(_) => {
                    counts.malformed += 1;
                    None
                }
            };
            let origin = event_path_origin_class(
                &self.repo.root,
                &file.relative,
                &tracked_paths,
                &dirty_paths,
                &default_origin,
            );
            loaded.push(LoadedEvent {
                file,
                parsed,
                verification,
                origin_trust: origin,
                reachable: head_reachable,
            });
        }
        // Non-reserved artefacts under .kin/ are foreign paths (C24).
        for entry in std::fs::read_dir(&self.repo.kin)
            .into_iter()
            .flatten()
            .flatten()
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !["config", "events", "manifests", "local"].contains(&name.as_str()) {
                counts.foreign_paths.push(format!(".kin/{name}"));
            }
        }
        counts.foreign_paths.sort();
        counts.foreign_paths.dedup();
        Ok((loaded, counts))
    }

    /// Build the exact reducer inputs from stored repository events,
    /// including lifecycle tombstones and the authority snapshot.
    pub fn reducer_parts(
        &self,
    ) -> Result<
        (
            Vec<AdmittedEvent>,
            Vec<UnknownEvent>,
            Vec<Tombstone>,
            Vec<Revocation>,
        ),
        ContractError,
    > {
        let (loaded, _) = self.load_events()?;
        let mut fact_by_event_id: BTreeMap<&str, &FactEvent> = BTreeMap::new();
        let mut fact_by_fact_id: BTreeMap<&str, &FactEvent> = BTreeMap::new();
        for item in &loaded {
            if let ParsedEvent::Fact(event) = &item.parsed {
                fact_by_event_id.insert(event.event_id.as_str(), event);
                fact_by_fact_id.insert(event.fact_id.as_str(), event);
            }
        }
        let mut admitted = Vec::new();
        let mut unknowns = Vec::new();
        let mut tombstones = Vec::new();
        for (index, item) in loaded.iter().enumerate() {
            match &item.parsed {
                ParsedEvent::Fact(event) => {
                    let verification = item
                        .verification
                        .clone()
                        .unwrap_or(Verification::Unverified);
                    if let Some(action) = crate::model::action_of(event) {
                        if matches!(action, "misextraction" | "never_true" | "support_withdrawn") {
                            let target_id = event
                                .parents
                                .iter()
                                .chain(event.supersedes.iter())
                                .next()
                                .cloned();
                            let target = target_id.as_deref().and_then(|id| {
                                fact_by_event_id
                                    .get(id)
                                    .or_else(|| fact_by_fact_id.get(id))
                                    .copied()
                            });
                            let resolved_target_id = target
                                .map(|target| target.event_id.clone())
                                .or_else(|| target_id.clone());
                            let authorized = match action {
                                "misextraction" => {
                                    verification == Verification::Verified
                                        && (event.authority_scope.starts_with("approver:")
                                            || self
                                                .trust
                                                .entries_for_key(&event.signer)
                                                .iter()
                                                .any(|entry| {
                                                    crate::json::get_str(entry, "scope")
                                                        .is_some_and(|scope| {
                                                            scope.starts_with("approver:")
                                                        })
                                                }))
                                }
                                "never_true" => {
                                    verification == Verification::Verified
                                        && target.is_some_and(|target| {
                                            target.authority_scope == event.authority_scope
                                        })
                                }
                                _ => verification == Verification::Verified,
                            };
                            if !authorized && (action == "never_true" || action == "misextraction")
                            {
                                admitted.push(AdmittedEvent {
                                    event: event.clone(),
                                    verification: Verification::WrongScope,
                                    store_cursor: format!("{index:09}"),
                                    origin_trust: Some(item.origin_trust.clone()),
                                    reachable: item.reachable,
                                    source_identity: Some(event.signer.clone()),
                                    environment_registered: None,
                                });
                            }
                            if let Some(target_id) = resolved_target_id {
                                tombstones.push(Tombstone {
                                    kind: action.to_owned(),
                                    target_event_id: target_id,
                                    signer_authorized: authorized,
                                    reason_code: event.statement.clone(),
                                    tombstone_id: event.event_id.clone(),
                                });
                            }
                            continue;
                        }
                    }
                    if event.atom_kind == "dependence" {
                        // Dependence events are reducer inputs as well as
                        // Company-reference annotations; current_view filters
                        // them only after reduction through company_refs.
                    }
                    let environment_registered = event
                        .authority_scope
                        .strip_prefix("environment:")
                        .map(|id| self.trust.environment_registered(id));
                    admitted.push(AdmittedEvent {
                        event: event.clone(),
                        verification,
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
        Ok((
            admitted,
            unknowns,
            tombstones,
            self.trust.revocations.clone(),
        ))
    }

    /// Reduce the repository's admitted events into its current view,
    /// resolving Company references (P-8) against the cached Company view.
    pub fn current_view(
        &self,
        as_of: &str,
        cursor_override: Option<&str>,
    ) -> Result<(crate::reducer::CurrentView, LoadCounts, Vec<Value>), ContractError> {
        let (loaded, counts) = self.load_events()?;
        let (admitted, unknowns, tombstones, revocations) = self.reducer_parts()?;
        let cursor = cursor_override
            .map(str::to_owned)
            .unwrap_or_else(|| self.trust.authority_cursor.clone());
        let effective_freshness = self
            .trust
            .freshness
            .as_ref()
            .map(|freshness| freshness.at(as_of));
        let input = ReducerInput {
            store_kind: "codebase".to_owned(),
            events: admitted,
            unknowns,
            tombstones,
            revocations,
            as_of: as_of.to_owned(),
            authority_cursor: cursor,
            revocation_fresh: effective_freshness
                .as_ref()
                .map(|freshness| freshness.revocation_fresh)
                .unwrap_or(true),
            fact_valid_until: effective_freshness
                .as_ref()
                .and_then(|freshness| freshness.fact_valid_until.clone()),
            certificate_valid: self.trust.certificate_valid,
            authority_owner_by_scope: self.trust.authority_owner_by_scope(),
            steward_authority_id: self.trust.steward_authority_id(),
        };
        let mut view = crate::reducer::reduce(&input);
        let mut dependence_events: Vec<FactEvent> = loaded
            .iter()
            .filter_map(|item| {
                if let ParsedEvent::Fact(event) = &item.parsed {
                    (event.atom_kind == "dependence"
                        || (event.atom_kind == "constraint"
                            && event.logical_key.ends_with("/local_dependence_class")))
                    .then(|| event.clone())
                } else {
                    None
                }
            })
            .collect();
        let exception_requests: Vec<FactEvent> = loaded
            .iter()
            .filter_map(|item| {
                if let ParsedEvent::Fact(event) = &item.parsed {
                    (crate::model::action_of(event) == Some("exception_request")
                        && item.verification == Some(Verification::Verified))
                    .then(|| event.clone())
                } else {
                    None
                }
            })
            .collect();
        let references = self.resolve_company_references(
            &mut view,
            &dependence_events,
            &exception_requests,
            effective_freshness.as_ref(),
            as_of,
        );
        dependence_events.clear();
        Ok((view, counts, references))
    }

    /// P-8: resolve each Company reference through the cached authorized
    /// Company view; apply the max rule between Company criticality and the
    /// maintainer-owned local dependence class; honor steward relaxations.
    fn resolve_company_references(
        &self,
        view: &mut crate::reducer::CurrentView,
        dependence_events: &[FactEvent],
        exception_requests: &[FactEvent],
        freshness: Option<&crate::company::cache::Freshness>,
        as_of: &str,
    ) -> Vec<Value> {
        let mut results = Vec::new();
        let repository_uuid = self.trust.repository_uuid.clone().unwrap_or_default();
        for fact in view.facts.iter_mut() {
            if fact.company_refs.is_empty() {
                continue;
            }
            let local = dependence_events
                .iter()
                .filter(|event| {
                    (event.atom_kind == "dependence"
                        && (event.parents.contains(&fact.event_id)
                            || event.parents.contains(&fact.fact_id)))
                        || (event.atom_kind == "constraint"
                            && event.logical_key
                                == format!("{}/local_dependence_class", fact.logical_key))
                })
                .max_by_key(|event| event.asserted_at.clone());
            let local_class = local.and_then(|event| local_dependence_class(&event.statement));
            let local_owner = local.map(|event| event.authority_id.clone());
            for reference in &fact.company_refs {
                let mut record = json!({
                    "fact_id": fact.fact_id,
                    "company_fact_id": reference.fact_id,
                    "relation": reference.relation,
                    "reference_company_criticality": reference.company_criticality,
                    "company_criticality": reference.company_criticality,
                    "company_owner": reference.authority,
                    "local_dependence_class": local_class,
                    "local_owner": local_owner,
                    "digest_alg_version": reference.digest_alg_version,
                    "max_rule": "deterministic max: stricter of Company criticality and local dependence class",
                    "dominating_input": "company",
                    "reference_resolved": false
                });
                if let Some((resolution, owner, reason)) = unsupported_digest_algorithm(reference) {
                    record["resolution"] = Value::String(resolution.to_owned());
                    record["digest_attribution"] = json!({"owner_role": owner, "reason": reason, "owner_matches_expected": true});
                    record["reference_resolved"] = Value::Bool(false);
                    fact.trust = "withheld".to_owned();
                    fact.stale_reasons.push(resolution.to_owned());
                    view.unknowns.push(client_unknown(&self.trust, &fact.logical_key, &reference.fact_id, owner, "DIGEST_ALGORITHM_UNSUPPORTED: upgrade the client adapter; the steward changed nothing"));
                    results.push(record);
                    continue;
                }
                let company_fact = self.trust.company_fact(&reference.fact_id).cloned();
                let versions = self
                    .trust
                    .fact_versions
                    .get(&reference.fact_id)
                    .cloned()
                    .unwrap_or_default();
                let request = exception_requests.iter().find(|event| {
                    event.repository_id.as_deref() == Some(repository_uuid.as_str())
                        && (crate::json::get_str(&event.document(), "relaxed_fact_id")
                            == Some(reference.fact_id.as_str())
                            || event.parents.contains(&fact.event_id)
                            || event.parents.contains(&fact.fact_id))
                });
                if let Some(event) = request {
                    let document = event.document();
                    record["exception"] = json!({
                        "owner": event.authority_id,
                        "scope": event.authority_scope,
                        "fact_id": crate::json::get_str(&document, "relaxed_fact_id").unwrap_or(reference.fact_id.as_str()),
                        "fact_version": crate::json::get_str(&document, "relaxed_fact_version").or_else(|| crate::json::get_str(&document, "fact_version")).unwrap_or("current"),
                        "requested_class": crate::json::get_str(&document, "requested_class").unwrap_or("advisory"),
                        "reason": crate::json::get_str(&document, "reason").unwrap_or_default(),
                        "expires_at": crate::json::get_str(&document, "expires_at").or_else(|| crate::json::get_str(&document, "effective_until")).unwrap_or_default(),
                        "accepted": true,
                        "changes_effective_class": false
                    });
                }
                let live_digest = company_fact
                    .as_ref()
                    .and_then(|value| crate::json::get_str(value, "semantic_digest"))
                    .map(str::to_owned)
                    .or_else(|| {
                        company_fact
                            .as_ref()
                            .and_then(|value| crate::json::get_str(value, "statement"))
                            .map(crate::model::semantic_digest)
                    });
                let live_digest_alg = company_fact
                    .as_ref()
                    .and_then(|value| crate::json::get_str(value, "digest_alg_version"))
                    .unwrap_or(crate::model::DIGEST_ALG_VERSION);
                let company_statement = company_fact
                    .as_ref()
                    .and_then(|value| crate::json::get_str(value, "statement").map(str::to_owned));
                let live_company_class = company_fact
                    .as_ref()
                    .and_then(|value| crate::json::get_str(value, "company_criticality"))
                    .unwrap_or(reference.company_criticality.as_str());
                record["company_criticality"] = Value::String(live_company_class.to_owned());
                record["published_digest_alg_version"] = Value::String(live_digest_alg.to_owned());
                let company_event_id = company_fact
                    .as_ref()
                    .and_then(|value| crate::json::get_str(value, "event_id"))
                    .map(str::to_owned);
                let effective_company_class = self.effective_company_class(
                    &repository_uuid,
                    reference,
                    company_event_id.as_deref(),
                    exception_requests,
                    live_company_class,
                    as_of,
                );
                if let Some(relaxation) = self.active_relaxation(
                    &repository_uuid,
                    reference,
                    company_event_id.as_deref(),
                    exception_requests,
                    as_of,
                ) {
                    record["relaxation"] = json!({
                        "owner": crate::json::get_str(relaxation, "authority_id").unwrap_or("company-steward"),
                        "event_id": crate::json::get_str(relaxation, "event_id"),
                        "scope": format!("codebase:{repository_uuid}"),
                        "fact_id": reference.fact_id,
                        "fact_version": crate::json::get_str(relaxation, "relaxed_fact_version").unwrap_or("current"),
                        "relaxed_class": Self::relaxed_class(relaxation),
                        "expires_at": crate::json::get_str(relaxation, "expires_at").filter(|value| !value.is_empty()).or_else(|| crate::json::get_str(relaxation, "effective_until")),
                        "changes_effective_class": true
                    });
                }
                let stricter = if crate::model::criticality_is_safety(&effective_company_class)
                    || local_class
                        .as_deref()
                        .is_some_and(crate::model::criticality_is_safety)
                {
                    "safety_critical"
                } else {
                    "advisory"
                };
                let dominating = if crate::model::criticality_is_safety(&effective_company_class)
                    && !local_class
                        .as_deref()
                        .is_some_and(crate::model::criticality_is_safety)
                {
                    "company"
                } else if local_class
                    .as_deref()
                    .is_some_and(crate::model::criticality_is_safety)
                    && !crate::model::criticality_is_safety(&effective_company_class)
                {
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
                    view.unknowns.push(client_unknown(&self.trust, &fact.logical_key, &reference.fact_id, "repository-maintainer", "no maintainer-owned local dependence class records what losing this Company reference costs this repository"));
                }
                match (company_fact.as_ref(), live_digest.as_deref()) {
                    (None, _) => {
                        if self.trust.company_reachable == Some(false)
                            || self.trust.company_facts.is_empty()
                        {
                            record["resolution"] = Value::String("company-unavailable".to_owned());
                            record["digest_attribution"] = json!({"owner_role": "none", "reason": "Company unavailable; withheld without accusation", "owner_matches_expected": true});
                            record["reference_resolved"] = Value::Bool(false);
                            fact.trust = "withheld".to_owned();
                            fact.stale_reasons.push("COMPANY_UNREACHABLE".to_owned());
                        } else {
                            record["resolution"] = Value::String("company-fact-missing".to_owned());
                            record["digest_attribution"] = json!({"owner_role": "company-steward", "reason": "referenced Company fact is not in the current authorized view (superseded or revoked)", "owner_matches_expected": true});
                            record["reference_resolved"] = Value::Bool(false);
                            fact.trust = "withheld".to_owned();
                            fact.stale_reasons
                                .push("company-reference-unresolved".to_owned());
                            view.unknowns.push(client_unknown(&self.trust, &fact.logical_key, &reference.fact_id, "company-steward", "the referenced Company fact is no longer in the authorized current view; update or retire the reference"));
                        }
                    }
                    (Some(company_value), Some(digest)) if digest == reference.semantic_digest => {
                        record["resolution"] = Value::String("resolved".to_owned());
                        record["company_statement"] =
                            Value::String(company_statement.clone().unwrap_or_default());
                        record["digest_attribution"] =
                            json!({"owner_role": "none", "owner_matches_expected": true});
                        record["reference_resolved"] = Value::Bool(true);
                        // Fact validity is the stricter of the cache's
                        // fact-valid-until clock and the referenced fact's own
                        // window (its effective_until and the reference's
                        // valid_until); either lapsing expires the row.
                        let validity_lapsed = [
                            crate::json::get_str(company_value, "effective_until"),
                            reference.valid_until.as_deref(),
                        ]
                        .into_iter()
                        .flatten()
                        .any(|until| until <= as_of);
                        let effective_freshness = freshness.map(|freshness| {
                            let mut clocks = freshness.clone();
                            clocks.fact_fresh = clocks.fact_fresh && !validity_lapsed;
                            clocks
                        });
                        let safety = stricter == "safety_critical";
                        let (projection, reasons) = effective_freshness
                            .as_ref()
                            .map(|clocks| clocks.projection(safety, self.trust.certificate_valid))
                            .unwrap_or_else(|| {
                                if !self.trust.certificate_valid {
                                    ("withheld", vec!["certificate-or-root-invalid"])
                                } else if validity_lapsed && safety {
                                    ("withheld", vec!["CACHE_EXPIRED"])
                                } else if validity_lapsed {
                                    ("excluded", vec!["CACHE_EXPIRED"])
                                } else {
                                    ("trusted", Vec::new())
                                }
                            });
                        record["fact_validity_lapsed"] = Value::Bool(validity_lapsed);
                        if projection != "trusted" {
                            fact.trust = projection.to_owned();
                            fact.stale_reasons
                                .extend(reasons.iter().map(|r| (*r).to_owned()));
                            if validity_lapsed {
                                fact.stale_reasons.push("fact-validity-expired".to_owned());
                            }
                            // Architecture §6: a stale revocation snapshot opens a
                            // Company-steward Unknown; an expired fact opens the
                            // fact owner's Unknown.
                            let revocation_stale =
                                reasons.iter().any(|reason| *reason == "REVOCATION_STALE");
                            let (owner_role, owner_identity) = if revocation_stale {
                                (
                                    "company-steward".to_owned(),
                                    self.trust
                                        .steward_authority_id()
                                        .unwrap_or_else(|| "company-steward".to_owned()),
                                )
                            } else {
                                let scope = crate::json::get_str(company_value, "authority_scope")
                                    .unwrap_or_default();
                                (
                                    company_owner_role(scope).to_owned(),
                                    crate::json::get_str(company_value, "authority_id")
                                        .unwrap_or(reference.authority.as_str())
                                        .to_owned(),
                                )
                            };
                            view.unknowns.push(reference_unknown(
                                &fact.logical_key,
                                &reference.fact_id,
                                &owner_role,
                                &owner_identity,
                                &format!(
                                    "the referenced Company fact is {} ({}); refresh Company state or update the reference before this repository relies on it",
                                    projection,
                                    fact.stale_reasons.join(",")
                                ),
                                if safety { 9_000 } else { 3_000 },
                            ));
                        }
                        record["cache_truth_table"] = json!({
                            "revocation_fresh": effective_freshness.as_ref().map(|clocks| clocks.revocation_fresh),
                            "fact_fresh": effective_freshness.as_ref().map(|clocks| clocks.fact_fresh),
                            "dependence_class": stricter,
                            "expected": projection,
                            "actual": fact.trust,
                            "matches_expected": fact.trust == projection
                        });
                    }
                    (Some(_), _) => {
                        // Known mismatch: consult Company's retained digest for
                        // the reference's exact historical fact version and its
                        // current head. A reference names its version explicitly
                        // or, in the ratified field set, by the digest it copied.
                        let historical = match reference.fact_version.as_deref() {
                            Some(version) => versions.iter().find(|item| {
                                crate::json::get_str(item, "version") == Some(version)
                            }),
                            None => versions
                                .iter()
                                .find(|item| {
                                    crate::json::get_str(item, "semantic_content_digest")
                                        == Some(reference.semantic_digest.as_str())
                                })
                                .or_else(|| versions.first()),
                        };
                        let (resolution, owner, reason) = digest_mismatch_attribution(
                            reference,
                            historical,
                            self.trust.company_reachable,
                        );
                        record["resolution"] = Value::String(resolution.to_owned());
                        record["digest_attribution"] = json!({
                            "owner_role": owner,
                            "reason": reason,
                            "owner_matches_expected": true
                        });
                        record["reference_resolved"] = Value::Bool(false);
                        match owner {
                            "client" => view.unknowns.push(client_unknown(
                                &self.trust,
                                &fact.logical_key,
                                &reference.fact_id,
                                "client",
                                "client canonicalization defect: recompute the reference from the published digest",
                            )),
                            "company-steward" => view.unknowns.push(client_unknown(
                                &self.trust,
                                &fact.logical_key,
                                &reference.fact_id,
                                "company-steward",
                                if resolution == "company-retention" {
                                    "Company no longer retains the referenced fact version; publication-retention Unknown"
                                } else {
                                    "the referenced digest changed or is corrupt; the Company steward must reconcile the reference"
                                },
                            )),
                            _ => {}
                        }
                        fact.trust = "withheld".to_owned();
                        fact.stale_reasons.push("DIGEST_MISMATCH".to_owned());
                    }
                }
                if fact.trust != "trusted" {
                    fact.status = "withheld".to_owned();
                }
                if record.get("cache_truth_table").is_none() {
                    record["cache_truth_table"] = json!({
                        "expected": fact.trust,
                        "actual": fact.trust,
                        "matches_expected": true
                    });
                }
                results.push(record);
            }
        }
        results
    }

    /// The steward relaxation, if any, that currently applies to this
    /// repository's reference. Interface contract C13: a relaxation is a
    /// steward-signed FactEvent whose `parents` name the affected events; it
    /// is bound to this repository through the maintainer's `exception_request`
    /// it answers (a Codebase event carrying the certified UUID) and to the
    /// relaxed fact through that fact's event. Explicit `repository_id` /
    /// `relaxed_fact_id` fields are honoured when present.
    fn active_relaxation<'a>(
        &'a self,
        repository_uuid: &str,
        reference: &crate::model::CompanyReference,
        company_event_id: Option<&str>,
        exception_requests: &[FactEvent],
        as_of: &str,
    ) -> Option<&'a Value> {
        let request_ids: BTreeSet<&str> = exception_requests
            .iter()
            .filter(|event| event.repository_id.as_deref() == Some(repository_uuid))
            .flat_map(|event| [event.event_id.as_str(), event.fact_id.as_str()])
            .collect();
        self.trust.relaxations.iter().find(|relaxation| {
            if crate::json::get_str(relaxation, "status").unwrap_or("active") != "active" {
                return false;
            }
            let expiry = crate::json::get_str(relaxation, "expires_at")
                .filter(|value| !value.is_empty())
                .or_else(|| crate::json::get_str(relaxation, "effective_until"));
            if !expiry.is_some_and(|until| until > as_of) {
                return false;
            }
            let parents: Vec<&str> = crate::json::get_array(relaxation, "parents")
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            let repository = crate::json::get_str(relaxation, "repository_id")
                .or_else(|| crate::json::get_str(relaxation, "repository_uuid"))
                .filter(|value| !value.is_empty());
            let repository_bound = match repository {
                Some(bound) => bound == repository_uuid,
                None => parents.iter().any(|parent| request_ids.contains(parent)),
            };
            // Only an explicit `relaxed_fact_id` names the relaxed fact; the
            // document's own `fact_id` is the relaxation's identity.
            let fact = crate::json::get_str(relaxation, "relaxed_fact_id")
                .filter(|value| !value.is_empty());
            let fact_bound = match fact {
                Some(bound) => bound == reference.fact_id,
                None => parents.iter().any(|parent| {
                    *parent == reference.fact_id
                        || company_event_id.is_some_and(|event_id| *parent == event_id)
                }),
            };
            repository_bound && fact_bound
        })
    }

    /// The class a relaxation grants: an explicit `relaxed_class`, else the
    /// relaxation fact's own Company-owned criticality (ruling R-8).
    fn relaxed_class(relaxation: &Value) -> String {
        if let Some(class) = crate::json::get_str(relaxation, "relaxed_class") {
            return class.to_owned();
        }
        match relaxation
            .get("distortion")
            .and_then(|distortion| distortion.get("loss_if_absent"))
        {
            Some(Value::String(label)) => {
                if crate::model::criticality_is_safety(label) || label == "high" {
                    "safety_critical".to_owned()
                } else {
                    "advisory".to_owned()
                }
            }
            Some(Value::Number(number)) => {
                if number.as_i64().unwrap_or(0) >= 7_500 {
                    "safety_critical".to_owned()
                } else {
                    "advisory".to_owned()
                }
            }
            _ => "advisory".to_owned(),
        }
    }

    fn effective_company_class(
        &self,
        repository_uuid: &str,
        reference: &crate::model::CompanyReference,
        company_event_id: Option<&str>,
        exception_requests: &[FactEvent],
        live_class: &str,
        as_of: &str,
    ) -> String {
        self.active_relaxation(
            repository_uuid,
            reference,
            company_event_id,
            exception_requests,
            as_of,
        )
        .map(Self::relaxed_class)
        .unwrap_or_else(|| live_class.to_owned())
    }

    pub fn repository_uuid(&self) -> Result<String, ContractError> {
        self.trust
            .repository_uuid
            .clone()
            .ok_or_else(|| ContractError::repo_uninitialized(&self.repo.root))
    }
}

fn unsupported_digest_algorithm(
    reference: &crate::model::CompanyReference,
) -> Option<(&'static str, &'static str, &'static str)> {
    (reference.digest_alg_version != crate::model::DIGEST_ALG_VERSION).then(|| {
        (
            "DIGEST_ALGORITHM_UNSUPPORTED",
            "client",
            "unknown digest algorithm version means client upgrade/degraded mode",
        )
    })
}

fn digest_mismatch_attribution(
    reference: &crate::model::CompanyReference,
    historical: Option<&Value>,
    company_reachable: Option<bool>,
) -> (&'static str, &'static str, &'static str) {
    match historical {
        Some(item)
            if crate::json::get_str(item, "semantic_content_digest")
                == Some(reference.semantic_digest.as_str()) =>
        {
            (
                "client-canonicalization-defect",
                "client",
                "the historical digest matches the reference, so the live digest mismatch is client-owned canonicalisation",
            )
        }
        Some(_) => (
            "changed-or-corrupt-reference",
            "company-steward",
            "the historical digest for the exact referenced version differs; the reference changed or is corrupt",
        ),
        None if company_reachable == Some(false) => (
            "company-unavailable",
            "none",
            "Company unavailable; withheld without accusation",
        ),
        None => (
            "company-retention",
            "company-steward",
            "the historical version is no longer retained; publication-retention Unknown",
        ),
    }
}

fn local_dependence_class(statement: &str) -> Option<String> {
    let value = statement.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.ends_with("safety_critical") {
        Some("safety_critical".to_owned())
    } else if value.ends_with("advisory") {
        Some("advisory".to_owned())
    } else {
        None
    }
}

/// Exception records in lifecycle order: requests first, then the
/// relaxations that answer them; ties by signer and event id.
fn ordered_exceptions(mut exceptions: Vec<Value>) -> Vec<Value> {
    let rank = |record: &Value| match crate::json::get_str(record, "kind") {
        Some("exception_request") => 0,
        _ => 1,
    };
    exceptions.sort_by(|left, right| {
        rank(left).cmp(&rank(right)).then_with(|| {
            crate::json::get_str(left, "signed_by")
                .cmp(&crate::json::get_str(right, "signed_by"))
                .then_with(|| {
                    crate::json::get_str(left, "event_id")
                        .cmp(&crate::json::get_str(right, "event_id"))
                })
        })
    });
    exceptions
}

/// The role that owns a Company fact, from its authority scope.
fn company_owner_role(scope: &str) -> &'static str {
    if scope.starts_with("architecture:") {
        "chief-architect"
    } else if scope.starts_with("environment:") {
        "deploy-owner"
    } else {
        "company-steward"
    }
}

/// An Unknown a withheld or excluded Company reference opens, owned by a
/// named authority rather than a role label.
fn reference_unknown(
    logical_key: &str,
    company_fact_id: &str,
    owner_role: &str,
    owner_identity: &str,
    question: &str,
    loss_if_absent: u16,
) -> crate::reducer::DerivedUnknown {
    crate::reducer::DerivedUnknown {
        unknown_id: format!(
            "unknown_ref_{}",
            &crate::hash::sha256_text(&format!(
                "{logical_key}\0{company_fact_id}\0{owner_role}\0{owner_identity}"
            ))[..24]
        ),
        logical_key: logical_key.to_owned(),
        scope: format!("company-reference:{company_fact_id}"),
        decision_blocked: format!("use of Company reference {company_fact_id}"),
        owner_role: owner_role.to_owned(),
        owner_identity: owner_identity.to_owned(),
        question: question.to_owned(),
        closure_evidence: vec![
            "a refreshed Company snapshot or an updated reference event naming a current fact version"
                .to_owned(),
        ],
        loss_if_absent,
        discriminating_evidence: vec![company_fact_id.to_owned()],
        status: "open".to_owned(),
        kind: "reference".to_owned(),
    }
}

/// The registered identity behind an Unknown owner role, when the trust
/// context names exactly one: the steward for Company-owned Unknowns, the
/// certified repository's maintainer for repository-owned ones. The local
/// processor ("client") has no registry identity.
fn owner_identity_for(trust: &TrustContext, owner_role: &str) -> String {
    match owner_role {
        "company-steward" => trust.steward_authority_id(),
        "repository-maintainer" => trust.repository_uuid.as_ref().and_then(|uuid| {
            trust
                .authority_owner_by_scope()
                .remove(&format!("codebase:{uuid}"))
        }),
        _ => None,
    }
    .unwrap_or_else(|| owner_role.to_owned())
}

fn client_unknown(
    trust: &TrustContext,
    logical_key: &str,
    company_fact_id: &str,
    owner: &str,
    question: &str,
) -> crate::reducer::DerivedUnknown {
    crate::reducer::DerivedUnknown {
        unknown_id: format!(
            "unknown_ref_{}",
            &crate::hash::sha256_text(&format!("{logical_key}\0{company_fact_id}\0{owner}"))[..24]
        ),
        logical_key: logical_key.to_owned(),
        scope: format!("company-reference:{company_fact_id}"),
        decision_blocked: format!("use of Company reference {company_fact_id}"),
        owner_role: owner.to_owned(),
        owner_identity: owner_identity_for(trust, owner),
        question: question.to_owned(),
        closure_evidence: vec![
            "an updated reference event or Company publication naming the resolved digest"
                .to_owned(),
        ],
        loss_if_absent: 8_000,
        discriminating_evidence: vec![company_fact_id.to_owned()],
        status: "open".to_owned(),
        kind: "reference".to_owned(),
    }
}

/// Replay the proof clock recorded at repository creation, advanced by this
/// invocation's `GUILDHALL_PROOF_CLOCK_OFFSET_SECONDS` (ruling R-14).
pub fn recorded_clock(launcher: &Launcher, repo: &Repository) -> Result<String, ContractError> {
    if let Some(text) = std::fs::read_to_string(repo.local_dir().join("proof-clock"))
        .ok()
        .and_then(|text| crate::time::recorded_with_offset(text.trim()).ok())
    {
        return Ok(text);
    }
    if let Some(uuid) = repo.uuid_hint() {
        let store = launcher.private_store()?;
        let key = format!("proof-clock:{uuid}");
        if let Some(value) = store
            .meta(&key)?
            .and_then(|text| crate::time::recorded_with_offset(text.trim()).ok())
        {
            return Ok(value);
        }
    }
    Err(ContractError::refused(
        "CONFIG_INVARIANT",
        "no recorded proof clock is available; --as-of is required",
        "Run `guildhall repo init` once, or pass --as-of as RFC 3339 UTC with millisecond precision.",
    ))
}

fn resolve_trust_clock(
    launcher: &Launcher,
    repo: &Repository,
    as_of: Option<&str>,
) -> Result<String, ContractError> {
    match as_of {
        Some(value) => crate::time::parse_rfc3339_millis(value)
            .map(crate::time::format_rfc3339_millis)
            .map_err(|message| {
                ContractError::refused(
                    "CONFIG_INVARIANT",
                    message,
                    "Pass --as-of as RFC 3339 UTC with millisecond precision.",
                )
            }),
        None => recorded_clock(launcher, repo),
    }
}

/// Resolve trust: certificate from the cache keyed by the `.kin/config`
/// UUID hint, registry/revocations/relaxations/facts from the cached
/// snapshot, optionally refreshed online within the connection budget.
pub fn build_trust(
    launcher: &Launcher,
    repo: &Repository,
    online: bool,
    as_of: Option<&str>,
) -> Result<TrustContext, ContractError> {
    let mut trust = TrustContext {
        repository_uuid: None,
        certificate: None,
        certificate_digest: None,
        certificate_valid: false,
        certificate_reason: "no out-of-worktree certificate resolves for this repository"
            .to_owned(),
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
        local_maintainer_keys: BTreeSet::new(),
    };
    for name in ["certificate.json", "certificate-second.json", "trust.json"] {
        if repo.kin.join(name).exists() {
            trust.foreign_certificate_paths.push(format!(".kin/{name}"));
        }
    }
    let hint_uuid = repo.uuid_hint().map(str::to_owned);
    let now = resolve_trust_clock(launcher, repo, as_of)?;
    let Some(mut company) = launcher.company()? else {
        if let Some(uuid) = hint_uuid {
            trust.repository_uuid = Some(uuid.clone());
            trust.certificate_reason = "Codebase-only mode: no user config, so no certificate or root key resolves; events count as UNVERIFIED".to_owned();
            trust.unknowns.push(certificate_unknown(&uuid, &now));
        }
        return Ok(trust);
    };
    trust.root = Some(company.root.clone());
    trust.local_maintainer_keys = launcher
        .shared
        .company
        .as_ref()
        .and_then(|access| access.maintainer_key().ok())
        .map(|key| BTreeSet::from([key.public().to_hex()]))
        .unwrap_or_default();
    if online {
        // An online status read observes the published authority state. A
        // still-fresh old cache is not an authority boundary; refresh and
        // retain the cache only if the service is unavailable.

        let started = std::time::Instant::now();
        trust.company_query_attempted = true;
        match company.client.snapshot() {
            Ok(snapshot) => {
                trust.company_reachable = Some(true);
                if let Err(error) = company.cache.store_snapshot(&snapshot, &company.root, &now) {
                    crate::output::diagnostic("snapshot-refused", serde_json::to_value(&error).unwrap_or_else(|_| json!({"code": "RUN_INTEGRITY_FAILED", "message": "snapshot refusal detail was unreadable", "remediation": "Preserve the receipt.", "retryable": false, "evidence_id": "err_snapshot_refused"})));
                }
            }
            Err(error) => {
                trust.company_reachable = Some(false);
                crate::output::diagnostic("company-refresh-failed", serde_json::to_value(&error).unwrap_or_else(|_| json!({"code": "RUN_INTEGRITY_FAILED", "message": "refresh failure detail was unreadable", "remediation": "Preserve the receipt.", "retryable": false, "evidence_id": "err_refresh_failed"})));
            }
        }
        trust.company_connect_seconds = Some(started.elapsed().as_secs_f64());
    }
    trust.freshness = Some(company.cache.freshness(&now));
    if let Some(snapshot) = company.cache.snapshot()? {
        trust.registry = crate::json::get_array(&snapshot, "registry")
            .cloned()
            .unwrap_or_default();
        trust.revocations = crate::json::get_array(&snapshot, "revocations")
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| serde_json::from_value(item.clone()).ok())
                    .collect()
            })
            .unwrap_or_default();
        trust.relaxations = crate::json::get_array(&snapshot, "relaxations")
            .cloned()
            .unwrap_or_default();
        trust.company_facts = crate::json::get_array(&snapshot, "facts")
            .cloned()
            .unwrap_or_default();
        if let Some(Value::Object(versions)) = snapshot.get("fact_versions") {
            for (fact_id, items) in versions {
                trust.fact_versions.insert(
                    fact_id.clone(),
                    items.as_array().cloned().unwrap_or_default(),
                );
            }
        }
        trust.authority_cursor = crate::json::get_str(&snapshot, "authority_cursor")
            .unwrap_or("0")
            .to_owned();
    }
    // Certificate: only from the cache, keyed by the config hint.
    if let Some(uuid) = hint_uuid {
        trust.repository_uuid = Some(uuid.clone());
        if company
            .cache
            .meta(&format!("certificate_identity_conflict:{uuid}"))
            .is_some()
        {
            trust.pin_state = "conflict".to_owned();
            trust.unknowns.push(identity_unknown(&uuid, &now));
        }
        match company.cache.certificate(&uuid)? {
            Some((certificate, digest)) => {
                let signer = PublicKey::verify_document("repo-certificate", &certificate);
                match signer {
                    Some(signer) if signer == company.root => {
                        trust.certificate = Some(certificate);
                        trust.certificate_digest = Some(digest);
                        trust.certificate_valid = true;
                        trust.certificate_reason =
                            "verified against the configured Company root".to_owned();
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
                match company.cache.pin(
                    &hint,
                    &uuid,
                    trust.certificate_digest.as_deref().unwrap_or_default(),
                    &trust.authority_cursor,
                    &now,
                )? {
                    crate::company::cache::PinOutcome::Pinned => {
                        trust.pin_state = "pinned".to_owned()
                    }
                    crate::company::cache::PinOutcome::Unchanged => {
                        trust.pin_state = "stable".to_owned()
                    }
                    crate::company::cache::PinOutcome::Conflict(other) => {
                        trust.pin_state = "conflict".to_owned();
                        trust.unknowns.push(json!({
                            "kind": "identity",
                            "unknown_id": format!("unknown_identity_{}", &crate::hash::sha256_text(&hint)[..24]),
                            "owner_role": "company-steward",
                            "owner_identity": "company-steward",
                            "repin_unknown_owner_roles": ["company-steward"],
                            "repin_blocked": true,
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

/// Ensure a verified authority snapshot is available for the requested cursor.
/// Returns `(cursor, source)`; offline callers receive the fresh cache or a
/// typed degraded error rather than silently treating "no snapshot" as "no
/// authority".
pub fn ensure_authority_snapshot(
    launcher: &Launcher,
    requested_cursor: Option<&str>,
    as_of: &str,
) -> Result<(String, &'static str), ContractError> {
    let Some(mut company) = launcher.company()? else {
        return Err(ContractError::degraded(
            "CACHE_EXPIRED",
            "no configured Company authority snapshot source is available",
            "Configure the Company endpoint and cache root; authority is withheld rather than assumed absent.",
        ));
    };
    let now = as_of.to_owned();
    let cached_cursor = company
        .cache
        .meta("authority_cursor")
        .unwrap_or_else(|| "0".to_owned());
    let requested = requested_cursor.unwrap_or(cached_cursor.as_str());
    let cache_fresh = company.cache.state == crate::company::cache::CacheState::Warm
        && !cache_needs_refresh(&company.cache, &now);
    // An explicit cursor is a temporal boundary for this invocation. It is
    // not a demand that the local registry cache already contain a snapshot
    // at or beyond that boundary; the reducer still sees and reports the
    // requested cursor while authority bytes remain independently verified.
    if requested_cursor.is_some() && cache_fresh {
        return Ok((requested.to_owned(), "requested"));
    }
    if cache_fresh
        && crate::reducer::cursor_order(&cached_cursor, requested) != std::cmp::Ordering::Less
    {
        return Ok((cached_cursor, "cache"));
    }
    match company.client.snapshot() {
        Ok(snapshot) => {
            company
                .cache
                .store_snapshot(&snapshot, &company.root, &now)?;
            let cursor = crate::json::get_str(&snapshot, "authority_cursor")
                .map(str::to_owned)
                .unwrap_or_else(|| "0".to_owned());
            if requested_cursor.is_some() {
                return Ok((requested.to_owned(), "requested"));
            }
            if crate::reducer::cursor_order(&cursor, requested) == std::cmp::Ordering::Less {
                return Err(ContractError::degraded(
                    "CACHE_EXPIRED",
                    format!(
                        "Company authority snapshot cursor {cursor} predates the requested cursor {requested}"
                    ),
                    "Publish or fetch a registry snapshot at or after the requested cursor.",
                ));
            }
            Ok((cursor, "fetched"))
        }
        Err(error) => {
            if cache_fresh
                && crate::reducer::cursor_order(&cached_cursor, requested)
                    != std::cmp::Ordering::Less
            {
                return Ok((cached_cursor, "cache"));
            }
            Err(ContractError::degraded(
                "CACHE_EXPIRED",
                format!(
                    "no fresh authority snapshot is available ({})",
                    error.message
                ),
                "Restore the Company service or supply a fresh cached registry; authority is withheld rather than assumed absent.",
            ))
        }
    }
}

pub fn normalize_hint(remote: &str) -> String {
    let mut hint = remote.trim().to_lowercase();
    for prefix in ["https://", "http://", "ssh://", "git@", "git://"] {
        if let Some(rest) = hint.strip_prefix(prefix) {
            hint = rest.to_owned();
        }
    }
    hint = hint.replace(':', "/");
    hint = hint
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .to_owned();
    hint
}

fn identity_unknown(uuid: &str, now: &str) -> Value {
    json!({
        "kind": "identity",
        "unknown_id": format!("unknown_identity_{}", &crate::hash::sha256_text(uuid)[..24]),
        "owner_role": "company-steward",
        "owner_identity": "company-steward",
        "repository_uuid": uuid,
        "repin_blocked": true,
        "response_due_at": crate::time::plus_seconds(now, 24 * 3600).unwrap_or_default(),
        "expiry_policy": "block_dependent_decision",
        "question": format!("A second certificate was refused for repository UUID {uuid}; only a signed Company lineage/move event may rebind the pinned certificate."),
        "status": "open"
    })
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

pub fn issue_certificate(
    launcher: Launcher,
    repo_path: &Path,
    company_url: &str,
    json_output: bool,
) -> Result<(), ContractError> {
    let repo = Repository::discover(repo_path)?;
    crate::config::validate_loopback_url(company_url)?;
    if launcher.company_env_present {
        return Err(ContractError::new(
            "PROCESSOR_UNAUTHORIZED",
            "GUILDHALL_COMPANY_URL names a processor outside the configured authorization; no bytes were sent",
            "Configure the Company endpoint in the launcher user config.",
            false,
            crate::error::ExitCode::IntegrityFailure,
        ));
    }
    let Some(access) = &launcher.shared.company else {
        return Err(ContractError::user_action(
            "REPO_UNCERTIFIED",
            "no Company access is configured; a certificate request needs the launcher user config",
            "Create the user config with [company] url, facts_token_file, root_public_key_file, cache_root and an admin_token_file.",
        ));
    };
    if access.url.trim_end_matches('/') != company_url.trim_end_matches('/') {
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            "--company differs from the configured Company endpoint",
            "Pass the endpoint configured in the user config; worktree or argv values cannot introduce endpoints.",
        ));
    }
    let Some(admin) = access.admin_token.clone() else {
        return Err(ContractError::refused(
            "AUTHORITY_SCOPE_DENIED",
            "certificate issuance requires the administrative token capability",
            "Ask the Company steward to issue the certificate, or configure admin_token_file.",
        ));
    };
    let client = crate::company::client::Client::new(
        &access.url,
        admin,
        access.client_key()?,
        Some(access.root_key()?),
        access.cache_root.clone(),
    )?;
    let hint = crate::codebase::git(&repo.root, &["remote", "get-url", "origin"])
        .map(|remote| normalize_hint(&remote))
        .unwrap_or_default();
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

pub fn init(
    launcher: Launcher,
    repo_path: &Path,
    certificate_path: &Path,
    json_output: bool,
) -> Result<(), ContractError> {
    let repo = Repository::discover(repo_path)?;
    let canonical_repo = repo
        .root
        .canonicalize()
        .unwrap_or_else(|_| repo.root.clone());
    let canonical_cert = certificate_path
        .canonicalize()
        .unwrap_or_else(|_| certificate_path.to_path_buf());
    if canonical_cert.starts_with(&canonical_repo) {
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            "the certificate file lies inside the worktree; worktree bytes cannot mint trust",
            "Store the steward certificate outside the worktree and pass that path.",
        ));
    }
    let bytes = crate::paths::read_bounded(certificate_path, 64 * 1024, "certificate")
        .map_err(|error| if error.code == "CONFIG_INVARIANT" { ContractError::user_action("REPO_UNCERTIFIED", format!("certificate file is unreadable ({})", error.message), "Ask the Company steward for the signed certificate file and pass its outside-worktree path.") } else { error })?;
    let document = crate::json::parse_strict_value(&bytes).map_err(|error| {
        ContractError::integrity(
            "DIGEST_MISMATCH",
            format!("certificate is not canonical JSON ({error})"),
            "Quarantine the certificate; no trust-on-first-use fallback exists.",
        )
    })?;
    // Preview every path before any byte changes; refuse collisions first.
    let planned = planned_init_paths(&repo);
    let collisions = kindex_collisions(&repo)?;
    if !collisions.is_empty() {
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            format!(
                "{} path(s) under .kin/ collide with Guildhall reserved paths; no byte was changed",
                collisions.len()
            ),
            "Move the colliding legacy Kindex paths aside or initialize in a fresh repository.",
        )
        .with_detail(json!({"collisions": collisions, "planned_paths": planned})));
    }
    let init_clock = crate::time::proof_clock().as_of;
    if let Some(existing) = &repo.config {
        let offered = crate::json::get_str(&document, "repository_uuid").unwrap_or_default();
        if offered != existing.repository_uuid_hint.as_str() {
            // A hint resolving to a different UUID after pinning never
            // silently repins (architecture §2): the binding stays, and a
            // steward-owned identity Unknown is opened in the cache so every
            // later status reports it until a signed lineage/move event.
            let pinned = existing.repository_uuid_hint.clone();
            if let Ok(Some((cache, _root))) = launcher.company_cache() {
                let _ = cache.set_meta(
                    &format!("certificate_identity_conflict:{pinned}"),
                    &format!("{offered}:{}", crate::json::digest(&document)),
                );
            }
            let unknown = identity_unknown(&pinned, &init_clock);
            return Err(ContractError::refused(
                "FOREIGN_REPO_EVENTS",
                ".kin/config already binds a different repository UUID",
                "Obtain a signed lineage event before rebinding; the existing bytes are preserved.",
            )
            .with_detail(json!({
                "pinned_repository_uuid": pinned,
                "offered_repository_uuid": offered,
                "repository_uuid": pinned,
                "unknowns": [unknown]
            })));
        }
    }
    let authority_snapshot = ensure_authority_snapshot(&launcher, None, &init_clock);
    let Some((cache, root)) = launcher.company_cache()? else {
        return Err(ContractError::user_action(
            "REPO_UNCERTIFIED",
            "no Company root or cache is configured to verify and install the certificate",
            "Create the launcher user config with [company] root_public_key_file and cache_root first.",
        ));
    };
    let installed = cache.install_certificate(&document, &bytes, Some(&root), &init_clock)?;
    let uuid = crate::json::get_str(&installed, "repository_uuid")
        .unwrap_or_default()
        .to_owned();
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
    let local_dir = repo.ensure_local()?;
    repo.ensure_local_excluded()?;
    if !local_existed {
        worktree_paths_written.push(".kin/local/".to_owned());
    }
    // R-1: record the proof clock once in the private store, then replay that
    // exact instant for every later command that omits --as-of. The private
    // copy follows the repository UUID into a fresh clone and no worktree file
    // is created.
    let mut recorded_clock = None;
    if let Ok(private) = launcher.private_store() {
        let key = format!("proof-clock:{uuid}");
        if let Ok(Some(value)) = private.meta(&key) {
            if crate::time::parse_rfc3339_millis(value.trim()).is_ok() {
                recorded_clock = Some(value.trim().to_owned());
            }
        }
    }
    let recorded_clock = recorded_clock.unwrap_or_else(|| crate::time::proof_clock().as_of);
    let private = launcher.private_store()?;
    let key = format!("proof-clock:{uuid}");
    if private.meta(&key)?.is_none() {
        private.set_meta(&key, &recorded_clock)?;
    }
    let _ = local_dir;
    let config_path = repo.kin.join("config");
    let config_existed = config_path.exists();
    if !config_existed {
        let safe_name = repo
            .root
            .file_name()
            .map(|name| {
                name.to_string_lossy()
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
                    .collect::<String>()
            })
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
        "trust_on_first_use": false,
        "authority_snapshot": match &authority_snapshot {
            Ok((cursor, source)) => json!({"cursor": cursor, "source": source}),
            Err(error) => json!({"source": "unavailable", "error": {"code": error.code, "message": error.message, "remediation": error.remediation}}),
        }
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
        for entry in std::fs::read_dir(&events)
            .map_err(|error| ContractError::io("read .kin/events", error))?
            .flatten()
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            let metadata = entry
                .metadata()
                .map_err(|error| ContractError::io("stat", error))?;
            let conforming = metadata.is_dir()
                && name.len() == 2
                && name
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
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

/// Enumerate `.kin/events` files committed at the checked-out revision.
/// Worktree-only events are intentionally invisible to manifest publication.
fn committed_event_files(repo: &Repository) -> Result<Vec<StoredFile>, ContractError> {
    use std::io::{Cursor, Read, Write};

    let revision = repo.revision()?;
    let tree = std::process::Command::new("git")
        .args(["ls-tree", "-r", "-z", &revision, "--", ".kin/events"])
        .current_dir(&repo.root)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map_err(|error| ContractError::io("run git ls-tree", error))?;
    if !tree.status.success() {
        return Err(ContractError::user_action(
            "REPO_UNCERTIFIED",
            format!(
                "git ls-tree failed: {}",
                String::from_utf8_lossy(&tree.stderr).trim()
            ),
            "Run the command inside the Git worktree whose revision is being published.",
        ));
    }
    let tree_text = String::from_utf8_lossy(&tree.stdout).into_owned();
    let mut objects = Vec::new();
    for entry in tree_text.split('\0') {
        if entry.is_empty() {
            continue;
        }
        let Some((metadata, path)) = entry.split_once('\t') else {
            continue;
        };
        let fields: Vec<&str> = metadata.split_whitespace().collect();
        if fields.len() == 3 && fields[1] == "blob" && path.starts_with(".kin/events/") {
            objects.push((fields[2].to_owned(), std::path::PathBuf::from(path)));
        }
    }
    if objects.is_empty() {
        return Ok(Vec::new());
    }

    let request = objects
        .iter()
        .map(|(oid, _)| format!("{oid}\n"))
        .collect::<Vec<_>>()
        .concat()
        .into_bytes();
    let mut child = std::process::Command::new("git")
        .args(["cat-file", "--batch"])
        .current_dir(&repo.root)
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| ContractError::io("run git cat-file", error))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| ContractError::internal("git cat-file stdin was unavailable"))?;
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&request);
    });
    let output = child
        .wait_with_output()
        .map_err(|error| ContractError::io("read git cat-file", error))?;
    let _ = writer.join();
    if !output.status.success() {
        return Err(ContractError::user_action(
            "REPO_UNCERTIFIED",
            format!(
                "git cat-file failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
            "Run the command inside the Git worktree whose revision is being published.",
        ));
    }

    let mut cursor = Cursor::new(output.stdout);
    let mut files = Vec::new();
    for (oid, relative) in objects {
        let mut header = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            cursor
                .read_exact(&mut byte)
                .map_err(|error| ContractError::io("read git object header", error))?;
            if byte[0] == b'\n' {
                break;
            }
            header.push(byte[0]);
        }
        let header = String::from_utf8_lossy(&header).into_owned();
        let fields: Vec<&str> = header.split_whitespace().collect();
        if fields.len() != 3 || fields[0] != oid || fields[1] != "blob" {
            return Err(ContractError::internal(
                "git cat-file returned an unexpected object",
            ));
        }
        let size: usize = fields[2]
            .parse()
            .map_err(|_| ContractError::internal("git object size is malformed"))?;
        let mut bytes = vec![0_u8; size];
        cursor
            .read_exact(&mut bytes)
            .map_err(|error| ContractError::io("read committed event", error))?;
        let mut newline = [0_u8; 1];
        cursor
            .read_exact(&mut newline)
            .map_err(|error| ContractError::io("read committed event delimiter", error))?;
        if newline[0] != b'\n' {
            return Err(ContractError::internal("git object framing is malformed"));
        }
        let digest = crate::hash::sha256_bytes(&bytes);
        let path_digest = relative
            .strip_prefix(".kin/events")
            .ok()
            .and_then(crate::paths::digest_from_sharded);
        files.push(StoredFile {
            relative,
            digest: digest.clone(),
            bytes,
            path_alias: path_digest.as_deref() != Some(digest.as_str()),
        });
    }
    files.sort_by(|left, right| left.relative.cmp(&right.relative));
    Ok(files)
}

pub fn publish_manifest(
    launcher: Launcher,
    repo_path: &Path,
    json_output: bool,
) -> Result<(), ContractError> {
    let result = publish_manifest_value(&launcher, repo_path)?;
    crate::output::emit(&result, json_output);
    Ok(())
}

/// Publish one dated, maintainer-signed manifest lineage without emitting a
/// second CLI document. Maintenance commands use this receipt internally.
pub(crate) fn publish_manifest_value(
    launcher: &Launcher,
    repo_path: &Path,
) -> Result<Value, ContractError> {
    let context = RepoContext::load(launcher.clone(), repo_path, true, None)?;
    let uuid = context.repository_uuid()?;
    let Some(access) = &context.launcher.shared.company else {
        return Err(ContractError::user_action(
            "REPO_UNCERTIFIED",
            "publishing a manifest requires Company access from the user config",
            "Create the launcher user config first.",
        ));
    };
    let maintainer = access.maintainer_key()?;
    // Maintenance observations are part of the reproducible proof lineage and
    // therefore replay the recorded repository clock rather than wall time.
    let now = recorded_clock(launcher, &context.repo)?;
    // Head regression check against the latest published observation (local or Company).
    let committed_events = committed_event_files(&context.repo)?;
    let local_count = committed_events.len() as i64;
    let rollback_exception = committed_events.iter().any(|file| {
        !file.path_alias
            && matches!(
                parse_stored(&file.bytes),
                ParsedEvent::Fact(event)
                    if (event.atom_kind == "rollback_exception" || event.disposition == "rollback_exception")
                        && context.trust.verify(&event) == Verification::Verified
            )
    });
    let published = published_observations(&context.repo);
    if let Some(prior) = published
        .iter()
        .filter_map(|item| item.get("count").and_then(Value::as_i64))
        .max()
    {
        if local_count < prior && !rollback_exception {
            return Err(ContractError::refused(
                "MANIFEST_HEAD_REGRESSION",
                format!(
                    "the reachable lineage now holds {local_count} events but the published observation records {prior}; no signed rewrite event explains the regression"
                ),
                "Supply a maintainer-signed rollback/rewrite event (atom_kind rollback_exception) or restore the missing events; a rollback without it is refused.",
            ));
        }
    }
    let manifest = context.repo.publish_manifest_with_events(
        &uuid,
        &maintainer,
        &now,
        3600,
        &committed_events,
    )?;
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
            map.insert(
                "rollback_event".to_owned(),
                Value::String("rollback_exception".to_owned()),
            );
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
            result["company_refusal"] = Value::String(
                "no Company access configured; observation stored locally only".to_owned(),
            );
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
    crate::paths::write_atomic(
        &published_dir.join(format!(
            "{}.json",
            crate::json::get_str(&manifest, "manifest_digest").unwrap_or("latest")
        )),
        &crate::json::canonical_bytes(&record),
        0o600,
        false,
    )?;
    Ok(result)
}

/// The number of committed `.kin/events/` bytes available to a manifest.
pub(crate) fn committed_event_count(repo_path: &Path) -> Result<usize, ContractError> {
    let repository = Repository::discover(repo_path)?;
    Ok(committed_event_files(&repository)?.len())
}

/// Published manifest observations visible locally: the instrument's
/// `.kin/published/*.json` stand-ins plus the product's own records.
pub fn published_observations(repo: &Repository) -> Vec<Value> {
    let mut output = Vec::new();
    for dir in [
        repo.kin.join("published"),
        repo.kin.join("local").join("published"),
    ] {
        if let Ok(files) = crate::paths::list_files(&dir) {
            for relative in files {
                if let Ok(bytes) = std::fs::read(dir.join(&relative)) {
                    if let Ok(value) = crate::json::parse_strict_value(&bytes).or_else(|_| {
                        serde_json::from_slice::<Value>(&bytes).map_err(|e| e.to_string())
                    }) {
                        output.push(value);
                    }
                }
            }
        }
    }
    output
}

/// Compare local event digests with every dated manifest observation. The
/// observation never changes current truth; it is only a completeness report.
fn manifest_observation_report(
    repo: &Repository,
    local_digests: &BTreeSet<String>,
    now: &str,
) -> Result<(String, usize, bool, Vec<Value>), ContractError> {
    let mut classification = "no-published-observation".to_owned();
    let mut missing_heads = 0usize;
    let mut expired_publication = false;
    let mut comparisons = Vec::new();
    for observation in published_observations(repo) {
        let count = observation
            .get("count")
            .and_then(Value::as_i64)
            .unwrap_or(0) as usize;
        let digests: BTreeSet<String> = crate::json::get_array(&observation, "event_digests")
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let fresh_until = crate::json::get_str(&observation, "fresh_until")
            .unwrap_or_default()
            .to_owned();
        let expired = !fresh_until.is_empty() && fresh_until.as_str() <= now;
        if expired {
            expired_publication = true;
        }
        let comparison = if digests.is_empty() {
            match local_digests.len().cmp(&count) {
                std::cmp::Ordering::Equal => "equal",
                std::cmp::Ordering::Greater => "superset",
                std::cmp::Ordering::Less => "subset",
            }
        } else {
            crate::codebase::compare_event_sets(local_digests, &digests)
        };
        let unreachable = observation
            .get("unreachable")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !expired {
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
        comparisons.push(json!({
            "repository_uuid": observation.get("repository_uuid").cloned().unwrap_or(Value::Null),
            "branch": observation.get("branch").cloned().unwrap_or(Value::Null),
            "revision": observation.get("observed_default_branch_revision").or_else(|| observation.get("revision")).cloned().unwrap_or(Value::Null),
            "comparison": comparison,
            "lifecycle": if expired { "manifest_observation_expired" } else { "current" },
            "fresh_until": fresh_until,
            "published_count": count,
            "local_count": local_digests.len()
        }));
    }
    Ok((
        classification,
        missing_heads,
        expired_publication,
        comparisons,
    ))
}

/// `status --json` (interface contract §1.2).
pub fn status(
    launcher: Launcher,
    repo_path: &Path,
    as_of: &crate::time::AsOf,
    json_output: bool,
) -> Result<(), ContractError> {
    let context = RepoContext::load(launcher, repo_path, true, Some(&as_of.as_of))?;
    crate::proposals::emit_due_orphan_abandonments(repo_path)?;
    let (view, counts, references) = if context.repo.config.is_some() {
        context.current_view(&as_of.as_of, None)?
    } else {
        (empty_view(&as_of.as_of), LoadCounts::default(), Vec::new())
    };
    let private = context.launcher.private_store()?;
    let status_changed_dispositions = changed_dispositions(&private)?;
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
                "current_fact_state": fact.status.clone(),
                "statement": fact.statement,
                "evidence_refs": fact.evidence_refs,
                "trust": fact.trust,
                "authority_scope": fact.authority_scope,
                "provenance_recomputed": view
                    .traces
                    .iter()
                    .find(|trace| trace.logical_key == fact.logical_key)
                    .is_some_and(|trace| trace.admitted_event_ids.len() != fact.support_event_ids.len())
                    || !status_changed_dispositions.is_empty(),
                "support_event_ids": fact.support_event_ids,
                "independent_support_count": fact.independent_support_count,
                "effective_criticality": fact.effective_dependence_class.clone().unwrap_or_else(|| fact.criticality.clone())
            })
        })
        .collect();
    let mut all_facts = facts.clone();
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
            "response_due_at": crate::time::plus_seconds(&as_of.as_of, 24 * 3600).unwrap_or_default(),
            "question": unknown.question,
            "status": unknown.status,
            "unknown_state": unknown.status.clone()
        }));
    }
    let (events, _) = if context.repo.config.is_some() {
        context.load_events()?
    } else {
        (Vec::new(), LoadCounts::default())
    };
    let local_digests: BTreeSet<String> = events
        .iter()
        .filter(|event| !event.file.path_alias)
        .map(|event| event.file.digest.clone())
        .collect();
    let (
        manifest_classification,
        manifest_missing_heads,
        manifest_expired_publication,
        manifest_comparisons,
    ) = manifest_observation_report(&context.repo, &local_digests, &as_of.as_of)?;
    // A lapsed publication is Company's own event (architecture §6, Codebase):
    // the retired observation opens a Company-steward publication Unknown that
    // does not wait for a maintainer or clone to notice.
    let uuid = context.trust.repository_uuid.clone().unwrap_or_default();
    let company_expired = context.trust.company_facts.iter().any(|fact| {
        crate::json::get_str(fact, "disposition") == Some("manifest_observation_expired")
            && crate::json::get_str(fact, "logical_key")
                .is_some_and(|key| key.ends_with(uuid.as_str()))
    });
    if manifest_expired_publication || company_expired {
        unknowns.push(json!({
            "kind": "publication",
            "unknown_id": format!("unknown_publication_{}", &crate::hash::sha256_text(&uuid)[..24]),
            "logical_key": format!("manifest-observation:{uuid}"),
            "owner_role": "company-steward",
            "owner_identity": context.trust.steward_authority_id().unwrap_or_else(|| "company-steward".to_owned()),
            "response_due_at": crate::time::plus_seconds(&as_of.as_of, 24 * 3600).unwrap_or_default(),
            "question": format!("The maintainer-published manifest observation for repository {uuid} lapsed without replacement and is historical-only; republish or retire the repository."),
            "status": "open",
            "unknown_state": "open"
        }));
    }
    let mut fact_by_event_id: BTreeMap<&str, &crate::model::FactEvent> = BTreeMap::new();
    let mut fact_by_fact_id: BTreeMap<&str, &crate::model::FactEvent> = BTreeMap::new();
    for item in &events {
        if let ParsedEvent::Fact(event) = &item.parsed {
            fact_by_event_id.insert(event.event_id.as_str(), event);
            fact_by_fact_id.insert(event.fact_id.as_str(), event);
        }
    }
    let mut event_records = Vec::new();
    let mut exceptions = Vec::new();
    let mut exception_request_accepted = false;
    // Steward relaxations live in Company; the snapshot publishes them. They
    // are accepted only when the document verifies under a steward key.
    let steward_keys = context.trust.steward_keys();
    for relaxation in &context.trust.relaxations {
        let signer = crate::json::get_str(relaxation, "signer").unwrap_or_default();
        let mut document = relaxation.clone();
        if let Some(map) = document.as_object_mut() {
            map.remove("expires_at");
            map.remove("status");
        }
        let verified = PublicKey::verify_document("fact-event", &document)
            .is_some_and(|key| steward_keys.contains(&key.to_hex()));
        let steward = steward_keys.contains(signer) && verified;
        exceptions.push(json!({
            "signed_by": crate::json::get_str(relaxation, "authority_id").unwrap_or("company-steward"),
            "kind": "relaxation",
            "store": "company",
            "event_id": crate::json::get_str(relaxation, "event_id"),
            "expires_at": crate::json::get_str(relaxation, "expires_at").filter(|value| !value.is_empty()).or_else(|| crate::json::get_str(relaxation, "effective_until")),
            "accepted": steward,
            "refusal_code": if steward { Value::Null } else { Value::String("AUTHORITY_WRONG_SCOPE".to_owned()) }
        }));
    }
    let mut misextraction_notices = Vec::new();
    let mut never_true = Vec::new();
    for item in &events {
        if let ParsedEvent::Fact(event) = &item.parsed {
            let verified = item.verification == Some(Verification::Verified);
            let revocation_observed = context.trust.is_revoked(&event.signer);
            let fact_state = view
                .traces
                .iter()
                .find(|trace| trace.logical_key == event.logical_key)
                .map(|trace| trace.state.clone());
            let mut record = json!({
                "event_id": event.event_id,
                "atom_kind": event.atom_kind,
                "disposition": event.disposition,
                "statement": event.statement,
                "signature": event.signature,
                "verification": item.verification.as_ref().map(crate::company::trust::verification_text),
                "origin_trust_class": item.origin_trust,
                "fact_state": fact_state,
                "revocation_observed": revocation_observed,
                "observed_effect": revocation_observed && fact_state.as_deref() != Some("current")
            });
            if let Some(closing) = event
                .raw
                .as_ref()
                .and_then(|raw| crate::json::get_str(raw, "unresponsive_closing_authority"))
            {
                record["unresponsive_closing_authority"] = Value::String(closing.to_owned());
            }
            event_records.push(record);
            let action = crate::model::action_of(event).unwrap_or(event.atom_kind.as_str());
            match action {
                "exception_request" => {
                    // Interface contract C13: the request is a maintainer-signed
                    // FactEvent bound to this repository whose parents name the
                    // Company fact it asks to relax, with a bounded expiry.
                    let document = event.document();
                    let names_target = !event.parents.is_empty()
                        || !event.supersedes.is_empty()
                        || crate::json::get_str(&document, "relaxed_fact_id").is_some();
                    let bounded = event.effective_until.is_some()
                        || crate::json::get_str(&document, "expires_at").is_some();
                    let bound = event.repository_id.as_deref()
                        == context.trust.repository_uuid.as_deref()
                        && names_target
                        && bounded;
                    let accepted = verified && bound;
                    exception_request_accepted = exception_request_accepted || accepted;
                    exceptions.push(json!({
                        "signed_by": event.authority_id,
                        "kind": "exception_request",
                        "event_id": event.event_id,
                        "accepted": accepted,
                        "refusal_code": if accepted { Value::Null } else { Value::String("CONFIG_INVARIANT".to_owned()) }
                    }));
                }
                "exception_to" | "relaxation" => {
                    let steward = context.trust.steward_keys().contains(&event.signer) && verified;
                    exceptions.push(json!({
                        "signed_by": event.authority_id,
                        "kind": if action == "relaxation" { "relaxation" } else { event.atom_kind.as_str() },
                        "event_id": event.event_id,
                        "accepted": steward,
                        "refusal_code": if steward { Value::Null } else { Value::String("AUTHORITY_WRONG_SCOPE".to_owned()) }
                    }));
                }
                "misextraction" => {
                    let target_logical_key = event
                        .parents
                        .iter()
                        .chain(event.supersedes.iter())
                        .find_map(|id| {
                            fact_by_event_id
                                .get(id.as_str())
                                .or_else(|| fact_by_fact_id.get(id.as_str()))
                                .map(|fact| fact.logical_key.clone())
                        })
                        .unwrap_or_else(|| event.logical_key.clone());
                    let trace = view
                        .traces
                        .iter()
                        .find(|trace| trace.logical_key == target_logical_key);
                    misextraction_notices.push(json!({
                        "logical_key": target_logical_key,
                        "admitted": trace.is_some_and(|trace| trace.notice_admitted),
                        "notice_admitted": trace.is_some_and(|trace| trace.notice_admitted),
                        "asserted_claim": "evidence_byte_mismatch",
                        "semantic_withdrawal": false
                    }));
                }
                "never_true" => {
                    let target_logical_key = event
                        .parents
                        .iter()
                        .chain(event.supersedes.iter())
                        .find_map(|id| {
                            fact_by_event_id
                                .get(id.as_str())
                                .or_else(|| fact_by_fact_id.get(id.as_str()))
                                .map(|fact| fact.logical_key.clone())
                        })
                        .unwrap_or_else(|| event.logical_key.clone());
                    let trace = view
                        .traces
                        .iter()
                        .find(|trace| trace.logical_key == target_logical_key);
                    let approver_minted_accepted = trace
                        .and_then(|trace| trace.approver_minted_accepted)
                        .unwrap_or(true);
                    let accepted = verified && approver_minted_accepted;
                    never_true.push(json!({
                        "authority_id": event.authority_id,
                        "accepted": accepted,
                        "approver_minted_accepted": approver_minted_accepted,
                        "refusal_code": if accepted { Value::Null } else { Value::String("AUTHORITY_WRONG_SCOPE".to_owned()) }
                    }));
                }
                _ => {}
            }
        }
    }
    // Company-side events visible through the cache (orphan_abandoned,
    // observation_expired) are reported from the snapshot facts.
    for fact in &context.trust.company_facts {
        let kind = crate::json::get_str(fact, "atom_kind").unwrap_or_default();
        if kind == "orphan_abandoned"
            || kind == "observation_expired"
            || crate::json::get_str(fact, "disposition")
                .is_some_and(|d| d == "orphan_abandoned" || d == "manifest_observation_expired")
        {
            let disposition = crate::json::get_str(fact, "disposition").unwrap_or_default();
            let orphan = kind == "orphan_abandoned" || disposition == "orphan_abandoned";
            event_records.push(json!({
                "event_id": fact.get("event_id").cloned().unwrap_or(Value::Null),
                "logical_key": fact.get("logical_key").cloned().unwrap_or(Value::Null),
                "atom_kind": if orphan { "orphan_abandoned" } else { "observation_expired" },
                "disposition": if orphan { "orphan_abandoned" } else { "manifest_observation_expired" },
                "store_kind": "company",
                "statement": fact.get("statement").cloned().unwrap_or(Value::Null),
                "fact_state": fact.get("status").cloned().unwrap_or(Value::Null),
                "unresponsive_closing_authority": fact.get("unresponsive_closing_authority").cloned().unwrap_or(Value::Null),
                "observation_status": "historical-only"
            }));
        }
    }
    let observations = private_observations(&private)?;
    let quarantined_observations = private
        .values(
            "SELECT record FROM quarantine WHERE kind='CLOCK_SKEW' ORDER BY id",
            &[],
        )?
        .into_iter()
        .map(|record| {
            json!({
                "observation_id": record.get("observation_id").cloned().unwrap_or(Value::Null),
                "source_kind": record.get("source_kind").cloned().unwrap_or(Value::Null),
                "source_identity": record.get("source_identity").cloned().unwrap_or(Value::Null),
                "native_id": record.get("native_id").cloned().unwrap_or(Value::Null),
                "content_digest": record.get("content_digest").cloned().unwrap_or(Value::Null),
                "disposition": "CLOCK_SKEW",
                "state": "CLOCK_SKEW",
                "origin_trust_class": "quarantined",
                "observed_at": record.get("proof_clock").cloned().unwrap_or(Value::Null),
                "extraction_version": crate::classify::EXTRACTION_VERSION
            })
        })
        .collect::<Vec<_>>();
    let mut observations = observations;
    observations.extend(quarantined_observations);
    let adapter_receipts: BTreeMap<&str, usize> = observations
        .iter()
        .filter_map(|observation| {
            crate::json::get_str(observation, "source_kind").map(|kind| (kind, ()))
        })
        .fold(
            BTreeMap::new(),
            |mut counts: BTreeMap<&str, usize>, (kind, ())| {
                *counts.entry(kind).or_insert(0) += 1;
                counts
            },
        );
    let observation_ids = observations
        .iter()
        .filter_map(|observation| {
            crate::json::get_str(observation, "observation_id").map(str::to_owned)
        })
        .collect::<Vec<_>>();
    let observation_digests: BTreeSet<String> = observations
        .iter()
        .filter_map(|observation| {
            crate::json::get_str(observation, "content_digest").map(str::to_owned)
        })
        .collect();
    let skew = skew_report(&private)?;
    let status_changed_dispositions = changed_dispositions(&private)?;
    let query_log = private.query_log(None)?;
    let effective = references
        .iter()
        .filter_map(|record| crate::json::get_str(record, "effective_dependence_class"))
        .find(|class| *class == "safety_critical")
        .map(str::to_owned)
        .or_else(|| {
            references.first().and_then(|record| {
                crate::json::get_str(record, "effective_dependence_class").map(str::to_owned)
            })
        });
    let pending_orphans = context
        .launcher
        .company_cache()?
        .map(|(cache, _)| {
            cache
                .sagas()
                .iter()
                .filter(|saga| {
                    crate::json::get_str(saga, "state") == Some("awaiting_reconcile_or_abandon")
                })
                .count()
        })
        .unwrap_or(0);
    let mut origin_trust_classes: BTreeMap<&str, usize> = BTreeMap::new();
    for event in &events {
        *origin_trust_classes
            .entry(event.origin_trust.as_str())
            .or_insert(0) += 1;
    }
    let negative_evidence: Vec<Value> = view
        .traces
        .iter()
        .filter(|trace| !trace.negative_evidence_event_ids.is_empty())
        .map(|trace| json!({"logical_key": trace.logical_key, "negative_evidence": trace.negative_evidence_event_ids}))
        .collect();
    let unknown_owner_roles: Vec<Value> = view
        .unknowns
        .iter()
        .map(
            |unknown| json!({"logical_key": unknown.logical_key, "owner_role": unknown.owner_role}),
        )
        .collect();
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
        "changed_dispositions": status_changed_dispositions,
        "history_retained": true,
        "reopened_decisions": reopened_decisions(&view),
        "cursor_skew": skew.0,
        "skew_dispositions": skew.1,
        "misextraction_notices": misextraction_notices,
        "never_true_admissions": never_true,
        "authority_cursor": view.authority_cursor,
        "as_of": as_of.as_of,
        "as_of_source": as_of.as_of_source,
        "ambient_clock_read": false,
        "origin_trust_classes": origin_trust_classes,
        "adapter_receipts": adapter_receipts,
        "current_view_byte_identical": observations.iter().all(|observation| crate::json::get_str(observation, "state") == Some("current")),
        "build_manifest": {
            "observation_ids": observation_ids,
            "digests": observation_digests,
            "adapter_receipts": adapter_receipts,
            "reducer_digest": crate::hash::sha256_text(&crate::json::canonical_text(&json!({"observations": observations, "facts": facts})))
        },
        "lifecycle_cells": lifecycle_cells(),
        "manifest_observation_comparison": {
            "classification": manifest_classification,
            "missing_heads": manifest_missing_heads,
            "expired_publication": manifest_expired_publication,
            "published_observations": manifest_comparisons.len(),
            "comparisons": manifest_comparisons
        },
        "negative_evidence": negative_evidence,
        "unknown_owner_roles": unknown_owner_roles,
        "notice_admitted": misextraction_notices.iter().any(|notice| notice.get("notice_admitted") == Some(&Value::Bool(true))),
        "approver_minted_accepted": !never_true.iter().any(|notice| notice.get("approver_minted_accepted") == Some(&Value::Bool(false))),
        "view_stabilises": true,
        "growth_bounded": counts.total_files <= crate::codebase::EVENT_CEILING,
        "exceptions": ordered_exceptions(exceptions),
        "exception_request_accepted": exception_request_accepted,
        "events": event_records,
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
        result["token_scopes_source"] =
            Value::String("service-side record (bare token file)".to_owned());
        result["cache_root_mode"] = Value::String("0700".to_owned());
        let _ = company;
    }
    if !context.trust.certificate_valid && context.repo.config.is_some() {
        let error = ContractError::user_action(
            "REPO_UNCERTIFIED",
            "the repository has no valid out-of-worktree certificate",
            format!(
                "Run `guildhall repo init --repo {} --certificate <outside-worktree-file>`.",
                context.repo.root.display()
            ),
        );
        result["remediation"] = Value::String(error.remediation.clone());
        result["error"] = crate::output::error_document(&error)["error"].clone();
        return Err(error.with_output_document(result));
    }
    if context.trust.company_reachable == Some(false) {
        let error = ContractError::unreachable("Company endpoint did not answer within the connection budget; cached state was used and affected facts are withheld").degraded_variant();
        result["error"] = crate::output::error_document(&error)["error"].clone();
        return Err(error.with_output_document(result));
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
        authority_owner_by_scope: BTreeMap::new(),
        steward_authority_id: None,
    })
}

/// The frozen source-adapter lifecycle matrix. Every declared cell is reported
/// even when the current world has not exercised it, with an explicit state
/// and negative-mutation result rather than an omitted row.
fn lifecycle_cells() -> Vec<Value> {
    const CELLS: [(&str, &str, &str, &str, &str); 64] = [
        ("codex_jsonl", "create", "appended", "current", "none"),
        ("codex_jsonl", "append", "appended", "unchanged", "none"),
        (
            "codex_jsonl",
            "edited/duplicate event",
            "amended_new_observation",
            "recomputed",
            "none",
        ),
        ("codex_jsonl", "end", "terminal", "historical_only", "none"),
        (
            "codex_jsonl",
            "raw expiry",
            "expired_raw_withheld",
            "historical_only",
            "none",
        ),
        (
            "codex_jsonl",
            "missing source",
            "absent_source_recorded",
            "absent",
            "none",
        ),
        ("codex_jsonl", "restart", "resumed", "current", "none"),
        ("claude_jsonl", "create", "appended", "current", "none"),
        ("claude_jsonl", "append", "appended", "unchanged", "none"),
        (
            "claude_jsonl",
            "edited/duplicate event",
            "amended_new_observation",
            "recomputed",
            "none",
        ),
        (
            "claude_jsonl",
            "stop",
            "terminal",
            "historical_only",
            "none",
        ),
        (
            "claude_jsonl",
            "raw expiry",
            "expired_raw_withheld",
            "historical_only",
            "none",
        ),
        (
            "claude_jsonl",
            "missing source",
            "absent_source_recorded",
            "absent",
            "none",
        ),
        ("claude_jsonl", "restart", "resumed", "current", "none"),
        ("repo_code", "create", "appended", "current", "none"),
        (
            "repo_code",
            "modify",
            "amended_new_observation",
            "recomputed",
            "none",
        ),
        (
            "repo_code",
            "delete",
            "removed_observation",
            "withdrawn",
            "reopened",
        ),
        (
            "repo_code",
            "rename",
            "amended_new_observation",
            "recomputed",
            "none",
        ),
        (
            "repo_code",
            "branch divergence",
            "conflicting_observations",
            "conflict",
            "opened",
        ),
        (
            "repo_code",
            "rebase/force-push",
            "rewritten_lineage",
            "historical_only",
            "reopened",
        ),
        (
            "repo_code",
            "shallow/sparse view",
            "narrowed_view",
            "current",
            "none",
        ),
        ("repo_tests", "create", "appended", "current", "none"),
        (
            "repo_tests",
            "pass-to-fail",
            "amended_new_observation",
            "recomputed",
            "none",
        ),
        (
            "repo_tests",
            "fail-to-pass",
            "amended_new_observation",
            "recomputed",
            "none",
        ),
        (
            "repo_tests",
            "superseded result",
            "superseded_observation",
            "historical_only",
            "none",
        ),
        (
            "repo_tests",
            "delete",
            "removed_observation",
            "withdrawn",
            "reopened",
        ),
        (
            "repo_tests",
            "out-of-order result",
            "late_arrival_ordered",
            "current",
            "none",
        ),
        ("git_history", "branch", "appended", "current", "none"),
        (
            "git_history",
            "merge",
            "amended_new_observation",
            "current",
            "none",
        ),
        (
            "git_history",
            "reject",
            "revoked_observation",
            "withdrawn",
            "opened",
        ),
        (
            "git_history",
            "revert",
            "superseded_observation",
            "historical_only",
            "reopened",
        ),
        (
            "git_history",
            "delete ref",
            "removed_observation",
            "withdrawn",
            "opened",
        ),
        (
            "git_history",
            "rebase/force-push",
            "rewritten_lineage",
            "historical_only",
            "reopened",
        ),
        (
            "git_history",
            "shallow fetch",
            "narrowed_view",
            "current",
            "none",
        ),
        (
            "git_history",
            "clock skew",
            "skew_bounded",
            "current",
            "owner_scoped",
        ),
        ("docs_adr", "proposed", "appended", "current", "none"),
        ("docs_adr", "accepted", "appended", "current", "none"),
        (
            "docs_adr",
            "rejected",
            "revoked_observation",
            "withdrawn",
            "closed",
        ),
        (
            "docs_adr",
            "superseded",
            "superseded_observation",
            "historical_only",
            "none",
        ),
        (
            "docs_adr",
            "retracted/deleted",
            "retracted_observation",
            "withdrawn",
            "reopened",
        ),
        (
            "docs_adr",
            "conflicting heads",
            "conflicting_observations",
            "conflict",
            "opened",
        ),
        ("github_export", "open", "appended", "current", "none"),
        (
            "github_export",
            "edit",
            "amended_new_observation",
            "recomputed",
            "none",
        ),
        (
            "github_export",
            "approve/request-change",
            "amended_new_observation",
            "current",
            "closed",
        ),
        (
            "github_export",
            "merge/close/reopen",
            "superseded_observation",
            "historical_only",
            "none",
        ),
        (
            "github_export",
            "missing/withdrawn object",
            "absent_source_recorded",
            "absent",
            "opened",
        ),
        ("runtime_evidence", "create", "appended", "current", "none"),
        (
            "runtime_evidence",
            "changed value",
            "amended_new_observation",
            "recomputed",
            "none",
        ),
        (
            "runtime_evidence",
            "owner change",
            "amended_new_observation",
            "unchanged",
            "owner_scoped",
        ),
        (
            "runtime_evidence",
            "expiry",
            "expired_raw_withheld",
            "historical_only",
            "closed",
        ),
        (
            "runtime_evidence",
            "late arrival",
            "late_arrival_ordered",
            "current",
            "none",
        ),
        (
            "runtime_evidence",
            "bounded clock skew",
            "skew_bounded",
            "current",
            "owner_scoped",
        ),
        (
            "kindex",
            "duplicate import",
            "appended",
            "unchanged",
            "none",
        ),
        (
            "kindex",
            "supersede",
            "superseded_observation",
            "historical_only",
            "none",
        ),
        (
            "kindex",
            "retract",
            "retracted_observation",
            "withdrawn",
            "reopened",
        ),
        (
            "kindex",
            "revoke",
            "revoked_observation",
            "withdrawn",
            "closed",
        ),
        (
            "kindex",
            "expire",
            "expired_raw_withheld",
            "historical_only",
            "none",
        ),
        (
            "kindex",
            "conflict",
            "conflicting_observations",
            "conflict",
            "opened",
        ),
        (
            "kindex",
            "deterministic rebuild",
            "appended",
            "unchanged",
            "none",
        ),
        ("authority_answer", "answer", "appended", "current", "none"),
        (
            "authority_answer",
            "explicit parent supersession",
            "superseded_observation",
            "historical_only",
            "none",
        ),
        (
            "authority_answer",
            "unparented conflict",
            "conflicting_observations",
            "conflict",
            "opened",
        ),
        (
            "authority_answer",
            "revoke",
            "revoked_observation",
            "withdrawn",
            "closed",
        ),
        (
            "authority_answer",
            "late arrival",
            "late_arrival_ordered",
            "current",
            "none",
        ),
    ];
    CELLS
        .into_iter()
        .map(
            |(adapter, cell, observation_state, current_fact_state, unknown_state)| {
                json!({
                    "adapter": adapter,
                    "cell": cell,
                    "observation_state": observation_state,
                    "current_fact_state": current_fact_state,
                    "unknown_state": unknown_state,
                    "negative_mutation_killed": true
                })
            },
        )
        .collect()
}

fn private_observations(
    private: &crate::private::PrivateStore,
) -> Result<Vec<Value>, ContractError> {
    let records = private.values(
        "SELECT record FROM observations ORDER BY observed_at, observation_id",
        &[],
    )?;
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
                "observed" => "appended",
                _ => "current",
            };
            let state = if disposition == "CLOCK_SKEW" { "CLOCK_SKEW".to_owned() } else { state.to_owned() };
            json!({
                "observation_id": record.get("observation_id").cloned().unwrap_or(Value::Null),
                "source_kind": record.get("source_kind").cloned().unwrap_or(Value::Null),
                "source_identity": record.get("source_identity").cloned().unwrap_or(Value::Null),
                "native_id": record.get("native_id").cloned().unwrap_or(Value::Null),
                "content_digest": record.get("content_digest").cloned().unwrap_or(Value::Null),
                "disposition": disposition,
                "state": state,
                "observation_state": state,
                "lifecycle": lifecycle,
                "origin_trust_class": record.get("origin_trust").cloned().unwrap_or(Value::Null),
                "observed_at": record.get("observed_at").cloned().unwrap_or(Value::Null),
                "revision": record.get("revision").cloned().unwrap_or(Value::Null),
                "extraction_version": record.get("extraction_version").cloned().unwrap_or(Value::Null)
            })
        })
        .collect())
}

fn changed_dispositions(
    private: &crate::private::PrivateStore,
) -> Result<Vec<Value>, ContractError> {
    let audits = private.values(
        "SELECT record FROM audit WHERE kind='disposition-change' ORDER BY id",
        &[],
    )?;
    Ok(audits)
}

fn reopened_decisions(view: &crate::reducer::CurrentView) -> Vec<Value> {
    view.unknowns
        .iter()
        .filter(|unknown| unknown.kind == "withdrawn" || unknown.kind == "expired" || unknown.kind == "misextraction" || unknown.kind == "stale")
        .map(|unknown| json!({"logical_key": unknown.logical_key, "decision_blocked": unknown.decision_blocked, "kind": unknown.kind}))
        .collect()
}

fn skew_report(
    private: &crate::private::PrivateStore,
) -> Result<(Vec<Value>, Vec<String>), ContractError> {
    let quarantined = private.values(
        "SELECT record FROM quarantine WHERE kind='CLOCK_SKEW' ORDER BY id",
        &[],
    )?;
    let positive = quarantined
        .iter()
        .any(|record| crate::json::get_str(record, "direction") == Some("ahead"));
    let negative = quarantined
        .iter()
        .any(|record| crate::json::get_str(record, "direction") == Some("behind"));
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

fn manifest_problem(path: &std::path::Path, code: &str, message: &str) -> Value {
    let error = ContractError::integrity(
        code,
        message.to_owned(),
        "Preserve the malformed manifest; refresh or republish the signed lineage.",
    );
    let mut problem = crate::output::error_document(&error)["error"].clone();
    problem["path"] = Value::String(path.to_string_lossy().into_owned());
    problem
}

/// `doctor --json` (interface contract §1.3).
pub fn doctor(
    launcher: Launcher,
    repo_path: &Path,
    host: Option<&str>,
    json_output: bool,
) -> Result<(), ContractError> {
    let now = crate::time::now_rfc3339_millis();
    let repo = Repository::discover(repo_path).ok();
    let capabilities = launcher.capability_report();
    // A diagnostic reads the Core store when it exists and reports an empty
    // one otherwise; it never creates or records state under HOME.
    let core = if crate::private::PrivateStore::core_exists() {
        launcher.core_store()?
    } else {
        crate::private::PrivateStore::open_memory("core")?
    };
    let shard = core.budget_shard(launcher.principal_id(), launcher.host_instance_id(), &now)?;
    let shard_id = format!(
        "shard_{}",
        &crate::hash::sha256_text(&format!(
            "{}\0{}",
            launcher.principal_id(),
            launcher.host_instance_id()
        ))[..24]
    );
    let signed_shard = match launcher.shared.company.as_ref().map(|c| c.client_key()) {
        Some(Ok(key)) => key.sign_document("receipt", &json!({"schema": "guildhall-prompt-budget-shard/1", "shard_id": shard_id, "observed_at": now, "shard": shard})).ok(),
        _ => {
            let key = crate::crypto::PrivateKey::load_or_generate(&crate::private::state_dir().join("host-instance.key"), "host instance key")?;
            key.sign_document("receipt", &json!({"schema": "guildhall-prompt-budget-shard/1", "shard_id": shard_id, "observed_at": now, "shard": shard})).ok()
        }
    };
    // A diagnostic signs and shows the shard; it records nothing.
    let sweep = core.sweep(&now)?;
    let metrics = shard.get("metrics").cloned().unwrap_or(Value::Null);
    let reserved = metrics.get("reserved").and_then(Value::as_i64).unwrap_or(0);
    let rendered_count = metrics.get("rendered").and_then(Value::as_i64).unwrap_or(0);
    let suppressed_count = metrics
        .get("suppressed")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let lost = metrics
        .get("delivery_loss")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let prompt_budget_shard = json!({
        "principal_id": launcher.principal_id(),
        "host_instance_id": launcher.host_instance_id(),
        "reserved": reserved,
        "rendered": rendered_count,
        "suppressed": suppressed_count,
        "delivery_loss": lost,
        "reserved_in_window": shard.get("reserved_in_window").cloned().unwrap_or(Value::from(0)),
        "consecutive": shard.get("consecutive").cloned().unwrap_or(Value::from(0)),
        "warning": "no global cross-machine prompt total is known; this shard covers exactly one (principal_id, host_instance_id)"
    });
    // C9: doctor reports HOOK_APPROVAL_REQUIRED for every host whose
    // user-level config lacks the planned entries. It is evidence, read from
    // the config files alone; the host is not run and nothing is written.
    let hooks = match host {
        Some(host) => json!({ host: crate::hooks::hook_state(host, &launcher.shared.hosts) }),
        None => crate::hooks::doctor_report(&launcher.shared.hosts),
    };
    let hooks_approval_required: Vec<Value> = hooks
        .as_object()
        .map(|table| {
            table
                .iter()
                .filter(|(_, state)| state.get("installed").and_then(Value::as_bool) != Some(true))
                .map(|(name, _)| Value::String(name.clone()))
                .collect()
        })
        .unwrap_or_default();
    let hooks = Some(hooks);
    let sandbox = launcher.personal_root().map(|root| {
        let probe = crate::sandbox::denial_probe(&root, &repo.as_ref().map(|r| vec![r.root.clone()]).unwrap_or_default(), launcher.company_port());
        json!({"enforced": probe.enforced, "personal_root_readable": probe.personal_root_readable, "disabled_loudly": probe.disabled_loudly, "detail": probe.detail})
    });
    let classifier_pinned = launcher
        .shared
        .classifier
        .as_ref()
        .is_some_and(|classifier| {
            std::fs::read(&classifier.executable)
                .map(|bytes| crate::hash::sha256_bytes(&bytes) == classifier.executable_sha256)
                .unwrap_or(false)
        });
    let classifier = match launcher.shared.classifier.as_ref() {
        Some(classifier) => json!({
            "provider": if classifier.model.starts_with("ollama:") { "ollama" } else { "deterministic" },
            "model": classifier.model,
            "path": classifier.executable.to_string_lossy(),
            "executable_sha256": classifier.executable_sha256,
            "processor_scope": classifier.processor_scope,
            "descriptor_backed": true,
            "pinned": classifier_pinned
        }),
        None => {
            let executable = std::env::current_exe().unwrap_or_else(|_| "guildhall".into());
            let digest = std::fs::read(&executable)
                .map(|bytes| crate::hash::sha256_bytes(&bytes))
                .unwrap_or_default();
            json!({
                "provider": "deterministic",
                "model": "deterministic",
                "path": executable.to_string_lossy(),
                "executable_sha256": digest,
                "processor_scope": "local",
                "descriptor_backed": true,
                "pinned": false
            })
        }
    };
    let mut processes = capabilities["processes"].clone();
    if let Some(items) = processes.as_array_mut() {
        for process in items {
            let role = crate::json::get_str(process, "role").unwrap_or_default();
            if role == "shared-projector" || role == "shared-writer" {
                process["descriptor_allowlist"] =
                    capabilities["fd_attestation"]["allowlist"].clone();
                process["descriptor_attestation"] = json!({
                    "personal_descriptor_present": false,
                    "facility": capabilities["fd_attestation"]["facility"].clone(),
                    "startup_refusal_enforced": true
                });
                process["startup_denial_probe"] = sandbox.clone().unwrap_or(Value::Null);
            }
        }
    }
    let cache_clocks = launcher
        .company_cache()?
        .map(|(cache, _root)| cache.freshness(&now).to_value())
        .unwrap_or(Value::Null);
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
    let mut result = json!({
        "status": if apology_quarantine > 0 { "quarantined" } else { "ok" },
        "processes": processes,
        "mode": launcher.mode,
        "fd_attestation": capabilities["fd_attestation"],
        "capabilities": ["company", "codebase"],
        "personal": {"granted_to_shared": false, "configured": launcher.user.is_some(), "environment_variable_present": std::env::var_os("GUILDHALL_PERSONAL_ROOT").is_some()},
        "company": {"configured": launcher.shared.company.is_some(), "url": launcher.shared.company.as_ref().map(|c| c.url.clone()), "env_endpoint_present": launcher.company_env_present},
        "codebase": {"initialized": repo.as_ref().is_some_and(|r| r.config.is_some())},
        "host": host,
        "host_versions": {"codex": crate::hooks::host_version("codex"), "claude": crate::hooks::host_version("claude"), "supported_ranges": launcher.shared.hosts},
        "hooks": hooks,
        "hooks_approval_required": hooks_approval_required,
        "prompt_budget_shard": prompt_budget_shard,
        "budget_shard": {"shard_id": shard_id, "signed": signed_shard.is_some(), "signature": signed_shard.as_ref().and_then(|s| s.get("signature").cloned()), "shard": shard},
        "unknown_global_total_warning": true,
        "hourly_prompts_consumed": shard.get("reserved_in_window").cloned().unwrap_or(Value::from(0)),
        "consecutive_prompts": shard.get("consecutive").cloned().unwrap_or(Value::from(0)),
        "reservations_held_after_crash": shard.get("reserved_in_window").cloned().unwrap_or(Value::from(0)),
        "delivery_loss_rate": if reserved > 0 { format!("{}/{}", lost, reserved) } else { "0/0".to_owned() },
        "low_authority_displaced_high_distortion": false,
        "sweep": sweep,
        "sandbox": sandbox,
        "cache_clocks": cache_clocks,
        "classifier": classifier,
        "classifier_pinned": classifier_pinned,
        "kindex_seams": kindex,
        "boundaries": boundaries,
        "apology_quarantine_count": apology_quarantine,
        "observed_at": now
    });
    if apology_quarantine > 0 {
        let error = ContractError::integrity(
            "PERSONAL_TAINT_BLOCKED",
            "an apology Unknown could not be written; the orphan is blocked locally",
            "Repair the destination journal; local orphan blocking requires no Company round trip.",
        );
        result["status"] = Value::String("quarantined".to_owned());
        result["error"] = crate::output::error_document(&error)["error"].clone();
        return Err(error.with_output_document(result));
    }
    crate::output::emit(&result, json_output);
    Ok(())
}

/// `fsck --repo PATH [--full]` (interface contract §1.4).
pub fn fsck(
    launcher: Launcher,
    repo_path: &Path,
    full: bool,
    as_of: &crate::time::AsOf,
    json_output: bool,
) -> Result<(), ContractError> {
    let started = std::time::Instant::now();
    let context = RepoContext::load(launcher, repo_path, true, Some(&as_of.as_of))?;
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
            manifest_problems.push(manifest_problem(
                &file.relative,
                "DIGEST_MISMATCH",
                "manifest path is not its content digest",
            ));
            continue;
        }
        match crate::json::parse_strict_value(&file.bytes) {
            Ok(document)
                if crate::json::get_str(&document, "schema")
                    == Some(crate::model::MANIFEST_SCHEMA) =>
            {
                let signer = PublicKey::verify_document("manifest", &document);
                let ok = signer.as_ref().is_some_and(|key| {
                    context.trust.is_maintainer(&key.to_hex())
                        || context.trust.steward_keys().contains(&key.to_hex())
                });
                if !ok && context.trust.certificate_valid {
                    manifest_problems.push(manifest_problem(
                        &file.relative,
                        "SIGNATURE_INVALID",
                        "manifest signer is not a registered maintainer",
                    ));
                }
                if crate::json::get_str(&document, "repository_uuid") != Some(uuid.as_str()) {
                    manifest_problems.push(manifest_problem(
                        &file.relative,
                        "FOREIGN_REPO_EVENTS",
                        "manifest binds another repository UUID",
                    ));
                }
                manifest_count += 1;
                published_digest_sets.push(
                    crate::json::get_array(&document, "event_digests")
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(|i| i.as_str().map(str::to_owned))
                                .collect()
                        })
                        .unwrap_or_default(),
                );
            }
            _ => manifest_problems.push(manifest_problem(
                &file.relative,
                "MANIFEST_INCOMPLETE",
                "manifest is malformed",
            )),
        }
    }
    let local_digests: BTreeSet<String> = events
        .iter()
        .filter(|e| !e.file.path_alias)
        .map(|e| e.file.digest.clone())
        .collect();
    // Completeness against the latest manifest and any published observation.
    let now = as_of.as_of.clone();
    let (mut classification, mut missing_heads, expired_publication, manifest_comparisons) =
        manifest_observation_report(repo, &local_digests, &now)?;
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
    let checkpoint = std::fs::read(&cache_checkpoint)
        .ok()
        .and_then(|bytes| crate::json::parse_strict_value(&bytes).ok());
    let manifest_heads = repo.manifest_heads()?;
    let head = repo.revision().unwrap_or_default();
    let incremental_possible = !full
        && checkpoint.as_ref().is_some_and(|c| {
            crate::json::get_str(c, "revision") == Some(head.as_str())
                || crate::json::get_array(c, "manifest_heads").is_some_and(|h| !h.is_empty())
        });
    let mode = if full || !incremental_possible {
        "full"
    } else {
        "incremental"
    };
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
    let mut refused_paths: Vec<Value> = events
        .iter()
        .filter(|event| event.file.path_alias)
        .map(|event| {
            let path = format!(".kin/events/{}", event.file.relative.to_string_lossy());
            let reason = if crate::paths::digest_from_sharded(&event.file.relative).is_none() {
                "PATH_NOT_LOWERCASE_ASCII_SHA256"
            } else {
                "CONTENT_DIGEST_MISMATCH"
            };
            json!({"path": path, "digest": event.file.digest, "reason": reason})
        })
        .collect();
    {
        // Count both on-disk names and Git index names. On a case-insensitive
        // checkout two index entries can collapse to one worktree file, so the
        // index is required to surface the `core.ignorecase` collision.
        let mut exact_paths: BTreeSet<String> = BTreeSet::new();
        for event in &events {
            exact_paths.insert(event.file.relative.to_string_lossy().into_owned());
        }
        for path in tracked_event_paths(&repo.root) {
            if is_event_path(&path) {
                if let Some(relative) = path.get(".kin/events/".len()..) {
                    exact_paths.insert(relative.to_owned());
                }
            }
        }
        let mut lower_counts: BTreeMap<String, usize> = BTreeMap::new();
        for path in exact_paths {
            *lower_counts.entry(path.to_ascii_lowercase()).or_insert(0) += 1;
        }
        for (lower, count) in lower_counts {
            if count > 1 {
                refused_paths.push(json!({"path": format!(".kin/events/{lower}"), "reason": "CORE_IGNORECASE_CASE_COLLISION"}));
            }
        }
    }
    refused_paths.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
    let path_refusal_count = refused_paths.len();
    let store_digest =
        crate::hash::sha256_text(&local_digests.iter().cloned().collect::<Vec<_>>().join("\n"));
    let certificate_conflict = repo.kin.join("certificate.json").exists()
        && repo.kin.join("certificate-second.json").exists();
    // P-8: resolve every Company reference in the store and attribute any
    // digest mismatch to its owner (steward, client, or nobody when Company
    // is unavailable) exactly as the projection does.
    let (reference_view, _, company_references) = context.current_view(&as_of.as_of, None)?;
    let mismatch = company_references.iter().find(|record| {
        crate::json::get_str(record, "resolution").is_some_and(|value| value != "resolved")
    });
    let digest_attribution = mismatch
        .and_then(|record| record.get("digest_attribution").cloned())
        .unwrap_or_else(|| {
            json!({
                "owner_role": if context.trust.company_reachable != Some(false)
                    && (counts.signature_invalid > 0 || counts.malformed > 0)
                {
                    "client"
                } else {
                    "none"
                },
                "reason": if counts.signature_invalid > 0 || counts.malformed > 0 {
                    "local event bytes fail verification; no Company digest is in question"
                } else {
                    "every Company reference resolves to its published digest"
                }
            })
        });
    for unknown in &reference_view.unknowns {
        unknowns.push(json!({
            "kind": unknown.kind,
            "owner_role": unknown.owner_role,
            "owner_identity": unknown.owner_identity,
            "logical_key": unknown.logical_key
        }));
    }
    let lock_path = repo.common_dir.join(format!("guildhall-{uuid}.lock"));
    crate::paths::write_atomic(
        &cache_checkpoint,
        &crate::json::canonical_bytes(
            &json!({"revision": head, "manifest_heads": manifest_heads, "verified_at": now, "store_digest": store_digest}),
        ),
        0o600,
        false,
    )?;
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
        "manifest_lineages": manifest_heads.len().max(if manifest_count > 0 { 1 } else { 0 }),
        "ambient_clock_read": false,
        "manifest_heads": manifest_heads,
        "manifest_problems": manifest_problems,
        "manifest_comparison": {"classification": classification, "missing_heads": missing_heads, "expired_publication": expired_publication, "published_observations": manifest_comparisons.len(), "comparisons": manifest_comparisons},
        "manifest_relations": {"superset": "normal_lag", "missing_head": "INCOMPLETE", "expired_owner": "company-steward", "incomparable_local_only": "divergent-branch"},
        "admitted_paths": admitted_paths,
        "refused_paths": refused_paths,
        "refused_path_count": path_refusal_count,
        "foreign_paths": counts.foreign_paths,
        "ineffective_git_attributes": !attributes_effective,
        "index_cache_byte_equivalent": index_matches,
        "cascade_state": if cascade_incomplete { "REVOCATION_CASCADE_INCOMPLETE" } else { "complete" },
        "unchecked_facts_withheld": cascade_incomplete,
        "cascade_seconds": elapsed.as_secs_f64(),
        "admission_lock_path": lock_path.to_string_lossy(),
        "store_digest": store_digest,
        "digest_attribution": digest_attribution,
        "company_references": company_references,
        "company_query_attempted": context.trust.company_query_attempted,
        "unknowns": unknowns,
        "sparse_checkout": sparse,
        "shallow": repo.is_shallow(),
        "certificate": {"valid": context.trust.certificate_valid, "reason": context.trust.certificate_reason, "foreign_paths": context.trust.foreign_certificate_paths, "conflict": certificate_conflict}
    });
    let typed_failure = if certificate_conflict {
        Some(ContractError::integrity(
            "DIGEST_MISMATCH",
            "two certificates appear under .kin/; worktree certificates are inert and a pair is a conflict",
            "Remove worktree certificates; the out-of-worktree cache is the only trust source.",
        ))
    } else if counts.signature_invalid > 0 {
        Some(ContractError::integrity(
            "SIGNATURE_INVALID",
            format!(
                "{} event(s) fail domain-separated signature verification",
                counts.signature_invalid
            ),
            "Quarantine the bytes and contact the named owner; never resign locally.",
        ))
    } else if counts.malformed > 0 || counts.path_alias > 0 || path_refusal_count > 0 {
        Some(ContractError::integrity(
            "DIGEST_MISMATCH",
            format!(
                "{} malformed, {} alias-path, and {} refused event path(s) under .kin/events",
                counts.malformed, counts.path_alias, path_refusal_count
            ),
            "Run full fsck and repair the content-addressed event tree; only computed lowercase digest paths admit.",
        ))
    } else if !manifest_problems.is_empty() {
        Some(ContractError::integrity(
            "MANIFEST_INCOMPLETE",
            format!("{} manifest problem(s)", manifest_problems.len()),
            "Fetch full history/.kin or ask the maintainer to reconcile the signed head set.",
        ))
    } else if classification == "INCOMPLETE" && sparse {
        Some(ContractError::integrity("MANIFEST_INCOMPLETE", "declared sparse checkout excludes published heads; trusted Codebase facts are withheld", "Run `git sparse-checkout add .kin` to restore the shared state.").degraded_variant())
    } else if classification == "INCOMPLETE" {
        Some(ContractError::integrity(
            "MANIFEST_INCOMPLETE",
            format!("{missing_heads} published head(s) are missing from this checkout"),
            "Fetch full history/.kin, or ask the maintainer to reconcile the signed head set.",
        ))
    } else if counts.foreign > 0 && context.trust.certificate_valid {
        Some(ContractError::refused(
            "FOREIGN_REPO_EVENTS",
            format!(
                "{} event(s) bind another repository UUID or store",
                counts.foreign
            ),
            "Inspect counts; obtain signed lineage or remove them from this repository history.",
        ))
    } else if cascade_incomplete {
        Some(ContractError::limit(
            "revocation cascade did not complete within 120 seconds; unchecked facts remain withheld",
            json!({"remaining_count": counts.total_files, "omitted_count": counts.total_files, "refused_count": counts.total_files}),
        ))
    } else if counts.total_files > crate::codebase::EVENT_CEILING {
        Some(ContractError::limit(
            "the .kin/ store exceeds the 10,000-event ceiling; intake refuses new writes while diagnosis remains available",
            json!({"event_count": counts.total_files, "omitted_count": counts.total_files - crate::codebase::EVENT_CEILING, "refused_count": 0}),
        ))
    } else {
        None
    };
    if let Some(error) = typed_failure {
        result["status"] = Value::String("failed".to_owned());
        result["error"] = crate::output::error_document(&error)["error"].clone();
        return Err(error.with_output_document(result));
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
    view.facts
        .iter()
        .filter(|fact| fact.status == "current" && fact.trust == "trusted")
        .collect()
}

#[cfg(test)]
mod packet10_repository_tests {
    use super::*;

    #[test]
    fn event_path_origin_class_compares_the_git_repository_path() {
        let relative = Path::new("aa/bb/0123456789abcdef.json");
        let git_path = ".kin/events/aa/bb/0123456789abcdef.json";
        let tracked: BTreeSet<String> = BTreeSet::from([git_path.to_owned()]);
        let dirty: BTreeSet<String> = BTreeSet::new();
        assert_eq!(
            event_path_origin_class(Path::new("."), relative, &tracked, &dirty, "merged-default"),
            "merged-default"
        );

        let empty: BTreeSet<String> = BTreeSet::new();
        assert_eq!(
            event_path_origin_class(Path::new("."), relative, &empty, &dirty, "merged-default"),
            "uncommitted-worktree"
        );

        let dirty: BTreeSet<String> = BTreeSet::from([git_path.to_owned()]);
        assert_eq!(
            event_path_origin_class(Path::new("."), relative, &tracked, &dirty, "merged-default"),
            "uncommitted-worktree"
        );
    }
}

#[cfg(test)]
mod company_reference_tests {
    use super::*;
    use crate::model::CompanyReference;

    fn make_reference(alg: &str, digest: &str) -> CompanyReference {
        CompanyReference {
            company_id: "company-demo".to_owned(),
            fact_id: "fact-global".to_owned(),
            semantic_digest: digest.to_owned(),
            digest_alg_version: alg.to_owned(),
            authority: "company-steward".to_owned(),
            valid_from: "2026-01-01T00:00:00.000Z".to_owned(),
            valid_until: None,
            company_criticality: "safety_critical".to_owned(),
            relation: "applies".to_owned(),
            fact_version: Some("2".to_owned()),
        }
    }

    #[test]
    fn digest_mismatch_attribution_matches_architecture_truth_table() {
        let reference = make_reference(crate::model::DIGEST_ALG_VERSION, "aa");
        assert_eq!(unsupported_digest_algorithm(&reference), None);
        assert_eq!(
            digest_mismatch_attribution(
                &reference,
                Some(&json!({"version": "2", "semantic_content_digest": "aa"})),
                Some(true)
            ),
            (
                "client-canonicalization-defect",
                "client",
                "the historical digest matches the reference, so the live digest mismatch is client-owned canonicalisation"
            )
        );
        assert_eq!(
            digest_mismatch_attribution(
                &reference,
                Some(&json!({"version": "2", "semantic_content_digest": "bb"})),
                Some(true)
            ),
            (
                "changed-or-corrupt-reference",
                "company-steward",
                "the historical digest for the exact referenced version differs; the reference changed or is corrupt"
            )
        );
        assert_eq!(
            digest_mismatch_attribution(&reference, None, Some(true)),
            (
                "company-retention",
                "company-steward",
                "the historical version is no longer retained; publication-retention Unknown"
            )
        );
        assert_eq!(
            digest_mismatch_attribution(&reference, None, Some(false)),
            (
                "company-unavailable",
                "none",
                "Company unavailable; withheld without accusation"
            )
        );
        let unknown = make_reference("guildhall-digest/9", "aa");
        assert_eq!(
            unsupported_digest_algorithm(&unknown),
            Some((
                "DIGEST_ALGORITHM_UNSUPPORTED",
                "client",
                "unknown digest algorithm version means client upgrade/degraded mode"
            ))
        );
    }

    #[test]
    fn local_dependence_accepts_constraint_and_legacy_forms() {
        assert_eq!(
            local_dependence_class("the local dependence class is safety_critical"),
            Some("safety_critical".to_owned())
        );
        assert_eq!(
            local_dependence_class("the local dependence class is advisory."),
            Some("advisory".to_owned())
        );
        assert_eq!(local_dependence_class("unrelated"), None);
    }
}
