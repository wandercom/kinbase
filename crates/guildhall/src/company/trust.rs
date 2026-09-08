//! Company trust resolution: steward keys (root plus rotations minus
//! revocations), exact-scope authority resolution from the signed registry,
//! and signer authorization for fact events.

use super::db::CompanyDb;
use crate::crypto::PublicKey;
use crate::error::ContractError;
use crate::model::FactEvent;
use crate::reducer::{Revocation, Verification};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub struct TrustState {
    pub root: PublicKey,
    pub steward_keys: BTreeSet<String>,
    pub revocations: Vec<Revocation>,
    pub registry: Vec<Value>,
    pub cursor: i64,
}

pub fn load(db: &CompanyDb, root: &PublicKey) -> Result<TrustState, ContractError> {
    let mut steward_keys: BTreeSet<String> = BTreeSet::new();
    steward_keys.insert(root.to_hex());
    let mut revocations = Vec::new();
    // Rotations: signed by an already authorized steward, name old and new.
    for (cursor, payload, verification) in db.events_of_kind("rotation")? {
        if verification != "verified" {
            continue;
        }
        let signer = crate::json::get_str(&payload, "signer").unwrap_or_default();
        if !steward_keys.contains(signer) {
            continue;
        }
        if let Some(new_key) = crate::json::get_str(&payload, "new_key") {
            steward_keys.insert(new_key.to_owned());
        }
        let _ = cursor;
    }
    for (cursor, payload, verification) in db.events_of_kind("revocation")? {
        if verification != "verified" {
            continue;
        }
        if let Some(key) = crate::json::get_str(&payload, "revoked_key") {
            revocations.push(Revocation {
                revoked_key: key.to_owned(),
                cursor: cursor.to_string(),
                effective_at: crate::json::get_str(&payload, "effective_at").unwrap_or_default().to_owned(),
            });
            steward_keys.remove(key);
        }
    }
    Ok(TrustState {
        root: root.clone(),
        steward_keys,
        revocations,
        registry: db.registry_entries()?,
        cursor: db.cursor()?,
    })
}

impl TrustState {
    pub fn is_steward(&self, key_hex: &str) -> bool {
        self.steward_keys.contains(key_hex)
    }

    pub fn is_revoked(&self, key_hex: &str) -> bool {
        self.revocations.iter().any(|revocation| revocation.revoked_key == key_hex)
    }

    /// Exact-scope resolution: exactly one active entry, else a registry
    /// conflict or an unresolved owner.
    pub fn authority_for_scope(&self, scope: &str) -> Result<Option<Value>, ContractError> {
        let active: Vec<&Value> = self
            .registry
            .iter()
            .filter(|entry| {
                crate::json::get_str(entry, "scope") == Some(scope)
                    && crate::json::get_str(entry, "status") == Some("active")
                    && !self.is_revoked(crate::json::get_str(entry, "public_key").unwrap_or_default())
            })
            .collect();
        match active.as_slice() {
            [] => Ok(None),
            [entry] => Ok(Some((*entry).clone())),
            _ => Err(ContractError::degraded(
                "UNKNOWN_OWNER_UNRESOLVED",
                format!("registry conflict: {} active authorities overlap the exact scope {scope}", active.len()),
                "The Company steward must repair the registry before any answer can close this scope.",
            )),
        }
    }

    pub fn entries_for_key(&self, key_hex: &str) -> Vec<&Value> {
        self.registry
            .iter()
            .filter(|entry| {
                crate::json::get_str(entry, "public_key") == Some(key_hex)
                    && crate::json::get_str(entry, "status") == Some("active")
            })
            .collect()
    }

    /// Is the signer authorized to publish a fact in the event's exact
    /// authority scope? Steward keys are authorized for every scope.
    pub fn verify_fact_signer(&self, event: &FactEvent) -> Verification {
        if event.verify_signature().is_none() {
            return Verification::SignatureInvalid;
        }
        if self.is_revoked(&event.signer) {
            return Verification::Revoked;
        }
        if self.is_steward(&event.signer) {
            return Verification::Verified;
        }
        let authorized = self.entries_for_key(&event.signer).iter().any(|entry| {
            let scope = crate::json::get_str(entry, "scope").unwrap_or_default();
            scope == event.authority_scope
                || (event.store_kind == "codebase"
                    && event
                        .repository_id
                        .as_deref()
                        .is_some_and(|repo| scope == format!("codebase:{repo}") || scope == format!("repository:{repo}")))
        });
        if authorized {
            Verification::Verified
        } else if self.entries_for_key(&event.signer).is_empty() {
            Verification::Unverified
        } else {
            Verification::WrongScope
        }
    }

    /// Maintainer entries registered for a repository UUID: the exact scope
    /// `codebase:<uuid>` (or `repository:<uuid>`).
    pub fn maintainers_for(&self, repository_uuid: &str) -> Vec<Value> {
        self.registry
            .iter()
            .filter(|entry| {
                let scope = crate::json::get_str(entry, "scope").unwrap_or_default();
                (scope == format!("repository:{repository_uuid}") || scope == format!("codebase:{repository_uuid}"))
                    && crate::json::get_str(entry, "status") == Some("active")
                    && !self.is_revoked(crate::json::get_str(entry, "public_key").unwrap_or_default())
            })
            .cloned()
            .collect()
    }

    pub fn is_maintainer(&self, repository_uuid: &str, key_hex: &str) -> bool {
        self.maintainers_for(repository_uuid)
            .iter()
            .any(|entry| crate::json::get_str(entry, "public_key") == Some(key_hex))
    }

    pub fn environment_registered(&self, environment_id: &str) -> bool {
        self.authority_for_scope(&format!("environment:{environment_id}"))
            .ok()
            .flatten()
            .is_some()
    }

    /// Stable authority identities by exact scope. A scope with multiple
    /// active owners is intentionally omitted so the reducer must surface an
    /// unresolved registry Unknown.
    pub fn authority_owner_by_scope(&self) -> BTreeMap<String, String> {
        let mut owners = BTreeMap::new();
        for entry in &self.registry {
            if crate::json::get_str(entry, "status") != Some("active") {
                continue;
            }
            let Some(scope) = crate::json::get_str(entry, "scope") else { continue };
            if self.authority_for_scope(scope).ok().flatten().is_some() {
                if let Some(identity) = crate::json::get_str(entry, "authority_id") {
                    owners.insert(scope.to_owned(), identity.to_owned());
                }
            }
        }
        owners
    }

    pub fn steward_authority_id(&self) -> Option<String> {
        self.authority_for_scope("company:root")
            .ok()
            .flatten()
            .and_then(|entry| crate::json::get_str(&entry, "authority_id").map(str::to_owned))
    }

    pub fn public_registry(&self) -> Vec<Value> {
        self.registry
            .iter()
            .map(|entry| {
                json!({
                    "authority_id": entry.get("authority_id").cloned().unwrap_or(Value::Null),
                    "scope": entry.get("scope").cloned().unwrap_or(Value::Null),
                    "public_key": entry.get("public_key").cloned().unwrap_or(Value::Null),
                    "channel": entry.get("channel").cloned().unwrap_or(Value::Null),
                    "capabilities": entry.get("capabilities").cloned().unwrap_or(Value::Array(Vec::new())),
                    "status": entry.get("status").cloned().unwrap_or(Value::Null),
                    "cursor": entry.get("cursor").cloned().unwrap_or(Value::Null)
                })
            })
            .collect()
    }
}

pub fn entry_has_capability(entry: &Value, capability: &str) -> bool {
    crate::json::get_array(entry, "capabilities")
        .map(|items| items.iter().any(|item| item.as_str() == Some(capability)))
        .unwrap_or(false)
}

/// Verify a steward-signed document (registry, certificate, revocation,
/// rotation, relaxation, directory update).
pub fn verify_steward_document(trust: &TrustState, message_type: &str, document: &Value) -> Result<PublicKey, ContractError> {
    let key = PublicKey::verify_document(message_type, document).ok_or_else(|| {
        ContractError::integrity(
            "SIGNATURE_INVALID",
            format!("{message_type} document signature failed"),
            "Quarantine the document and contact the Company steward; never resign locally.",
        )
    })?;
    if !trust.is_steward(&key.to_hex()) {
        return Err(ContractError::refused(
            "AUTHORITY_WRONG_SCOPE",
            format!("{message_type} document is not signed by an authorized Company steward key"),
            "Only the Company steward (root or rotated-in key) may sign this document.",
        ));
    }
    Ok(key)
}

pub fn verification_text(verification: &Verification) -> &'static str {
    match verification {
        Verification::Verified => "verified",
        Verification::Unverified => "unverified",
        Verification::Foreign => "foreign",
        Verification::SignatureInvalid => "signature-invalid",
        Verification::Revoked => "revoked",
        Verification::WrongScope => "wrong-scope",
    }
}
