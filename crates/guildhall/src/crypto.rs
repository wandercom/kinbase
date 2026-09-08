//! Ed25519 signing with domain separation (architecture §3): every signer
//! signs `SHA-256("guildhall-sig/1" || 0x00 || message_type || 0x00 ||
//! jcs_bytes)` and `message_type` is one closed enum. Keys are held in
//! memory; verification never writes a key to a temporary file. Wire
//! encoding (Validator addendum): public keys are 64-hex, signatures are
//! 128-hex; private seeds are stored as 64-hex in mode-0600 files.

use crate::error::{ContractError, ExitCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub const SIGNING_DOMAIN: &str = "guildhall-sig/1";
pub const MESSAGE_TYPES: [&str; 12] = [
    "fact-event",
    "unknown-event",
    "manifest",
    "approval-token",
    "repo-certificate",
    "authority-registry-entry",
    "rotation",
    "revocation",
    "tombstone",
    "question",
    "answer",
    "receipt",
];

#[derive(Clone)]
pub struct PrivateKey {
    key: SigningKey,
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PrivateKey({})", self.public().to_hex())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    key: VerifyingKey,
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

impl PrivateKey {
    pub fn generate() -> Self {
        Self {
            key: SigningKey::generate(&mut OsRng),
        }
    }

    /// Parse a seed from 64-hex (canonical) or base64 (legacy files).
    pub fn from_seed_text(text: &str) -> Result<Self, ContractError> {
        let text = text.trim();
        let decoded = crate::hash::hex_decode(text)
            .or_else(|| BASE64.decode(text).ok())
            .ok_or_else(|| signature_invalid("private key seed is not valid hex"))?;
        let seed: [u8; 32] = decoded
            .try_into()
            .map_err(|_| signature_invalid("private key must contain a 32-byte seed"))?;
        Ok(Self {
            key: SigningKey::from_bytes(&seed),
        })
    }

    pub fn to_seed_text(&self) -> String {
        crate::hash::hex_string(&self.key.to_bytes())
    }

    pub fn public(&self) -> PublicKey {
        PublicKey {
            key: self.key.verifying_key(),
        }
    }

    /// 128-hex signature over the domain-separated digest.
    pub fn sign(&self, message_type: &str, message: &[u8]) -> Result<String, ContractError> {
        let digest = domain_digest(message_type, message)?;
        Ok(crate::hash::hex_string(&self.key.sign(&digest).to_bytes()))
    }

    /// Sign a JSON document: returns a copy with `signer` (64-hex public
    /// key) and `signature` (128-hex) set, computed over the JCS bytes of
    /// the document without `signature`.
    pub fn sign_document(
        &self,
        message_type: &str,
        document: &serde_json::Value,
    ) -> Result<serde_json::Value, ContractError> {
        let mut copy = document.clone();
        let map = copy
            .as_object_mut()
            .ok_or_else(|| ContractError::internal("signed documents must be JSON objects"))?;
        map.remove("signature");
        map.insert(
            "signer".to_owned(),
            serde_json::Value::String(self.public().to_hex()),
        );
        let bytes = crate::json::try_canonical_bytes(&copy).map_err(|error| {
            ContractError::invariant(format!("document violates the canonical data model: {error}"))
        })?;
        let signature = self.sign(message_type, &bytes)?;
        copy.as_object_mut()
            .expect("object")
            .insert("signature".to_owned(), serde_json::Value::String(signature));
        Ok(copy)
    }

    /// Load from a mode-0600 file holding either the 64-hex seed or the 32
    /// raw seed bytes. The path role is named in errors; contents never are.
    pub fn load(path: &Path, role: &str) -> Result<Self, ContractError> {
        let bytes = read_private_bytes(path, role)?;
        if bytes.len() == 32 {
            let seed: [u8; 32] = bytes.as_slice().try_into().expect("32 bytes");
            return Ok(Self {
                key: SigningKey::from_bytes(&seed),
            });
        }
        let text = String::from_utf8(bytes).map_err(|_| signature_invalid("private key file is neither raw seed bytes nor hex"))?;
        Self::from_seed_text(&text)
    }

    /// Load from an already-open descriptor number (`GUILDHALL_*_FD`), the
    /// keychain/descriptor supply path of architecture §6.
    pub fn load_fd(fd: i32, role: &str) -> Result<Self, ContractError> {
        use std::io::Read;
        use std::os::fd::FromRawFd;
        if fd < 3 {
            return Err(ContractError::refused(
                "CONFIG_INVARIANT",
                format!("{role} descriptor must be an explicitly passed descriptor above stderr"),
                "Pass an open descriptor number greater than 2.",
            ));
        }
        // SAFETY: the descriptor number was supplied by the launcher for this
        // exact purpose and is owned by this process until it is consumed.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut text = String::new();
        file.read_to_string(&mut text)
            .map_err(|error| ContractError::unreadable(role, &error))?;
        Self::from_seed_text(&text)
    }

    /// Write the seed to a new mode-0600 file (never overwrites trust).
    pub fn save_new(&self, path: &Path, role: &str) -> Result<(), ContractError> {
        write_new_0600(path, format!("{}\n", self.to_seed_text()).as_bytes(), role)
    }

    pub fn load_or_generate(path: &Path, role: &str) -> Result<Self, ContractError> {
        if path.exists() {
            Self::load(path, role)
        } else {
            let key = Self::generate();
            key.save_new(path, role)?;
            Ok(key)
        }
    }
}

impl PublicKey {
    /// Parse a 64-hex public key (base64 accepted for legacy files).
    pub fn from_hex(text: &str) -> Result<Self, ContractError> {
        let text = text.trim();
        let decoded = crate::hash::hex_decode(text)
            .or_else(|| BASE64.decode(text).ok())
            .ok_or_else(|| signature_invalid("public key is not valid hex"))?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|_| signature_invalid("public key must contain 32 bytes"))?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| signature_invalid("public key is not a valid Ed25519 point"))?;
        Ok(Self { key })
    }

    pub fn to_hex(&self) -> String {
        crate::hash::hex_string(&self.key.to_bytes())
    }

    pub fn load(path: &Path, role: &str) -> Result<Self, ContractError> {
        let text = read_private_text(path, role)?;
        Self::from_hex(&text)
    }

    pub fn save_new(&self, path: &Path, role: &str) -> Result<(), ContractError> {
        write_new_0600(path, format!("{}\n", self.to_hex()).as_bytes(), role)
    }

    /// Verify a signed JSON document (`signer` + `signature` fields).
    /// Returns the signer key when valid.
    pub fn verify_document(message_type: &str, document: &serde_json::Value) -> Option<PublicKey> {
        let signer = document.get("signer").and_then(serde_json::Value::as_str)?;
        let signature = document.get("signature").and_then(serde_json::Value::as_str)?;
        let key = PublicKey::from_hex(signer).ok()?;
        let bytes = crate::json::unsigned_bytes(document).ok()?;
        key.verify(message_type, &bytes, signature).then_some(key)
    }

    /// Constant-result verification: a malformed signature is simply false.
    pub fn verify(&self, message_type: &str, message: &[u8], signature: &str) -> bool {
        let Ok(digest) = domain_digest(message_type, message) else {
            return false;
        };
        let Some(decoded) = crate::hash::hex_decode(signature.trim())
            .or_else(|| BASE64.decode(signature.trim()).ok())
        else {
            return false;
        };
        let Ok(bytes) = <[u8; 64]>::try_from(decoded) else {
            return false;
        };
        self.key
            .verify(&digest, &Signature::from_bytes(&bytes))
            .is_ok()
    }
}

fn domain_digest(message_type: &str, message: &[u8]) -> Result<[u8; 32], ContractError> {
    if !MESSAGE_TYPES.contains(&message_type) {
        return Err(signature_invalid(format!(
            "unsupported message type: {message_type}"
        )));
    }
    let mut digest = Sha256::new();
    digest.update(SIGNING_DOMAIN.as_bytes());
    digest.update([0]);
    digest.update(message_type.as_bytes());
    digest.update([0]);
    digest.update(message);
    Ok(digest.finalize().into())
}

fn signature_invalid(message: impl Into<String>) -> ContractError {
    ContractError::new(
        "SIGNATURE_INVALID",
        message,
        "Quarantine the bytes and contact the named owner; never resign locally.",
        false,
        ExitCode::IntegrityFailure,
    )
}

/// Read a token/key file enforcing the cli.md first-run rules: unreadable is
/// exit 4 with the role only; mode broader than 0600 is exit 4 with a chmod
/// remediation. Contents are never placed in an error.
pub fn read_private_text(path: &Path, role: &str) -> Result<String, ContractError> {
    let bytes = read_private_bytes(path, role)?;
    String::from_utf8(bytes).map_err(|_| {
        ContractError::refused(
            "CONFIG_INVARIANT",
            format!("{role} file is not UTF-8 text"),
            "Supply a text file; contents are never printed.",
        )
    })
}

pub fn read_private_bytes(path: &Path, role: &str) -> Result<Vec<u8>, ContractError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| ContractError::unreadable(role, &error))?;
    if metadata.file_type().is_symlink() {
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            format!("{role} file is a symlink"),
            "Point the configuration at a regular file; symlinks are rejected.",
        ));
    }
    if !metadata.is_file() {
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            format!("{role} path is not a regular file"),
            "Point the configuration at a regular mode-0600 file.",
        ));
    }
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(ContractError::broad_mode(role, path, mode));
    }
    if metadata.len() > 64 * 1024 {
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            format!("{role} file exceeds the 64 KiB key/token bound"),
            "Supply the bare token or key file.",
        ));
    }
    std::fs::read(path).map_err(|error| ContractError::unreadable(role, &error))
}

pub fn write_new_0600(path: &Path, bytes: &[u8], role: &str) -> Result<(), ContractError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| ContractError::io(&format!("create {role} directory"), error))?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| ContractError::io(&format!("create {role} file"), error))?;
    std::io::Write::write_all(&mut file, bytes)
        .map_err(|error| ContractError::io(&format!("write {role} file"), error))?;
    file.sync_all()
        .map_err(|error| ContractError::io(&format!("sync {role} file"), error))
}

pub fn write_0600(path: &Path, bytes: &[u8], role: &str) -> Result<(), ContractError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| ContractError::io(&format!("create {role} directory"), error))?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| ContractError::io(&format!("open {role} file"), error))?;
    std::io::Write::write_all(&mut file, bytes)
        .map_err(|error| ContractError::io(&format!("write {role} file"), error))?;
    file.sync_all()
        .map_err(|error| ContractError::io(&format!("sync {role} file"), error))
}

/// Constant-time byte comparison for bearer tokens.
pub fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut bytes);
    crate::hash::hex_string(&bytes)
}

pub fn random_id(prefix: &str) -> String {
    let mut bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut OsRng, &mut bytes);
    format!("{prefix}_{}", crate::hash::hex_string(&bytes))
}
