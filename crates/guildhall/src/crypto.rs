use crate::error::{ContractError, ExitCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

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

pub fn ensure_keypair(
    store: crate::StoreKind,
    repo: &Path,
) -> Result<(PathBuf, PathBuf), ContractError> {
    let root = crate::store::ensure_store_root(store, repo).map_err(io_error)?;
    let key_root = root.join("local").join("keys");
    std::fs::create_dir_all(&key_root).map_err(io_error)?;
    crate::store::secure_directory(&key_root).map_err(io_error)?;
    let private_path = key_root.join("ed25519.key");
    let public_path = key_root.join("ed25519.pub");
    if !private_path.exists() || !public_path.exists() {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let private_bytes = signing_key.to_bytes();
        let public_bytes = signing_key.verifying_key().to_bytes();
        write_private(&private_path, BASE64.encode(private_bytes).as_bytes())?;
        write_private(&public_path, BASE64.encode(public_bytes).as_bytes())?;
    }
    Ok((private_path, public_path))
}

fn domain_digest(message_type: &str, message: &[u8]) -> Result<[u8; 32], ContractError> {
    if !MESSAGE_TYPES.contains(&message_type) {
        return Err(ContractError::new(
            "SIGNATURE_INVALID",
            format!("unsupported message type: {message_type}"),
            "Use a closed Guildhall message type.",
            false,
            ExitCode::IntegrityFailure,
        ));
    }
    let mut digest = Sha256::new();
    digest.update(SIGNING_DOMAIN.as_bytes());
    digest.update([0]);
    digest.update(message_type.as_bytes());
    digest.update([0]);
    digest.update(message);
    Ok(digest.finalize().into())
}

pub fn sign_message(
    message_type: &str,
    message: &[u8],
    private_key: &Path,
) -> Result<String, ContractError> {
    let digest = domain_digest(message_type, message)?;
    let encoded = std::fs::read_to_string(private_key).map_err(io_error)?;
    let decoded = BASE64.decode(encoded.trim()).map_err(|error| {
        ContractError::new(
            "SIGNATURE_INVALID",
            error.to_string(),
            "Use a valid Ed25519 key file.",
            false,
            ExitCode::IntegrityFailure,
        )
    })?;
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&decoded);
    let signing_key = SigningKey::from_bytes(&bytes);
    Ok(BASE64.encode(signing_key.sign(&digest).to_bytes()))
}

pub fn verify_message(
    message_type: &str,
    message: &[u8],
    signature_text: &str,
    public_key: &Path,
) -> Result<bool, ContractError> {
    let digest = domain_digest(message_type, message)?;
    let encoded_public = std::fs::read_to_string(public_key).map_err(io_error)?;
    let decoded_public = BASE64.decode(encoded_public.trim()).map_err(|error| {
        ContractError::new(
            "SIGNATURE_INVALID",
            error.to_string(),
            "Use a valid Ed25519 public key.",
            false,
            ExitCode::IntegrityFailure,
        )
    })?;
    let mut public_bytes = [0u8; 32];
    public_bytes.copy_from_slice(&decoded_public);
    let verifying_key = VerifyingKey::from_bytes(&public_bytes).map_err(|error| {
        ContractError::new(
            "SIGNATURE_INVALID",
            error.to_string(),
            "Use a valid Ed25519 public key.",
            false,
            ExitCode::IntegrityFailure,
        )
    })?;
    let decoded_signature = BASE64.decode(signature_text.trim()).map_err(|error| {
        ContractError::new(
            "SIGNATURE_INVALID",
            error.to_string(),
            "Use a valid base64 signature.",
            false,
            ExitCode::IntegrityFailure,
        )
    })?;
    let mut signature_bytes = [0u8; 64];
    signature_bytes.copy_from_slice(&decoded_signature);
    let signature = Signature::from_bytes(&signature_bytes);
    Ok(verifying_key
        .verify(&digest, &signature)
        .map(|_| true)
        .unwrap_or(false))
}

pub fn sign(message: &[u8], private_key: &Path) -> Result<String, ContractError> {
    sign_message("receipt", message, private_key)
}

pub fn verify(
    message: &[u8],
    signature_text: &str,
    public_key: &Path,
) -> Result<bool, ContractError> {
    verify_message("receipt", message, signature_text, public_key)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), ContractError> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true).mode(0o600);
    let mut file = options.open(path).map_err(io_error)?;
    std::io::Write::write_all(&mut file, bytes).map_err(io_error)?;
    Ok(())
}

fn io_error(error: std::io::Error) -> ContractError {
    ContractError::new(
        "RUN_INTEGRITY_FAILED",
        error.to_string(),
        "Check filesystem permissions and retry.",
        false,
        ExitCode::InternalFailure,
    )
}
