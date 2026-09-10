use sha2::{Digest, Sha256};

pub fn sha256_bytes(bytes: &[u8]) -> String {
    hex_string(&Sha256::digest(bytes))
}

pub fn sha256_text(text: &str) -> String {
    sha256_bytes(text.as_bytes())
}

pub fn sha256_raw(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect()
}

/// Lowercase ASCII SHA-256 hex of fixed length; uppercase aliases and any
/// other byte are rejected before filesystem use.
pub fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Short stable identifier prefix from a digest.
pub fn short(digest: &str) -> &str {
    &digest[..digest.len().min(24)]
}

/// Keyed HMAC-SHA-256 used for permanent-evidence canary matches (never the
/// raw value).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> String {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        key_block[..32].copy_from_slice(&sha256_raw(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let inner: Vec<u8> = key_block.iter().map(|b| b ^ 0x36).collect();
    let outer: Vec<u8> = key_block.iter().map(|b| b ^ 0x5c).collect();
    let mut inner_hash = Sha256::new();
    inner_hash.update(inner);
    inner_hash.update(message);
    let inner_digest = inner_hash.finalize();
    let mut outer_hash = Sha256::new();
    outer_hash.update(outer);
    outer_hash.update(inner_digest);
    hex_string(&outer_hash.finalize())
}
