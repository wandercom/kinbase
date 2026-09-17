//! Loading the configuration creates nothing: read-only commands on a fresh
//! machine used to create the Company cache directory and mint the client
//! and maintainer signing keys.
//!
//! Roles collapsed: the lane that wrote the fix wrote this probe.

use kinbase::crypto::PrivateKey;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn private_write(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

#[test]
fn read_only_commands_mint_no_keys_and_create_no_cache() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let config = temp.path().join("config-home").join("kinbase");
    let personal = temp.path().join("personal");
    for directory in [&home, &config, &personal] {
        fs::create_dir_all(directory).unwrap();
    }
    fs::set_permissions(&personal, fs::Permissions::from_mode(0o700)).unwrap();
    let root = PrivateKey::generate();
    private_write(
        &config.join("root-public.key"),
        format!("{}\n", root.public().to_hex()).as_bytes(),
    );
    private_write(&config.join("facts.token"), b"facts-token\n");
    let cache = temp.path().join("company-cache");
    let client_key = config.join("client.key");
    let maintainer_key = config.join("maintainer.key");
    private_write(
        &config.join("config.toml"),
        format!(
            "schema_version = \"1\"\n\n[personal]\ndata_root = \"{}\"\n\n[company]\nurl = \"http://127.0.0.1:1\"\nfacts_token_file = \"{}\"\nroot_public_key_file = \"{}\"\ncache_root = \"{}\"\nclient_key_file = \"{}\"\nmaintainer_key_file = \"{}\"\n",
            personal.display(),
            config.join("facts.token").display(),
            config.join("root-public.key").display(),
            cache.display(),
            client_key.display(),
            maintainer_key.display(),
        )
        .as_bytes(),
    );
    let repo = temp.path().join("repo");
    fs::create_dir_all(&repo).unwrap();
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(&repo)
            .status()
            .unwrap()
            .success()
    );
    for args in [&["doctor", "--json"][..], &["status", "--json"][..]] {
        let _ = Command::new(env!("CARGO_BIN_EXE_kinbase"))
            .current_dir(&repo)
            .args(args)
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", temp.path().join("config-home"))
            .env("XDG_STATE_HOME", temp.path().join("state-home"))
            .env_remove("KINBASE_COMPANY_URL")
            .env_remove("KINBASE_CLIENT_KEY_FD")
            .output()
            .unwrap();
        assert!(!client_key.exists(), "{args:?} minted the client key");
        assert!(
            !maintainer_key.exists(),
            "{args:?} minted the maintainer key"
        );
        assert!(!cache.exists(), "{args:?} created the Company cache");
    }
}
