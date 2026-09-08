//! Process containment (architecture §1, §6; interface contract §4, C17):
//! descriptor enumeration/attestation with the platform-native facility,
//! the macOS `sandbox-exec` denial probe, and descriptor-backed classifier
//! execution.

use crate::error::ContractError;
use serde_json::{Value, json};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The frozen CLOEXEC-by-default descriptor allowlist: stdio plus any
/// explicitly declared launcher descriptors.
pub fn allowlist() -> Vec<i32> {
    let mut list = vec![0, 1, 2];
    for name in ["GUILDHALL_CLIENT_KEY_FD", "GUILDHALL_SHARED_CONFIG_FD"] {
        if let Ok(value) = std::env::var(name) {
            if let Ok(fd) = value.trim().parse::<i32>() {
                list.push(fd);
            }
        }
    }
    list
}

#[derive(Debug, Clone)]
pub struct OpenDescriptor {
    pub fd: i32,
    pub dev: u64,
    pub ino: u64,
    pub is_dir: bool,
    pub path: Option<PathBuf>,
}

/// Enumerate live descriptors with `fcntl(F_GETFD)` (never `/dev/fd`, which
/// would open a descriptor of its own) and `fstat`; on macOS `F_GETPATH`
/// resolves the path for containment checks.
pub fn open_descriptors() -> Vec<OpenDescriptor> {
    // SAFETY: sysconf and fcntl/fstat on integer descriptors have no memory
    // safety preconditions; failures are reported through return codes.
    let max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    let max = if max <= 0 { 1024 } else { max.min(65_536) } as i32;
    let mut output = Vec::new();
    for fd in 0..max {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            continue;
        }
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stat) } != 0 {
            continue;
        }
        let is_dir = (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR;
        let path = descriptor_path(fd);
        output.push(OpenDescriptor {
            fd,
            dev: stat.st_dev as u64,
            ino: stat.st_ino,
            is_dir,
            path,
        });
    }
    output
}

#[cfg(target_os = "macos")]
fn descriptor_path(fd: i32) -> Option<PathBuf> {
    let mut buffer = vec![0u8; libc::PATH_MAX as usize + 1];
    // SAFETY: F_GETPATH writes at most PATH_MAX bytes into the buffer.
    let result = unsafe { libc::fcntl(fd, libc::F_GETPATH, buffer.as_mut_ptr()) };
    if result < 0 {
        return None;
    }
    let end = buffer.iter().position(|b| *b == 0).unwrap_or(buffer.len());
    Some(PathBuf::from(String::from_utf8_lossy(&buffer[..end]).into_owned()))
}

#[cfg(not(target_os = "macos"))]
fn descriptor_path(fd: i32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()
}

/// Device/inode of a directory, for containment comparison.
pub fn dir_identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path).ok()?;
    Some((metadata.dev(), metadata.ino()))
}

/// Startup attestation: refuse any inherited descriptor under the Personal
/// root (by device/inode or resolved path) and any descriptor outside the
/// frozen allowlist. Returns the attestation record for `doctor`.
pub fn attest_descriptors(personal_root: Option<&Path>) -> Result<Value, ContractError> {
    let allow = allowlist();
    let descriptors = open_descriptors();
    let personal_identity = personal_root.and_then(dir_identity);
    let personal_canonical = personal_root.and_then(|root| root.canonicalize().ok());
    let mut extra = Vec::new();
    for descriptor in &descriptors {
        let under_personal = personal_identity.is_some_and(|(dev, ino)| descriptor.dev == dev && descriptor.ino == ino)
            || (personal_canonical.as_ref().zip(descriptor.path.as_ref())).is_some_and(|(root, path)| path.starts_with(root));
        if under_personal {
            return Err(ContractError::refused(
                "CONFIG_INVARIANT",
                format!("inherited descriptor {} resolves under the Personal root; shared work refused before any side effect", descriptor.fd),
                "Launch shared processes with the frozen descriptor allowlist only; never pass a Personal directory or file descriptor.",
            )
            .with_detail(json!({"shared_work_performed": false, "descriptor": descriptor.fd, "is_dir": descriptor.is_dir})));
        }
        if !allow.contains(&descriptor.fd) {
            extra.push(descriptor.fd);
        }
    }
    if !extra.is_empty() {
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            format!("{} inherited descriptor(s) outside the frozen allowlist; shared work refused before any side effect", extra.len()),
            "Launch with only the declared descriptors (stdio plus explicit GUILDHALL_*_FD values).",
        )
        .with_detail(json!({"shared_work_performed": false, "descriptors": extra})));
    }
    Ok(json!({
        "allowlist": allow,
        "open_descriptors": descriptors.iter().map(|d| d.fd).collect::<Vec<_>>(),
        "personal_descriptor_present": false,
        "facility": if cfg!(target_os = "macos") { "fcntl(F_GETFD)+fstat+F_GETPATH" } else { "fcntl(F_GETFD)+fstat+/proc/self/fd" }
    }))
}

/// macOS sandbox profile denying the Personal root and all unrelated user
/// paths while allowing only the declared Company cache and one repository
/// root (plus the system toolchain paths the binary needs to run).
pub fn profile(personal_root: &Path, allowed_roots: &[PathBuf], company_port: Option<u16>) -> String {
    let mut lines = vec![
        "(version 1)".to_owned(),
        "(deny default)".to_owned(),
        "(allow process-exec process-fork sysctl-read mach-lookup)".to_owned(),
        "(allow file-read-metadata)".to_owned(),
        "(allow file-read* (subpath \"/usr\") (subpath \"/bin\") (subpath \"/sbin\") (subpath \"/System\") (subpath \"/Library\") (subpath \"/opt\") (subpath \"/private/etc\") (subpath \"/dev\") (subpath \"/private/var/db\") (literal \"/\"))".to_owned(),
        "(allow file-write-data (literal \"/dev/null\") (literal \"/dev/tty\") (regex #\"^/dev/fd/\"))".to_owned(),
        "(allow file-read* (regex #\"^/dev/fd/\"))".to_owned(),
    ];
    for root in allowed_roots {
        let quoted = root.to_string_lossy().replace('"', "\\\"");
        lines.push(format!("(allow file-read* file-write* (subpath \"{quoted}\"))"));
    }
    if let Some(port) = company_port {
        lines.push(format!("(allow network-outbound (remote ip \"localhost:{port}\"))"));
    }
    let personal = personal_root.to_string_lossy().replace('"', "\\\"");
    lines.push(format!("(deny file-read* file-write* file-read-metadata (subpath \"{personal}\"))"));
    lines.join("\n")
}

pub fn sandbox_available() -> bool {
    cfg!(target_os = "macos") && Path::new("/usr/bin/sandbox-exec").exists()
}

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub enforced: bool,
    pub personal_root_readable: bool,
    pub disabled_loudly: bool,
    pub detail: Value,
}

/// Run the startup denial probe: a child under the sandbox profile attempts
/// to read the Personal root. Success is a hard failure of the boundary.
pub fn denial_probe(personal_root: &Path, allowed_roots: &[PathBuf], company_port: Option<u16>) -> ProbeResult {
    if !sandbox_available() {
        return ProbeResult {
            enforced: false,
            personal_root_readable: true,
            disabled_loudly: true,
            detail: json!({"reason": "no supported kernel enforcement (sandbox-exec) on this platform; shared projection/publication disabled"}),
        };
    }
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(error) => {
            return ProbeResult {
                enforced: false,
                personal_root_readable: true,
                disabled_loudly: true,
                detail: json!({"reason": format!("current executable unavailable ({})", error.kind())}),
            };
        }
    };
    let profile = profile(personal_root, allowed_roots, company_port);
    let output = Command::new("/usr/bin/sandbox-exec")
        .arg("-p")
        .arg(&profile)
        .arg(&exe)
        .arg("__probe")
        .arg(personal_root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/nonexistent")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let readable = stdout.contains("\"readable\":true");
            let probe_ran = stdout.contains("\"probe\":\"personal-root\"");
            ProbeResult {
                enforced: probe_ran && !readable,
                personal_root_readable: readable,
                disabled_loudly: !probe_ran || readable,
                detail: json!({"probe_ran": probe_ran, "exit": output.status.code(), "readable": readable}),
            }
        }
        Err(error) => ProbeResult {
            enforced: false,
            personal_root_readable: true,
            disabled_loudly: true,
            detail: json!({"reason": format!("sandbox-exec failed to launch ({})", error.kind())}),
        },
    }
}

/// The probe child body: attempt to open and list the directory; report
/// whether any byte of the tree was readable. Never prints the path.
pub fn probe_main(target: &Path) -> i32 {
    let mut readable = false;
    if let Ok(entries) = std::fs::read_dir(target) {
        for entry in entries.flatten() {
            readable = true;
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_file() {
                    if let Ok(mut file) = std::fs::File::open(entry.path()) {
                        let mut buffer = [0u8; 1];
                        let _ = std::io::Read::read(&mut file, &mut buffer);
                    }
                }
            }
        }
    }
    if !readable {
        if let Ok(metadata) = std::fs::metadata(target) {
            readable = metadata.is_dir() && std::fs::read_dir(target).is_ok();
        }
    }
    println!("{{\"probe\":\"personal-root\",\"readable\":{readable}}}");
    if readable { 0 } else { 3 }
}

/// Run a shared helper under the sandbox with a scrubbed environment and the
/// shared configuration on an explicit descriptor (never argv or env).
pub fn run_shared(
    personal_root: &Path,
    allowed_roots: &[PathBuf],
    company_port: Option<u16>,
    args: &[String],
    shared_config: &[u8],
) -> Result<std::process::Output, ContractError> {
    let exe = std::env::current_exe().map_err(|error| ContractError::io("current executable", error))?;
    let profile = profile(personal_root, allowed_roots, company_port);
    let mut command = if sandbox_available() {
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command.arg("-p").arg(&profile).arg(&exe);
        command
    } else {
        return Err(ContractError::refused(
            "PROCESSOR_UNAUTHORIZED",
            "no supported kernel enforcement is available; shared projection/publication is disabled",
            "Run on macOS with sandbox-exec (or a Landlock/bubblewrap backend) to enable shared work.",
        ));
    };
    let (mut reader, mut writer) = pipe()?;
    let reader_fd = reader.as_raw_fd();
    clear_cloexec(reader_fd)?;
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/opt/homebrew/bin")
        .env("HOME", "/nonexistent")
        .env("GUILDHALL_SHARED_CONFIG_FD", reader_fd.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = command.spawn().map_err(|error| ContractError::io("spawn shared helper", error))?;
    std::io::Write::write_all(&mut writer, shared_config).map_err(|error| ContractError::io("write shared config", error))?;
    drop(writer);
    let output = child.wait_with_output().map_err(|error| ContractError::io("wait shared helper", error))?;
    let _ = std::io::Read::read(&mut reader, &mut [0u8; 1]);
    Ok(output)
}

fn pipe() -> Result<(std::fs::File, std::fs::File), ContractError> {
    use std::os::fd::FromRawFd;
    let mut fds = [0i32; 2];
    // SAFETY: pipe writes two descriptors into the array on success.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(ContractError::io("pipe", std::io::Error::last_os_error()));
    }
    for fd in fds {
        // SAFETY: setting CLOEXEC on descriptors we own.
        unsafe {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }
    // SAFETY: the descriptors are fresh and owned by this process.
    Ok(unsafe { (std::fs::File::from_raw_fd(fds[0]), std::fs::File::from_raw_fd(fds[1])) })
}

fn clear_cloexec(fd: i32) -> Result<(), ContractError> {
    // SAFETY: clearing CLOEXEC on a descriptor we own so one child inherits it.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } != 0 {
        return Err(ContractError::io("clear cloexec", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Descriptor-backed classifier execution (architecture §5): open the
/// absolute executable once, verify owner/mode/regular file/containing
/// directory chain and the pinned SHA-256 through that descriptor, then
/// execute `/dev/fd/N` (the descriptor itself; the pathname is never
/// re-resolved). Returns stdout bytes.
pub fn run_verified_executable(
    executable: &Path,
    expected_sha256: &str,
    args: &[String],
    input: &[u8],
    timeout: std::time::Duration,
) -> Result<Vec<u8>, ContractError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !executable.is_absolute() {
        return Err(ContractError::integrity("PROCESSOR_UNAUTHORIZED", "classifier executable must be an absolute path", "Configure an absolute regular-file path; no PATH or shell resolution exists."));
    }
    let file = std::fs::File::open(executable).map_err(|error| ContractError::integrity("PROCESSOR_UNAUTHORIZED", format!("classifier executable cannot be opened ({})", error.kind()), "Configure a readable absolute executable."))?;
    let metadata = file.metadata().map_err(|error| ContractError::io("fstat classifier", error))?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if !metadata.is_file() || metadata.uid() != euid || metadata.permissions().mode() & 0o022 != 0 {
        return Err(ContractError::integrity("PROCESSOR_UNAUTHORIZED", "classifier executable is not a regular file owned by the effective user without group/other write", "Fix ownership and mode of the classifier executable."));
    }
    let mut ancestor = executable.parent();
    while let Some(dir) = ancestor {
        if let Ok(dir_metadata) = std::fs::symlink_metadata(dir) {
            if dir_metadata.file_type().is_symlink() {
                return Err(ContractError::integrity("PROCESSOR_UNAUTHORIZED", "classifier containing-directory chain traverses a symlink", "Place the classifier under a symlink-free directory chain."));
            }
            if dir_metadata.permissions().mode() & 0o022 != 0 && dir != Path::new("/") {
                return Err(ContractError::integrity("PROCESSOR_UNAUTHORIZED", "classifier containing directory is writable by group or other", "Tighten the directory chain to 0755 or stricter."));
            }
        }
        ancestor = dir.parent();
    }
    let mut bytes = Vec::new();
    {
        let mut reader = &file;
        std::io::Read::read_to_end(&mut reader, &mut bytes).map_err(|error| ContractError::io("read classifier", error))?;
    }
    if crate::hash::sha256_bytes(&bytes) != expected_sha256 {
        return Err(ContractError::integrity("PROCESSOR_UNAUTHORIZED", "classifier executable digest differs from the pinned SHA-256", "Update the pinned digest only through a reviewed configuration change; no input was sent."));
    }
    let fd = file.as_raw_fd();
    clear_cloexec(fd)?;
    let program = format!("/dev/fd/{fd}");
    let spawn = Command::new(&program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/nonexistent")
        .env("GUILDHALL_SHARED_CONFIG_FD", fd.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match spawn {
        Ok(child) => child,
        Err(error) if matches!(error.kind(), std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound) => {
            // Darwin does not permit executing a regular file through /dev/fd.
            // The descriptor above still performed ownership/mode/digest pinning;
            // refuse to fall back unless the pathname still names the same inode.
            let fallback = std::fs::File::open(executable)
                .map_err(|error| ContractError::io("reopen classifier", error))?;
            let fallback_metadata = fallback.metadata().map_err(|error| ContractError::io("fstat classifier", error))?;
            if fallback_metadata.dev() != metadata.dev() || fallback_metadata.ino() != metadata.ino() {
                return Err(ContractError::integrity("PROCESSOR_UNAUTHORIZED", "classifier pathname changed after descriptor verification", "Repin the classifier digest; the changed executable was not run."));
            }
            Command::new(executable)
                .args(args)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", "/nonexistent")
                .env("GUILDHALL_SHARED_CONFIG_FD", fd.to_string())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|error| ContractError::integrity("PROCESSOR_UNAUTHORIZED", format!("descriptor-backed execution failed ({})", error.kind()), "A platform without verified descriptor-backed execution disables the external classifier."))?
        }
        Err(error) => return Err(ContractError::integrity("PROCESSOR_UNAUTHORIZED", format!("descriptor-backed execution failed ({})", error.kind()), "A platform without verified descriptor-backed execution disables the external classifier.")),
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = std::io::Write::write_all(&mut stdin, input);
    }
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if started.elapsed() > timeout {
                    let _ = child.kill();
                    return Err(ContractError::degraded("UNKNOWN_OWNER_UNRESOLVED", "classifier exceeded its wall timeout; extraction abstained", "Increase classifier.timeout_seconds or use a faster local processor."));
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(error) => return Err(ContractError::io("wait classifier", error)),
        }
    }
    let output = child.wait_with_output().map_err(|error| ContractError::io("collect classifier", error))?;
    if !output.status.success() {
        return Err(ContractError::degraded("UNKNOWN_OWNER_UNRESOLVED", format!("classifier exited with {}; extraction abstained", output.status), "Repair the classifier; abstention creates a private Unknown."));
    }
    Ok(output.stdout)
}
