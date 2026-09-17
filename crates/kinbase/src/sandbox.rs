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
    for name in ["KINBASE_CLIENT_KEY_FD", "KINBASE_SHARED_CONFIG_FD"] {
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
    Some(PathBuf::from(
        String::from_utf8_lossy(&buffer[..end]).into_owned(),
    ))
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
        let under_personal = personal_identity
            .is_some_and(|(dev, ino)| descriptor.dev == dev && descriptor.ino == ino)
            || (personal_canonical.as_ref().zip(descriptor.path.as_ref()))
                .is_some_and(|(root, path)| path.starts_with(root));
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
            "Launch with only the declared descriptors (stdio plus explicit KINBASE_*_FD values).",
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
pub fn profile(
    personal_root: &Path,
    allowed_roots: &[PathBuf],
    company_port: Option<u16>,
) -> String {
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
        lines.push(format!(
            "(allow file-read* file-write* (subpath \"{quoted}\"))"
        ));
    }
    if let Some(port) = company_port {
        lines.push(format!(
            "(allow network-outbound (remote ip \"localhost:{port}\"))"
        ));
    }
    let personal = personal_root.to_string_lossy().replace('"', "\\\"");
    lines.push(format!(
        "(deny file-read* file-write* file-read-metadata (subpath \"{personal}\"))"
    ));
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
pub fn denial_probe(
    personal_root: &Path,
    allowed_roots: &[PathBuf],
    company_port: Option<u16>,
) -> ProbeResult {
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
    let exe =
        std::env::current_exe().map_err(|error| ContractError::io("current executable", error))?;
    let profile = profile(personal_root, allowed_roots, company_port);
    let mut command = if sandbox_available() {
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command.arg("-p").arg(&profile).arg(&exe);
        command
    } else {
        return Err(ContractError::integrity(
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
        .env("KINBASE_SHARED_CONFIG_FD", reader_fd.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = command
        .spawn()
        .map_err(|error| ContractError::io("spawn shared helper", error))?;
    std::io::Write::write_all(&mut writer, shared_config)
        .map_err(|error| ContractError::io("write shared config", error))?;
    drop(writer);
    let output = child
        .wait_with_output()
        .map_err(|error| ContractError::io("wait shared helper", error))?;
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
    Ok(unsafe {
        (
            std::fs::File::from_raw_fd(fds[0]),
            std::fs::File::from_raw_fd(fds[1]),
        )
    })
}

fn clear_cloexec(fd: i32) -> Result<(), ContractError> {
    // SAFETY: clearing CLOEXEC on a descriptor we own so one child inherits it.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } != 0 {
        return Err(ContractError::io(
            "clear cloexec",
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

/// An executable opened once and verified through that descriptor.
struct VerifiedExecutable {
    file: std::fs::File,
    metadata: std::fs::Metadata,
}

/// What verifying a pinned executable found: the digest it read, when it got
/// that far, and the rule that refused the executable, if any. These are the
/// checks `run_verified_executable` makes before it runs anything.
pub struct PinnedCheck {
    pub observed_sha256: Option<String>,
    pub refusal: Option<ContractError>,
}

pub fn check_pinned_executable(executable: &Path, expected_sha256: &str) -> PinnedCheck {
    match open_verified(executable, expected_sha256) {
        Ok((_, observed)) => PinnedCheck {
            observed_sha256: Some(observed),
            refusal: None,
        },
        Err((observed, error)) => PinnedCheck {
            observed_sha256: observed,
            refusal: Some(error),
        },
    }
}

/// Open the absolute executable once and verify owner, mode, regular file,
/// the containing directory chain and the pinned SHA-256 through that
/// descriptor. A refusal carries the digest when it was read.
fn open_verified(
    executable: &Path,
    expected_sha256: &str,
) -> Result<(VerifiedExecutable, String), (Option<String>, ContractError)> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let refuse = |error: ContractError| (None, error);
    if !executable.is_absolute() {
        return Err(refuse(ContractError::integrity(
            "PROCESSOR_UNAUTHORIZED",
            "classifier executable must be an absolute path",
            "Configure an absolute regular-file path; no PATH or shell resolution exists.",
        )));
    }
    let file = std::fs::File::open(executable).map_err(|error| {
        refuse(ContractError::integrity(
            "PROCESSOR_UNAUTHORIZED",
            format!("classifier executable cannot be opened ({})", error.kind()),
            "Configure a readable absolute executable.",
        ))
    })?;
    let metadata = file
        .metadata()
        .map_err(|error| refuse(ContractError::io("fstat classifier", error)))?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if !metadata.is_file() || metadata.uid() != euid || metadata.permissions().mode() & 0o022 != 0 {
        return Err(refuse(ContractError::integrity(
            "PROCESSOR_UNAUTHORIZED",
            "classifier executable is not a regular file owned by the effective user without group/other write",
            "Fix ownership and mode of the classifier executable.",
        )));
    }
    let mut ancestor = executable.parent();
    while let Some(dir) = ancestor {
        if let Ok(dir_metadata) = std::fs::symlink_metadata(dir) {
            if dir_metadata.file_type().is_symlink() {
                return Err(refuse(ContractError::integrity(
                    "PROCESSOR_UNAUTHORIZED",
                    "classifier containing-directory chain traverses a symlink",
                    "Place the classifier under a symlink-free directory chain.",
                )));
            }
            if dir_metadata.permissions().mode() & 0o022 != 0 && dir != Path::new("/") {
                return Err(refuse(ContractError::integrity(
                    "PROCESSOR_UNAUTHORIZED",
                    "classifier containing directory is writable by group or other",
                    "Tighten the directory chain to 0755 or stricter.",
                )));
            }
        }
        ancestor = dir.parent();
    }
    let mut bytes = Vec::new();
    {
        let mut reader = &file;
        std::io::Read::read_to_end(&mut reader, &mut bytes)
            .map_err(|error| refuse(ContractError::io("read classifier", error)))?;
    }
    let observed = crate::hash::sha256_bytes(&bytes);
    if observed != expected_sha256 {
        // A rebuilt classifier stops every classification until it is
        // re-pinned; say what was read and how to pin it.
        let error = ContractError::integrity(
            "PROCESSOR_UNAUTHORIZED",
            "classifier executable digest differs from the pinned SHA-256",
            "Review the executable, then record its digest (`shasum -a 256` of the configured \
             path; `kinbase doctor` shows it as classifier.observed_sha256) as \
             classifier.executable_sha256 in a reviewed configuration change; no input was sent.",
        )
        .with_detail(json!({
            "pinned_sha256": expected_sha256,
            "observed_sha256": observed
        }));
        return Err((Some(observed), error));
    }
    Ok((VerifiedExecutable { file, metadata }, observed))
}

/// The most classifier stdout kept (the input bound).
pub const MAX_CLASSIFIER_OUTPUT: usize = 8 * 1024 * 1024;
/// The most classifier stderr kept; only its first line is reported.
const MAX_CLASSIFIER_STDERR: usize = 64 * 1024;
/// How long output may keep arriving after the classifier exits.
const OUTPUT_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

enum OutputProblem {
    TooLarge,
    Late,
}

/// A pipe drained on its own thread, keeping at most `limit` bytes (the rest
/// is read and discarded, so the writer never blocks on a full pipe).
struct BoundedReader {
    receiver: std::sync::mpsc::Receiver<(Vec<u8>, bool)>,
}

impl BoundedReader {
    fn collect(self, deadline: std::time::Instant) -> Result<Vec<u8>, OutputProblem> {
        let wait = deadline.saturating_duration_since(std::time::Instant::now());
        match self.receiver.recv_timeout(wait) {
            Ok((_, true)) => Err(OutputProblem::TooLarge),
            Ok((bytes, false)) => Ok(bytes),
            Err(_) => Err(OutputProblem::Late),
        }
    }
}

fn bounded_reader(mut pipe: impl std::io::Read + Send + 'static, limit: usize) -> BoundedReader {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        let mut over = false;
        let mut chunk = [0u8; 64 * 1024];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    let room = limit.saturating_sub(kept.len());
                    if read > room {
                        over = true;
                    }
                    kept.extend_from_slice(&chunk[..read.min(room)]);
                }
            }
        }
        let _ = sender.send((kept, over));
    });
    BoundedReader { receiver }
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
    use std::os::unix::fs::MetadataExt;
    let (VerifiedExecutable { file, metadata }, _) =
        open_verified(executable, expected_sha256).map_err(|(_, error)| error)?;
    let fd = file.as_raw_fd();
    // The verified descriptor is exposed to exactly this child: CLOEXEC stays
    // set in the parent and is cleared after fork, so a concurrently spawned
    // sibling never inherits another child's descriptor (which its own
    // startup attestation would rightly refuse).
    let inherit_verified_descriptor = move || -> std::io::Result<()> {
        // SAFETY: fcntl is async-signal-safe and the descriptor is ours.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    };
    let program = format!("/dev/fd/{fd}");
    let mut command = Command::new(&program);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/nonexistent")
        .env("KINBASE_SHARED_CONFIG_FD", fd.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Its own process group, so a timeout reaches everything it started.
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    // SAFETY: the hook only calls fcntl, which is async-signal-safe.
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(&mut command, inherit_verified_descriptor);
    }
    let spawn = command.spawn();
    let mut child = match spawn {
        Ok(child) => child,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound
            ) =>
        {
            // Darwin does not permit executing a regular file through /dev/fd.
            // The descriptor above still performed ownership/mode/digest pinning;
            // refuse to fall back unless the pathname still names the same inode.
            let fallback = std::fs::File::open(executable)
                .map_err(|error| ContractError::io("reopen classifier", error))?;
            let fallback_metadata = fallback
                .metadata()
                .map_err(|error| ContractError::io("fstat classifier", error))?;
            if fallback_metadata.dev() != metadata.dev()
                || fallback_metadata.ino() != metadata.ino()
            {
                return Err(ContractError::integrity(
                    "PROCESSOR_UNAUTHORIZED",
                    "classifier pathname changed after descriptor verification",
                    "Repin the classifier digest; the changed executable was not run.",
                ));
            }
            let mut fallback_command = Command::new(executable);
            fallback_command
                .args(args)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", "/nonexistent")
                .env("KINBASE_SHARED_CONFIG_FD", fd.to_string())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            std::os::unix::process::CommandExt::process_group(&mut fallback_command, 0);
            // SAFETY: the hook only calls fcntl, which is async-signal-safe.
            unsafe {
                std::os::unix::process::CommandExt::pre_exec(
                    &mut fallback_command,
                    inherit_verified_descriptor,
                );
            }
            fallback_command
                .spawn()
                .map_err(|error| ContractError::integrity("PROCESSOR_UNAUTHORIZED", format!("descriptor-backed execution failed ({})", error.kind()), "A platform without verified descriptor-backed execution disables the external classifier."))?
        }
        Err(error) => {
            return Err(ContractError::integrity(
                "PROCESSOR_UNAUTHORIZED",
                format!("descriptor-backed execution failed ({})", error.kind()),
                "A platform without verified descriptor-backed execution disables the external classifier.",
            ));
        }
    };
    // Write stdin independently and read both pipes concurrently. A
    // classifier can emit more than a pipe buffer of atoms before consuming
    // all input; doing this synchronously deadlocks both processes.
    let stdin_writer = child.stdin.take().map(|mut stdin| {
        let input = input.to_vec();
        std::thread::spawn(move || {
            let _ = std::io::Write::write_all(&mut stdin, &input);
            // Drop closes stdin even if the child exits before reading all bytes.
        })
    });
    let stdout_reader = child
        .stdout
        .take()
        .map(|pipe| bounded_reader(pipe, MAX_CLASSIFIER_OUTPUT));
    let stderr_reader = child
        .stderr
        .take()
        .map(|pipe| bounded_reader(pipe, MAX_CLASSIFIER_STDERR));
    let group = child.id() as libc::pid_t;
    let started = std::time::Instant::now();
    let status = loop {
        // Peek at the exit without reaping: while the exited child is an
        // unreaped zombie its process-group id cannot be reused, so the group
        // can be signalled safely before the child is collected.
        // SAFETY: waitid writes only into `info`, a zeroed siginfo_t.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let peeked = unsafe {
            libc::waitid(
                libc::P_PID,
                group as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if peeked != 0 {
            return Err(ContractError::io(
                "wait classifier",
                std::io::Error::last_os_error(),
            ));
        }
        // SAFETY: si_pid is set by waitid (zero while the child runs).
        let exited = unsafe { info.si_pid() } != 0;
        if exited {
            // What the classifier left running in its group goes with it,
            // so the pipes close.
            // SAFETY: killpg only signals our child's (still unreaped) group.
            unsafe {
                libc::killpg(group, libc::SIGKILL);
            }
            break child
                .wait()
                .map_err(|error| ContractError::io("wait classifier", error))?;
        }
        if started.elapsed() > timeout {
            // The whole group, not just the child: a grandchild kept running
            // and holding the pipes. Nothing waits on the pipe readers or the
            // stdin writer afterwards, since a descendant outside the group
            // could hold them forever; they end when the last holder does.
            // SAFETY: killpg only signals our child's (still unreaped) group.
            unsafe {
                libc::killpg(group, libc::SIGKILL);
            }
            let _ = child.kill();
            let _ = child.wait();
            return Err(ContractError::degraded(
                "UNKNOWN_OWNER_UNRESOLVED",
                "classifier exceeded its wall timeout; extraction abstained",
                "Increase classifier.timeout_seconds or use a faster local processor.",
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    // Output that has not arrived within the grace period is not waited for.
    drop(stdin_writer);
    let deadline = std::time::Instant::now() + OUTPUT_GRACE;
    let stdout = stdout_reader
        .map(|reader| reader.collect(deadline))
        .unwrap_or_else(|| Ok(Vec::new()));
    let stderr = stderr_reader
        .map(|reader| reader.collect(deadline))
        .unwrap_or_else(|| Ok(Vec::new()))
        .unwrap_or_default();
    let stdout = match stdout {
        Ok(stdout) => stdout,
        Err(OutputProblem::TooLarge) => {
            return Err(ContractError::limit(
                format!(
                    "classifier output exceeds the {MAX_CLASSIFIER_OUTPUT}-byte bound; extraction abstained"
                ),
                serde_json::json!({"refused_count": 1, "omitted_count": 1, "ceiling_bytes": MAX_CLASSIFIER_OUTPUT}),
            ));
        }
        Err(OutputProblem::Late) => {
            return Err(ContractError::degraded(
                "UNKNOWN_OWNER_UNRESOLVED",
                "classifier output did not close after it exited; extraction abstained",
                "Repair the classifier so its output ends when it does.",
            ));
        }
    };
    if !status.success() {
        // The child's own words travel with the failure. An exit status alone
        // cannot tell a provider pushing back from a malformed answer, and the
        // caller decides whether to wait or to retry on exactly that.
        let excerpt: String = String::from_utf8_lossy(&stderr)
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or_default()
            .chars()
            .take(240)
            .collect();
        return Err(ContractError::degraded(
            "UNKNOWN_OWNER_UNRESOLVED",
            if excerpt.is_empty() {
                format!("classifier exited with {status}; extraction abstained")
            } else {
                format!("classifier exited with {status}: {excerpt}; extraction abstained")
            },
            "Repair the classifier; abstention creates a private Unknown.",
        ));
    }
    Ok(stdout)
}

#[cfg(test)]
mod pinned_check_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A directory whose whole chain the verifier accepts (no symlink, no
    /// group/other-writable ancestor); `/tmp` itself is 1777. An explicit
    /// `KINBASE_TEST_VERIFIED_DIR` is tried first.
    fn accepted_base() -> PathBuf {
        let candidates: Vec<PathBuf> = [
            std::env::var_os("KINBASE_TEST_VERIFIED_DIR").map(PathBuf::from),
            Some(std::env::temp_dir()),
            std::env::var_os("HOME").map(PathBuf::from),
            Some(PathBuf::from(env!("CARGO_MANIFEST_DIR"))),
        ]
        .into_iter()
        .flatten()
        .collect();
        candidates
            .iter()
            .filter_map(|dir| dir.canonicalize().ok())
            .find(|dir| {
                dir.ancestors().all(|ancestor| {
                    std::fs::symlink_metadata(ancestor).is_ok_and(|metadata| {
                        ancestor == Path::new("/")
                            || (!metadata.file_type().is_symlink()
                                && metadata.permissions().mode() & 0o022 == 0)
                    })
                })
            })
            .unwrap_or_else(|| {
                panic!(
                    "no directory chain the classifier verifier accepts among {candidates:?}; \
                     set KINBASE_TEST_VERIFIED_DIR to one"
                )
            })
    }

    #[test]
    fn a_rebuilt_executable_is_refused_with_the_digest_it_now_has() {
        let base = accepted_base();
        let dir = tempfile::TempDir::new_in(&base).expect("tempdir");
        let executable = dir.path().join("classifier");
        let body = b"#!/bin/sh\nexit 0\n";
        std::fs::write(&executable, body).expect("write");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
            .expect("chmod");
        let digest = crate::hash::sha256_bytes(body);

        let pinned = check_pinned_executable(&executable, &digest);
        assert!(
            pinned.refusal.is_none(),
            "{:?}",
            pinned.refusal.map(|error| error.message)
        );
        assert_eq!(pinned.observed_sha256.as_deref(), Some(digest.as_str()));

        let rebuilt = check_pinned_executable(&executable, &"0".repeat(64));
        assert_eq!(rebuilt.observed_sha256.as_deref(), Some(digest.as_str()));
        let error = rebuilt.refusal.expect("a stale pin is refused");
        assert_eq!(error.code, "PROCESSOR_UNAUTHORIZED");
        assert_eq!(
            error
                .detail
                .as_ref()
                .and_then(|detail| detail["observed_sha256"].as_str()),
            Some(digest.as_str())
        );
        assert!(
            error.remediation.contains("shasum -a 256"),
            "{}",
            error.remediation
        );

        let relative = check_pinned_executable(Path::new("classifier"), &digest);
        assert!(relative.refusal.is_some());
        assert!(relative.observed_sha256.is_none());
    }

    fn pinned_script(dir: &Path, body: &str) -> (PathBuf, String) {
        let executable = dir.join("classifier");
        std::fs::write(&executable, body).expect("write");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
            .expect("chmod");
        (executable, crate::hash::sha256_bytes(body.as_bytes()))
    }

    #[test]
    fn a_timeout_ends_a_classifier_whose_child_holds_its_output() {
        let base = accepted_base();
        let dir = tempfile::TempDir::new_in(&base).expect("tempdir");
        // The classifier starts a long-lived child that inherits stdout,
        // then hangs; before, the wall timeout killed only the classifier
        // and then waited on the pipe the child still held.
        let (executable, digest) = pinned_script(
            dir.path(),
            "#!/bin/sh
sleep 30 &
sleep 30
",
        );
        let started = std::time::Instant::now();
        let error = run_verified_executable(
            &executable,
            &digest,
            &[],
            b"",
            std::time::Duration::from_millis(300),
        )
        .expect_err("timed out");
        assert!(error.message.contains("wall timeout"), "{}", error.message);
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }

    #[test]
    fn classifier_output_is_bounded() {
        let base = accepted_base();
        let dir = tempfile::TempDir::new_in(&base).expect("tempdir");
        let (executable, digest) = pinned_script(
            dir.path(),
            "#!/bin/sh
head -c 9000000 /dev/zero
",
        );
        let error = run_verified_executable(
            &executable,
            &digest,
            &[],
            b"",
            std::time::Duration::from_secs(20),
        )
        .expect_err("over the bound");
        assert_eq!(error.code, "LIMIT_EXCEEDED");

        let (executable, digest) = pinned_script(
            dir.path(),
            "#!/bin/sh
printf ok
",
        );
        let output = run_verified_executable(
            &executable,
            &digest,
            &[],
            b"",
            std::time::Duration::from_secs(20),
        )
        .expect("small output");
        assert_eq!(output, b"ok");
    }

    #[test]
    fn an_exited_classifier_does_not_wait_on_a_detached_descendant() {
        let base = accepted_base();
        let dir = tempfile::TempDir::new_in(&base).expect("tempdir");
        // A descendant in its own session keeps the output pipe open after
        // the classifier exits; the run ends within the grace period.
        let (executable, digest) = pinned_script(
            dir.path(),
            "#!/bin/sh
printf done
( trap '' HUP; exec perl -e 'use POSIX; POSIX::setsid(); sleep 30' ) &
exit 0
",
        );
        let started = std::time::Instant::now();
        let result = run_verified_executable(
            &executable,
            &digest,
            &[],
            b"",
            std::time::Duration::from_secs(20),
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        match result {
            Ok(output) => assert_eq!(output, b"done"),
            Err(error) => assert!(error.message.contains("did not close"), "{}", error.message),
        }
    }
}
