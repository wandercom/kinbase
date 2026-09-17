//! Shared by the integration tests; each uses what it needs.
#![allow(dead_code)]

use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::Mutex;

/// One child starts at a time. On macOS a pipe another test is creating is
/// not close-on-exec until just after it exists, and a kinbase child started
/// in that instant inherits it and refuses to run ("inherited descriptor(s)
/// outside the frozen allowlist").
static SPAWN: Mutex<()> = Mutex::new(());

pub trait SpawnAlone {
    /// `Command::spawn`, with no other child starting meanwhile.
    fn spawn_alone(&mut self) -> std::io::Result<Child>;
    /// `Command::output`: stdin closed, stdout and stderr captured.
    fn output_alone(&mut self) -> std::io::Result<Output>;
    /// `Command::status`.
    fn status_alone(&mut self) -> std::io::Result<ExitStatus>;
}

impl SpawnAlone for Command {
    fn spawn_alone(&mut self) -> std::io::Result<Child> {
        let _guard = SPAWN
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.spawn()
    }

    fn output_alone(&mut self) -> std::io::Result<Output> {
        self.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        self.spawn_alone()?.wait_with_output()
    }

    fn status_alone(&mut self) -> std::io::Result<ExitStatus> {
        self.spawn_alone()?.wait()
    }
}
