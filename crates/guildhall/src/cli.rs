use crate::HostKind;
use crate::command_types::*;
use crate::error::ContractError;
use std::path::PathBuf;

pub fn run(json: bool, command: Command) {
    let result = dispatch(json, command);
    if let Err(error) = result {
        if json {
            let value = serde_json::to_value(&error)
                .unwrap_or_else(|_| serde_json::json!({"code":"RUN_INTEGRITY_FAILED"}));
            println!("{}", crate::json::canonical_text(&value));
        } else {
            println!("{}: {}", error.code, error.message);
            println!("remediation: {}", error.remediation);
            println!("retryable: {}", error.retryable);
            println!("evidence_id: {}", error.evidence_id);
        }
        std::process::exit(error.exit());
    }
}

fn dispatch(json: bool, command: Command) -> Result<(), ContractError> {
    match command {
        Command::Company(CompanyCommand::Init { config }) => {
            crate::company::init(&config, json).map_err(internal)?;
        }
        Command::Company(CompanyCommand::Serve { config }) => {
            crate::company::serve(&config, json).map_err(internal)?;
        }
        Command::Repo(RepoCommand::Issue { repo, company }) => {
            crate::repository::issue_certificate(&repo, &company, json).map_err(internal)?;
        }
        Command::Repo(RepoCommand::Init { repo, certificate }) => {
            crate::repository::init(&repo, &certificate, json).map_err(internal)?;
        }
        Command::Repo(RepoCommand::PublishManifest { repo }) => {
            crate::repository::publish_manifest(&repo, json).map_err(internal)?;
        }
        Command::Status { repo, as_of } => {
            let repo = repo
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let as_of = resolve_as_of(as_of.as_deref())?;
            crate::repository::status(&repo, &as_of, json).map_err(internal)?;
        }
        Command::Doctor { host, repo } => {
            let repo = repo
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            crate::repository::doctor(
                &repo,
                host.map(|h| {
                    if h == Host::Codex {
                        HostKind::Codex
                    } else {
                        HostKind::Claude
                    }
                }),
                json,
            )
            .map_err(internal)?;
        }
        Command::Ingest {
            source_kind,
            source,
            repo,
            checkpoint,
        } => {
            let repo = repo
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            crate::ingest::ingest(&repo, &source_kind, &source, checkpoint.as_deref(), json)
                .map_err(internal)?;
        }
        Command::Corpus(CorpusCommand::Rebuild { store, repo, as_of }) => {
            let repo = repo
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let as_of = resolve_as_of(as_of.as_deref())?;
            crate::corpus::rebuild(&repo, store_to_kind(store), &as_of, json).map_err(internal)?;
        }
        Command::Fsck { repo, full, as_of } => {
            let repo = repo
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let as_of = resolve_as_of(as_of.as_deref())?;
            crate::repository::fsck(&repo, full, &as_of, json).map_err(internal)?;
        }
        Command::Explain {
            logical_key,
            repo,
            decision,
            as_of,
        } => {
            let repo = repo
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let as_of = resolve_as_of(as_of.as_deref())?;
            crate::corpus::explain(&repo, &logical_key, &decision, &as_of, json).map_err(internal)?;
        }
        Command::Project {
            repo,
            task,
            decision,
            working_set,
            as_of,
        } => {
            let repo = repo
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let as_of = resolve_as_of(as_of.as_deref())?;
            crate::projector::run(&repo, &task, &decision, &working_set, &as_of, json)
                .map_err(internal)?;
        }
        Command::Session(SessionCommand::Start { host, repo }) => {
            let repo = repo
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            crate::session::start(&repo, host_kind(host), json).map_err(internal)?;
        }
        Command::Session(SessionCommand::Observe { session, event }) => {
            crate::session::observe(&session, &event, json).map_err(internal)?;
        }
        Command::Session(SessionCommand::Checkpoint { session }) => {
            crate::session::checkpoint(&session, json).map_err(internal)?;
        }
        Command::Session(SessionCommand::End { session }) => {
            crate::session::end(&session, json).map_err(internal)?;
        }
        Command::Proposals(command) => {
            crate::proposals::dispatch(command, json).map_err(internal)?;
        }
        Command::Questions(command) => {
            crate::questions::dispatch(command, json).map_err(internal)?;
        }
        Command::Hooks(command) => {
            crate::hooks::dispatch(command, json).map_err(internal)?;
        }
        Command::Experiment(command) => {
            crate::experiment::dispatch(command, json).map_err(internal)?;
        }
    }
    Ok(())
}

fn internal(error: crate::error::ContractError) -> ContractError {
    error
}

fn resolve_as_of(explicit: Option<&str>) -> Result<crate::time::AsOf, ContractError> {
    crate::time::resolve_as_of(explicit).map_err(|message| {
        ContractError::new(
            "CONFIG_INVARIANT",
            message,
            "Pass --as-of as RFC 3339 UTC with millisecond precision, e.g. 2026-09-07T12:00:00.000Z.",
            false,
            crate::error::ExitCode::Refused,
        )
    })
}

fn store_to_kind(store: Store) -> crate::StoreKind {
    match store {
        Store::Personal => crate::StoreKind::Personal,
        Store::Company => crate::StoreKind::Company,
        Store::Codebase => crate::StoreKind::Codebase,
    }
}

fn host_kind(host: Host) -> crate::HostKind {
    match host {
        Host::Codex => crate::HostKind::Codex,
        Host::Claude => crate::HostKind::Claude,
    }
}
