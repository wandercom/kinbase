use crate::command_types::*;
use crate::error::ContractError;
use crate::Cli;
use clap::error::ErrorKind;
use clap::Parser;
use std::path::PathBuf;

/// Parse the CLI while preserving the process contract.
///
/// Clap's default parser exits with its own usage code and prose. Guildhall
/// instead maps every refusal to the closed error taxonomy before any
/// launcher or repository state is touched.
pub fn parse_or_exit() -> Cli {
    match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp
                    | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
                    | ErrorKind::DisplayVersion
            ) {
                error.print().ok();
                std::process::exit(0);
            }

            let args: Vec<String> = std::env::args().skip(1).collect();
            let json = args.iter().any(|arg| arg == "--json");
            let contract_error = usage_error(&args, error.to_string());
            print_error(json, &contract_error);
            std::process::exit(contract_error.exit());
        }
    }
}

pub fn run(json: bool, command: Command) {
    let result = dispatch(json, command);
    if let Err(error) = result {
        print_error(json, &error);
        std::process::exit(error.exit());
    }
}

fn print_error(json: bool, error: &ContractError) {
    if json {
        let document = crate::output::error_document(error);
        eprintln!("{}", crate::json::canonical_text(&document));
    } else {
        println!("{}: {}", error.code, error.message);
        println!("remediation: {}", error.remediation);
        println!("retryable: {}", error.retryable);
        println!("evidence_id: {}", error.evidence_id);
    }
}

/// Convert parser refusals to the closed contract.
///
/// A proposal that names no candidate is an approval problem (exit 2), not a
/// generic parser problem. Every other malformed invocation is a configuration
/// invariant and exits 4 without running a command.
fn usage_error(args: &[String], _detail: String) -> ContractError {
    if proposals_names_no_candidate(args) {
        ContractError::user_action(
            "APPROVAL_EXPIRED",
            "no candidate is named",
            "Create or review a candidate before deciding or showing it.",
        )
    } else {
        ContractError::invariant("malformed command line; no state was changed")
    }
}

fn proposals_names_no_candidate(args: &[String]) -> bool {
    if args.first().map(String::as_str) != Some("proposals") {
        return false;
    }
    if !matches!(
        args.get(1).map(String::as_str),
        Some("decide") | Some("show")
    ) {
        return false;
    }
    if args
        .windows(2)
        .any(|window| window[0] == "--destination" && window[1] == "codebase:none")
    {
        return true;
    }

    let rest = &args[2..];
    let mut index = 0;
    while index < rest.len() {
        let arg = rest[index].as_str();
        if arg == "--json" {
            index += 1;
        } else if arg.starts_with("--") {
            match arg {
                "--reject" | "--defer" | "--escalate" => index += 1,
                _ => index += 2,
            }
        } else {
            return false;
        }
    }
    true
}

fn dispatch(json: bool, command: Command) -> Result<(), ContractError> {
    let launcher = crate::launcher::Launcher::load()?;
    match command {
        Command::Company(CompanyCommand::Init { config }) => {
            crate::company::init(&config, json).map_err(internal)?;
        }
        Command::Company(CompanyCommand::Serve { config }) => {
            crate::company::serve(&config, json).map_err(internal)?;
        }
        Command::Repo(RepoCommand::Issue { repo, company }) => {
            crate::repository::issue_certificate(launcher, &repo, &company, json)
                .map_err(internal)?;
        }
        Command::Repo(RepoCommand::Init { repo, certificate }) => {
            crate::repository::init(launcher, &repo, &certificate, json).map_err(internal)?;
        }
        Command::Repo(RepoCommand::PublishManifest { repo }) => {
            crate::repository::publish_manifest(launcher, &repo, json).map_err(internal)?;
        }
        Command::Status { repo, as_of } => {
            let repo = repo
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let as_of = resolve_as_of(as_of.as_deref())?;
            crate::repository::status(launcher, &repo, &as_of, json).map_err(internal)?;
        }
        Command::Doctor { host, repo } => {
            let repo = repo
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            crate::repository::doctor(
                launcher,
                &repo,
                host.map(|h| match h {
                    Host::Codex => "codex",
                    Host::Claude => "claude",
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
            crate::ingest::ingest(
                &repo,
                &source_kind,
                &source,
                checkpoint.as_deref(),
                launcher.shared.classifier.as_ref(),
                json,
            )
            .map_err(internal)?;
        }
        Command::Classifier {} => {
            let model = launcher
                .shared
                .classifier
                .as_ref()
                .map(|classifier| classifier.model.clone())
                .unwrap_or_else(|| "deterministic".to_owned());
            crate::classifier::run(&model, json)?;
        }
        Command::Corpus(CorpusCommand::Rebuild { store, repo, as_of, reducer_version }) => {
            let repo = repo
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let as_of = resolve_as_of(as_of.as_deref())?;
            crate::corpus::rebuild(&launcher, &repo, store_to_kind(store), &as_of, reducer_version, json)
                .map_err(internal)?;
        }
        Command::Fsck { repo, full, as_of } => {
            let repo = repo
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let as_of = resolve_as_of(as_of.as_deref())?;
            crate::repository::fsck(launcher, &repo, full, &as_of, json).map_err(internal)?;
        }
        Command::Explain {
            logical_key,
            repo,
            decision,
            as_of,
            authority_cursor,
        } => {
            let repo = repo
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let as_of = resolve_as_of(as_of.as_deref())?;
            crate::corpus::explain(&launcher, &repo, &logical_key, &decision, &as_of, authority_cursor, json)
                .map_err(internal)?;
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
            crate::projector::run(&launcher, &repo, &task, &decision, &working_set, &as_of, json)
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
