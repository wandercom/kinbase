use clap::{Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(subcommand)]
    Company(CompanyCommand),
    #[command(subcommand)]
    Repo(RepoCommand),
    Status {
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long = "as-of", help = "Explicit RFC 3339 UTC millisecond reducer instant; defaults to the recorded proof clock")]
        as_of: Option<String>,
    },
    Doctor {
        #[arg(long, value_enum)]
        host: Option<Host>,
        #[arg(long)]
        repo: Option<PathBuf>,
    },
    Ingest {
        source_kind: String,
        source: PathBuf,
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long)]
        checkpoint: Option<String>,
    },
    Classifier {},
    #[command(subcommand)]
    Corpus(CorpusCommand),
    Fsck {
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long)]
        full: bool,
        #[arg(long = "as-of")]
        as_of: Option<String>,
    },
    Explain {
        logical_key: String,
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long)]
        decision: String,
        #[arg(long = "as-of")]
        as_of: Option<String>,
        #[arg(long)]
        authority_cursor: Option<u64>,
    },
    Project {
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long)]
        task: String,
        #[arg(long)]
        decision: String,
        #[arg(long = "working-set", value_delimiter = ',')]
        working_set: Vec<String>,
        #[arg(long = "as-of")]
        as_of: Option<String>,
    },
    #[command(subcommand)]
    Session(SessionCommand),
    #[command(subcommand)]
    Proposals(ProposalCommand),
    #[command(subcommand)]
    Questions(QuestionCommand),
    #[command(subcommand)]
    Hooks(HookCommand),
    #[command(subcommand)]
    Experiment(ExperimentCommand),
}

#[derive(Debug, Subcommand)]
pub enum CompanyCommand {
    Init {
        #[arg(long)]
        config: PathBuf,
    },
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum RepoCommand {
    Issue {
        #[arg(long)]
        repo: PathBuf,
        #[arg(long)]
        company: String,
    },
    Init {
        #[arg(long)]
        repo: PathBuf,
        #[arg(long)]
        certificate: PathBuf,
    },
    PublishManifest {
        #[arg(long)]
        repo: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum CorpusCommand {
    Rebuild {
        #[arg(long, value_enum)]
        store: Store,
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long = "as-of")]
        as_of: Option<String>,
        #[arg(long)]
        reducer_version: Option<u64>,
    },
}

#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    Start {
        #[arg(long, value_enum)]
        host: Host,
        #[arg(long)]
        repo: Option<PathBuf>,
    },
    Observe {
        session: String,
        #[arg(long)]
        event: PathBuf,
    },
    Checkpoint {
        session: String,
    },
    End {
        session: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ProposalCommand {
    List {
        #[arg(long)]
        session: String,
    },
    Show {
        #[arg(long)]
        session: Option<String>,
        candidate: String,
        #[arg(long)]
        destination: String,
    },
    Decide {
        #[arg(long)]
        session: Option<String>,
        candidate: String,
        #[arg(long)]
        destination: String,
        #[arg(long)]
        approve_digest: Option<String>,
        #[arg(long)]
        reject: bool,
        #[arg(long)]
        defer: bool,
        #[arg(long)]
        escalate: bool,
    },
    Reissue {
        #[arg(long)]
        session: Option<String>,
        candidate: String,
    },
    Reset {
        #[arg(long)]
        session: Option<String>,
        #[arg(long = "after-primary-event")]
        after_primary_event: String,
        #[arg(long = "reason-code", value_enum)]
        reason_code: ResetReason,
    },
}

#[derive(Debug, Subcommand)]
pub enum QuestionCommand {
    List {
        #[arg(long)]
        owner: Option<String>,
    },
    Ask {
        question_id: String,
    },
    Answer {
        question_id: String,
        #[arg(long = "answer-file")]
        answer_file: PathBuf,
        #[arg(long = "key-file")]
        key_file: PathBuf,
    },
    Status {
        question_id: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum HookCommand {
    Plan { host: Host },
    Install { host: Host },
    Dispatch { host: Host, event: String },
}

#[derive(Debug, Subcommand)]
pub enum ExperimentCommand {
    Census {
        manifest: PathBuf,
    },
    Pilot {
        manifest: PathBuf,
    },
    Calibrate {
        manifest: PathBuf,
    },
    Freeze {
        manifest: PathBuf,
        #[arg(long)]
        budget: PathBuf,
    },
    Run {
        frozen_manifest: PathBuf,
        #[arg(long, help = "Validate admission and append the run census without launching candidates")]
        smoke: bool,
    },
    Score {
        run: PathBuf,
    },
    Verdict {
        run: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Host {
    Codex,
    Claude,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Store {
    Personal,
    Company,
    Codebase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ResetReason {
    NewPrimaryTask,
    OperatorRecovery,
    HostRestart,
}
