pub mod classify;
pub mod cli;
pub mod command_types;
pub mod company;
pub mod corpus;
pub mod crypto;
pub mod error;
pub mod experiment;
pub mod hash;
pub mod hooks;
pub mod ingest;
pub mod json;
pub mod model;
pub mod projector;
pub mod proposals;
pub mod questions;
pub mod reducer;
pub mod repository;
pub mod scanner;
pub mod session;
pub mod store;
pub mod time;

pub use crate::command_types::*;
pub use clap::Parser;
#[derive(Parser)]
#[command(name = "guildhall", version = env!("CARGO_PKG_VERSION"), about = "Three-store knowledge system for brownfield coding")]
pub struct Cli {
    #[arg(long, global = true, help = "Emit canonical JSON receipts")]
    pub json: bool,
    #[command(subcommand)]
    pub command: Command,
}
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreKind {
    Personal,
    Company,
    Codebase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKind {
    Codex,
    Claude,
}
