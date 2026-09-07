use clap::Parser;

pub use guildhall::Cli;
pub use guildhall::cli::run;
pub use guildhall::command_types::*;

fn main() {
    let cli = Cli::parse();
    run(cli.json, cli.command);
}
