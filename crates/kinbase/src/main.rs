pub use kinbase::Cli;
pub use kinbase::cli::{parse_or_exit, run};

fn main() {
    if std::env::args().nth(1).as_deref() == Some("__probe") {
        let target = std::env::args()
            .nth(2)
            .map(std::path::PathBuf::from)
            .unwrap_or_default();
        std::process::exit(kinbase::sandbox::probe_main(&target));
    }
    let cli = parse_or_exit();
    run(cli.json, cli.command);
}
