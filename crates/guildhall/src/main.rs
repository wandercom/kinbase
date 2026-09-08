//! Interim entry point. The rewritten foundation (see `lib.rs`) is not yet
//! wired to the cli.md command surface; every command therefore emits the
//! typed internal failure (exit 70, "no product pass") instead of a stale
//! or partial answer. `__probe` is the sandbox denial-probe child body.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("__probe") {
        let target = std::path::PathBuf::from(args.get(2).cloned().unwrap_or_default());
        std::process::exit(guildhall::sandbox::probe_main(&target));
    }
    let error = guildhall::error::ContractError::internal(
        "the command surface is not yet wired to the rewritten foundation (dispatch 009 handed over mid-rewrite); no product result is available",
    );
    let json = args.iter().any(|arg| arg == "--json");
    if json {
        println!("{}", guildhall::output::single_line(&guildhall::output::error_document(&error)));
    } else {
        println!("{}: {}", error.code, error.message);
        println!("remediation: {}", error.remediation);
        println!("retryable: {}", error.retryable);
        println!("evidence_id: {}", error.evidence_id);
    }
    std::process::exit(error.exit());
}
