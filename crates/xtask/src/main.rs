#![forbid(unsafe_code)]

mod coverage;

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if let Err(err) = run(&args) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("coverage") => coverage::run(&args[1..]),
        Some(command) => Err(format!("unknown xtask subcommand `{command}`")),
        None => Err("missing xtask subcommand".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::run;

    #[test]
    fn rejects_missing_subcommand() {
        let err = run(&[]).expect_err("missing command should fail");
        assert!(err.contains("missing xtask subcommand"));
    }

    #[test]
    fn rejects_unknown_subcommand() {
        let err = run(&["unknown".to_string()]).expect_err("unknown command should fail");
        assert!(err.contains("unknown xtask subcommand"));
    }
}
