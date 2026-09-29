//! `oxidrive-sim`: replays one simulation seed or searches many (docs `simulator.md`).
//!
//! ```text
//! oxidrive-sim --seed N [--epochs E] [--ticks T]          replay one run
//! oxidrive-sim --runs K [--from S] [--epochs E] [--ticks T]  search K seeds from S
//! ```
//!
//! Without `--from`, a search starts at a seed taken from the current time, printed first.
//! `--server sqlite` or `--server postgres` runs on the real server's rules and stores
//! (PostgreSQL at `OXIDRIVE_TEST_POSTGRES_URL`) instead of the in-memory server.

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use oxisoft_drive_sim::{Backend, Config, run_on};

const USAGE: &str = "usage: oxidrive-sim [--seed N | --runs K [--from S]] [--epochs E] \
                     [--ticks T] [--server memory|sqlite|postgres]";

/// Which server to run on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Server {
    Memory,
    Sqlite,
    Postgres,
}

#[derive(Debug, PartialEq, Eq)]
struct Args {
    seed: Option<u64>,
    runs: u64,
    from: Option<u64>,
    config: Config,
    server: Server,
}

fn parse(mut args: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut parsed = Args {
        seed: None,
        runs: 1,
        from: None,
        config: Config::default(),
        server: Server::Memory,
    };
    while let Some(flag) = args.next() {
        let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        if flag == "--server" {
            parsed.server = match value.as_str() {
                "memory" => Server::Memory,
                "sqlite" => Server::Sqlite,
                "postgres" => Server::Postgres,
                other => return Err(format!("--server: unknown server {other}")),
            };
            continue;
        }
        let number: u64 = value
            .parse()
            .map_err(|_| format!("{flag}: not a number: {value}"))?;
        let size = || usize::try_from(number).map_err(|error| format!("{flag}: {error}"));
        match flag.as_str() {
            "--seed" => parsed.seed = Some(number),
            "--runs" => parsed.runs = number,
            "--from" => parsed.from = Some(number),
            "--epochs" => parsed.config.epochs = size()?,
            "--ticks" => parsed.config.ticks = size()?,
            _ => return Err(format!("unknown option {flag}")),
        }
    }
    Ok(parsed)
}

fn time_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            elapsed.as_secs().wrapping_mul(1_000_003) ^ u64::from(elapsed.subsec_nanos())
        })
}

fn main() -> ExitCode {
    let args = match parse(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(error) => {
            complain(&format!("{error}\n{USAGE}"));
            return ExitCode::FAILURE;
        }
    };
    let (first, runs) = match args.seed {
        Some(seed) => (seed, 1),
        None => (args.from.unwrap_or_else(time_seed), args.runs),
    };
    say(&format!(
        "{runs} run(s) from seed {first}, {} epochs of {} ticks",
        args.config.epochs, args.config.ticks
    ));
    let url = std::env::var("OXIDRIVE_TEST_POSTGRES_URL").unwrap_or_default();
    let backend = match args.server {
        Server::Memory => Backend::Memory,
        Server::Sqlite => Backend::Sqlite,
        Server::Postgres => Backend::Postgres(&url),
    };
    for seed in first..first.saturating_add(runs) {
        match run_on(seed, args.config, backend) {
            Ok(summary) if runs == 1 => say(&format!("seed {seed}: {summary}")),
            Ok(_) => {}
            Err(failure) => {
                complain(&failure.to_string());
                return ExitCode::FAILURE;
            }
        }
    }
    say("all runs passed");
    ExitCode::SUCCESS
}

#[expect(
    clippy::print_stdout,
    reason = "the simulator reports progress on the terminal"
)]
fn say(message: &str) {
    println!("{message}");
}

#[expect(
    clippy::print_stderr,
    reason = "the simulator reports failures on the terminal"
)]
fn complain(message: &str) {
    eprintln!("{message}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_all(args: &[&str]) -> Result<Args, String> {
        parse(args.iter().map(|arg| (*arg).to_owned()))
    }

    #[test]
    fn parses_options() {
        let args = parse_all(&["--seed", "7", "--epochs", "2", "--ticks", "9"]).unwrap();
        assert_eq!(args.seed, Some(7));
        assert_eq!(
            args.config,
            Config {
                epochs: 2,
                ticks: 9
            }
        );
        let search = parse_all(&["--runs", "100", "--from", "40", "--server", "sqlite"]).unwrap();
        assert_eq!((search.runs, search.from), (100, Some(40)));
        assert_eq!(search.server, Server::Sqlite);
        assert_eq!(
            parse_all(&["--server", "postgres"]).unwrap().server,
            Server::Postgres
        );
        assert_eq!(
            parse_all(&["--server", "memory"]).unwrap().server,
            Server::Memory
        );
        assert_eq!(parse_all(&[]).unwrap().config, Config::default());
    }

    #[test]
    fn rejects_bad_options() {
        assert_eq!(parse_all(&["--seed"]).unwrap_err(), "--seed needs a value");
        assert_eq!(
            parse_all(&["--seed", "x"]).unwrap_err(),
            "--seed: not a number: x"
        );
        assert_eq!(
            parse_all(&["--fast", "1"]).unwrap_err(),
            "unknown option --fast"
        );
        assert_eq!(
            parse_all(&["--server", "oracle"]).unwrap_err(),
            "--server: unknown server oracle"
        );
    }

    #[test]
    fn time_seeds_vary() {
        assert_ne!(time_seed(), 0);
    }
}
