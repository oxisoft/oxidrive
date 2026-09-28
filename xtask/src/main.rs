//! Development tasks for the oxidrive workspace.
//!
//! `cargo xtask ci` runs exactly what CI runs, so a green local run means a green pipeline.
//!
//! | command | runs |
//! |---|---|
//! | `ci`   | every check, including the coverage gate (Linux CI job) |
//! | `test` | lints and tests only (macOS and Windows CI jobs) |
//! | `deny` | the dependency advisory, licence and source check (daily CI job) |

mod coverage;

use std::env;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const USAGE: &str = "usage: cargo xtask <ci | test | deny>";
const COVERAGE_JSON: &str = "target/llvm-cov/summary.json";

fn main() -> ExitCode {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let task = env::args().nth(1);
    let result = match task.as_deref() {
        Some("ci") => ci(&root),
        Some("test") => test(&root),
        Some("deny") => deny(&root),
        _ => Err(Error::Usage),
    };
    match result {
        Ok(()) => {
            say("xtask: all checks passed");
            ExitCode::SUCCESS
        }
        Err(error) => {
            complain(&format!("xtask: {error}"));
            ExitCode::FAILURE
        }
    }
}

/// Everything CI checks on Linux.
fn ci(root: &Path) -> Result<(), Error> {
    cargo(root, "fmt", &["fmt", "--all", "--check"], &[])?;
    run(
        root,
        "taplo",
        "taplo",
        &["fmt", "--check"],
        &[("RUST_LOG", "warn")],
    )?;
    clippy(root)?;
    cargo(
        root,
        "doc",
        &[
            "doc",
            "--workspace",
            "--no-deps",
            "--all-features",
            "--locked",
        ],
        &[("RUSTDOCFLAGS", "-D warnings")],
    )?;
    coverage(root)?;
    doctests(root)?;
    deny(root)?;
    run(root, "machete", "cargo-machete", &[], &[])?;
    let actionlint = find_tool("actionlint").ok_or(Error::ToolMissing("actionlint"))?;
    run(root, "actionlint", actionlint, &[], &[])?;
    zizmor(root)
}

/// Lints and tests, for the macOS and Windows CI jobs.
fn test(root: &Path) -> Result<(), Error> {
    clippy(root)?;
    cargo(
        root,
        "nextest",
        &[
            "nextest",
            "run",
            "--workspace",
            "--all-features",
            "--locked",
        ],
        &[("NEXTEST_PROFILE", "ci")],
    )?;
    doctests(root)
}

fn deny(root: &Path) -> Result<(), Error> {
    cargo(root, "deny", &["deny", "--all-features", "check"], &[])
}

fn clippy(root: &Path) -> Result<(), Error> {
    cargo(
        root,
        "clippy",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
        &[],
    )
}

fn doctests(root: &Path) -> Result<(), Error> {
    cargo(
        root,
        "doctests",
        &["test", "--doc", "--workspace", "--all-features", "--locked"],
        &[],
    )
}

/// Runs the tests under coverage instrumentation, then applies the per-crate gate.
fn coverage(root: &Path) -> Result<(), Error> {
    let path = root.join(COVERAGE_JSON);
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|source| Error::Io {
            what: format!("creating {}", dir.display()),
            source,
        })?;
    }
    cargo(
        root,
        "tests + coverage",
        &[
            "llvm-cov",
            "nextest",
            "--workspace",
            "--all-features",
            "--locked",
            "--no-cfg-coverage",
            "--json",
            "--summary-only",
            "--output-path",
            COVERAGE_JSON,
        ],
        &[("NEXTEST_PROFILE", "ci")],
    )?;
    let text = fs::read_to_string(&path).map_err(|source| Error::Io {
        what: format!("reading {}", path.display()),
        source,
    })?;
    let report: serde_json::Value =
        serde_json::from_str(&text).map_err(|error| Error::Coverage(error.to_string()))?;
    let crates_dir = fs::canonicalize(root.join("crates")).map_err(|source| Error::Io {
        what: "resolving crates/".to_owned(),
        source,
    })?;
    let results = coverage::per_crate(&report, &crates_dir);
    say(&coverage::table(&results));
    let failures = coverage::failures(&results);
    if failures.is_empty() {
        Ok(())
    } else {
        Err(Error::Coverage(failures.join("; ")))
    }
}

/// zizmor audits the workflows with its strictest persona. With a GitHub token it also checks
/// for actions with known vulnerabilities; without one (local runs) it runs its offline audits
/// only.
fn zizmor(root: &Path) -> Result<(), Error> {
    let mut args = vec!["--quiet", "--persona=pedantic", ".github/workflows"];
    if env::var_os("GH_TOKEN").is_none() && env::var_os("GITHUB_TOKEN").is_none() {
        args.insert(0, "--offline");
    }
    run(root, "zizmor", "zizmor", &args, &[])
}

fn cargo(root: &Path, name: &str, args: &[&str], envs: &[(&str, &str)]) -> Result<(), Error> {
    let program = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    run(root, name, program, args, envs)
}

fn run(
    root: &Path,
    name: &str,
    program: impl Into<OsString>,
    args: &[&str],
    envs: &[(&str, &str)],
) -> Result<(), Error> {
    say(&format!("==> {name}"));
    let program = program.into();
    let status = Command::new(&program)
        .args(args)
        .envs(envs.iter().copied())
        .current_dir(root)
        .status()
        .map_err(|source| Error::Io {
            what: format!("starting {}", program.to_string_lossy()),
            source,
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::StepFailed(name.to_owned()))
    }
}

/// Looks for a tool on `PATH`, then in Go's install directory (`$GOPATH/bin`, default
/// `~/go/bin`), where `go install` puts actionlint.
fn find_tool(name: &str) -> Option<PathBuf> {
    let go_bin = env::var_os("GOPATH")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| Path::new(&home).join("go")))
        .map(|gopath| gopath.join("bin"));
    env::var_os("PATH")
        .iter()
        .flat_map(env::split_paths)
        .chain(go_bin)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

#[expect(
    clippy::print_stdout,
    reason = "xtask reports progress on the terminal"
)]
fn say(message: &str) {
    println!("{message}");
}

#[expect(
    clippy::print_stderr,
    reason = "xtask reports failures on the terminal"
)]
fn complain(message: &str) {
    eprintln!("{message}");
}

#[derive(Debug)]
enum Error {
    Usage,
    StepFailed(String),
    ToolMissing(&'static str),
    Coverage(String),
    Io { what: String, source: io::Error },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => f.write_str(USAGE),
            Self::StepFailed(name) => write!(f, "step `{name}` failed"),
            Self::ToolMissing(name) => write!(f, "`{name}` not found on PATH or in ~/go/bin"),
            Self::Coverage(detail) => write!(f, "coverage gate: {detail}"),
            Self::Io { what, source } => write!(f, "{what}: {source}"),
        }
    }
}
