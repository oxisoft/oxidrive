//! Databases for tests and query checks (server crate G2, G3).
//!
//! - PostgreSQL: CI provides a service container and sets `OXIDRIVE_TEST_POSTGRES_URL`;
//!   locally a throwaway server is started with podman and removed afterwards.
//! - The compile-time query data in each store crate's `.sqlx/` is checked against freshly
//!   migrated databases with `sqlx-cli` (`cargo sqlx prepare --check`), or regenerated.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use crate::{Error, find_tool, run, say};

/// The environment variable tests read the PostgreSQL server URL from.
pub(crate) const POSTGRES_URL_VAR: &str = "OXIDRIVE_TEST_POSTGRES_URL";
/// The environment variable tests read the command prefix that runs `pg_dump` and
/// `pg_restore` from (server binary J2): the tool's name is appended to it.
pub(crate) const PG_TOOLS_VAR: &str = "OXIDRIVE_TEST_PG_TOOLS";
/// The PostgreSQL image for local runs: the version CI uses.
const POSTGRES_IMAGE: &str = "docker.io/library/postgres:18.6-alpine";
/// Only for the throwaway local server, bound to 127.0.0.1.
const LOCAL_PASSWORD: &str = "oxidrive-local";

/// A PostgreSQL server for this run: CI's, or a throwaway podman container removed on drop.
pub(crate) struct Postgres {
    /// Server URL ending in `/postgres`, for a user who may create databases.
    pub(crate) url: String,
    /// The command prefix running PostgreSQL's client tools of the server's version: CI's,
    /// or the same image run with podman.
    pub(crate) tools: String,
    container: Option<String>,
}

/// The client tools from the server's image, run with podman on the host network.
fn podman_tools(podman: &Path) -> String {
    format!(
        "{} run --rm -i --network host --env PGPASSWORD {POSTGRES_IMAGE}",
        podman.display()
    )
}

impl Postgres {
    /// CI's server if `OXIDRIVE_TEST_POSTGRES_URL` is set, otherwise a new local one.
    pub(crate) fn start() -> Result<Self, Error> {
        if let Ok(url) = env::var(POSTGRES_URL_VAR) {
            say(&format!("==> postgres: using {POSTGRES_URL_VAR}"));
            let tools = match env::var(PG_TOOLS_VAR) {
                Ok(tools) => tools,
                Err(_) => podman_tools(&find_tool("podman").ok_or(Error::ToolMissing("podman"))?),
            };
            return Ok(Self {
                url,
                tools,
                container: None,
            });
        }
        let podman = find_tool("podman").ok_or(Error::ToolMissing("podman"))?;
        let name = format!("oxidrive-xtask-{}", std::process::id());
        say(&format!(
            "==> postgres: starting {POSTGRES_IMAGE} as {name}"
        ));
        let started = Command::new(&podman)
            .args(["run", "--detach", "--rm", "--name", &name])
            .args(["--env", &format!("POSTGRES_PASSWORD={LOCAL_PASSWORD}")])
            .args(["--publish", "127.0.0.1::5432", POSTGRES_IMAGE])
            .output()
            .map_err(|source| Error::Io {
                what: "starting podman".to_owned(),
                source,
            })?;
        if !started.status.success() {
            return Err(Error::StepFailed(format!(
                "postgres container: {}",
                String::from_utf8_lossy(&started.stderr).trim()
            )));
        }
        // From here on, dropping removes the container.
        let mut server = Self {
            url: String::new(),
            tools: podman_tools(&podman),
            container: Some(name.clone()),
        };
        let mut ready = false;
        for _ in 0..120 {
            let probe = Command::new(&podman)
                .args([
                    "exec",
                    &name,
                    "pg_isready",
                    "--quiet",
                    "--username",
                    "postgres",
                ])
                .status();
            if probe.is_ok_and(|status| status.success()) {
                ready = true;
                break;
            }
            thread::sleep(Duration::from_millis(500));
        }
        if !ready {
            return Err(Error::StepFailed(
                "postgres container never became ready".into(),
            ));
        }
        let port = Command::new(&podman)
            .args(["port", &name, "5432"])
            .output()
            .map_err(|source| Error::Io {
                what: "reading the container port".to_owned(),
                source,
            })?;
        let address = String::from_utf8_lossy(&port.stdout).trim().to_owned();
        let port = address
            .rsplit(':')
            .next()
            .filter(|port| !port.is_empty())
            .ok_or_else(|| Error::StepFailed(format!("no port for the container: {address}")))?;
        server.url = format!("postgres://postgres:{LOCAL_PASSWORD}@127.0.0.1:{port}/postgres");
        Ok(server)
    }

    /// The URL of another database on the same server.
    pub(crate) fn database(&self, name: &str) -> String {
        let prefix = self
            .url
            .rsplit_once('/')
            .map_or(self.url.as_str(), |(prefix, _)| prefix);
        format!("{prefix}/{name}")
    }
}

impl Drop for Postgres {
    fn drop(&mut self) {
        if let (Some(name), Some(podman)) = (&self.container, find_tool("podman")) {
            let _ = Command::new(podman).args(["rm", "--force", name]).output();
        }
    }
}

/// What to do with a store crate's query data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Prepare {
    /// Fail if `.sqlx/` doesn't match the queries and schema.
    Check,
    /// Rewrite `.sqlx/`.
    Write,
}

/// Checks or rewrites the query data of both store crates against freshly migrated
/// databases.
pub(crate) fn sqlx_prepare(root: &Path, postgres: &Postgres, mode: Prepare) -> Result<(), Error> {
    let scratch = root.join("target").join("xtask-sqlx");
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).map_err(|source| Error::Io {
        what: format!("creating {}", scratch.display()),
        source,
    })?;
    let sqlite_url = format!("sqlite://{}", absolute(&scratch.join("check.db")).display());
    let postgres_url = postgres.database(&format!("sqlx_check_{}", std::process::id()));
    for (krate, var, url) in [
        ("server-sqlite", "SQLITE_DATABASE_URL", sqlite_url.as_str()),
        (
            "server-postgres",
            "POSTGRES_DATABASE_URL",
            postgres_url.as_str(),
        ),
    ] {
        let dir = root.join("crates").join(krate);
        let envs = [(var, url), ("SQLX_OFFLINE", "false")];
        run(
            &dir,
            &format!("{krate}: migrate"),
            sqlx_tool()?,
            &["database", "setup"],
            &envs,
        )?;
        let mut args = vec!["sqlx", "prepare"];
        if mode == Prepare::Check {
            args.push("--check");
        }
        let program = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        run(
            &dir,
            &format!("{krate}: sqlx prepare"),
            program,
            &args,
            &envs,
        )?;
    }
    Ok(())
}

fn sqlx_tool() -> Result<PathBuf, Error> {
    find_tool("sqlx").ok_or(Error::ToolMissing("sqlx (cargo install sqlx-cli)"))
}

fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}
