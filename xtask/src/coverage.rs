//! Per-crate line-coverage gate (engineering standards §2, Q-E1).
//!
//! Minimums only ever go up. Crates that exist only to support tests are measured but not
//! gated.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Component, Path};

/// Minimum line coverage in percent, by directory under `crates/`. `None` means not gated.
fn minimum(crate_dir: &str) -> Option<u64> {
    match crate_dir {
        "crypto" | "chunking" | "proto" | "core" => Some(90),
        "testkit" | "sim" | "it" => None,
        _ => Some(80),
    }
}

/// Covered and total lines of one crate.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CrateCoverage {
    pub(crate) crate_dir: String,
    pub(crate) covered: u64,
    pub(crate) count: u64,
}

/// Sums the per-file line counts of a `cargo llvm-cov --json --summary-only` report by crate.
/// Files outside `crates_dir` (such as xtask itself) are ignored.
pub(crate) fn per_crate(report: &serde_json::Value, crates_dir: &Path) -> Vec<CrateCoverage> {
    let mut sums: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let files = report
        .pointer("/data/0/files")
        .and_then(serde_json::Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    for file in files {
        let Some(name) = file.get("filename").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Ok(relative) = Path::new(name).strip_prefix(crates_dir) else {
            continue;
        };
        let Some(Component::Normal(dir)) = relative.components().next() else {
            continue;
        };
        let lines = |key: &str| {
            file.pointer(&format!("/summary/lines/{key}"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
        };
        let entry = sums.entry(dir.to_string_lossy().into_owned()).or_default();
        entry.0 += lines("covered");
        entry.1 += lines("count");
    }
    sums.into_iter()
        .map(|(crate_dir, (covered, count))| CrateCoverage {
            crate_dir,
            covered,
            count,
        })
        .collect()
}

/// One message per crate below its minimum. A crate without code yet passes.
pub(crate) fn failures(results: &[CrateCoverage]) -> Vec<String> {
    results
        .iter()
        .filter_map(|result| {
            let minimum = minimum(&result.crate_dir)?;
            (result.count > 0 && result.covered * 100 < minimum * result.count).then(|| {
                format!(
                    "{} has {}/{} lines covered, needs {minimum} %",
                    result.crate_dir, result.covered, result.count
                )
            })
        })
        .collect()
}

/// A human-readable summary table.
pub(crate) fn table(results: &[CrateCoverage]) -> String {
    let mut out = String::from("crate        lines covered  minimum\n");
    for result in results {
        let minimum =
            minimum(&result.crate_dir).map_or_else(|| "-".to_owned(), |m| format!("{m} %"));
        let covered = if result.count == 0 {
            "no code yet".to_owned()
        } else {
            format!("{}/{}", result.covered, result.count)
        };
        let _ = writeln!(out, "{:<12} {covered:<14} {minimum}", result.crate_dir);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn file(name: &str, covered: u64, count: u64) -> serde_json::Value {
        json!({ "filename": name, "summary": { "lines": { "covered": covered, "count": count } } })
    }

    fn report(files: &[serde_json::Value]) -> serde_json::Value {
        json!({ "data": [ { "files": files } ] })
    }

    fn cov(crate_dir: &str, covered: u64, count: u64) -> CrateCoverage {
        CrateCoverage {
            crate_dir: crate_dir.to_owned(),
            covered,
            count,
        }
    }

    #[test]
    fn sums_files_per_crate_and_ignores_files_outside_crates() {
        let report = report(&[
            file("/w/crates/core/src/lib.rs", 8, 10),
            file("/w/crates/core/src/sync.rs", 2, 10),
            file("/w/crates/server/src/main.rs", 5, 5),
            file("/w/xtask/src/main.rs", 0, 100),
        ]);
        let results = per_crate(&report, Path::new("/w/crates"));
        assert_eq!(results, vec![cov("core", 10, 20), cov("server", 5, 5)]);
    }

    #[test]
    fn malformed_report_yields_nothing() {
        assert!(per_crate(&json!({}), Path::new("/w/crates")).is_empty());
        let no_name = report(&[json!({ "summary": {} })]);
        assert!(per_crate(&no_name, Path::new("/w/crates")).is_empty());
    }

    #[test]
    fn core_crates_need_ninety_percent() {
        assert!(failures(&[cov("core", 90, 100)]).is_empty());
        let failed = failures(&[cov("crypto", 89, 100)]);
        assert_eq!(failed, vec!["crypto has 89/100 lines covered, needs 90 %"]);
    }

    #[test]
    fn other_crates_need_eighty_percent() {
        assert!(failures(&[cov("server", 80, 100)]).is_empty());
        assert_eq!(failures(&[cov("client", 79, 100)]).len(), 1);
    }

    #[test]
    fn test_support_crates_and_empty_crates_are_not_gated() {
        assert!(failures(&[cov("sim", 0, 100), cov("testkit", 1, 100)]).is_empty());
        assert!(failures(&[cov("core", 0, 0)]).is_empty());
    }

    #[test]
    fn table_lists_every_crate() {
        let text = table(&[cov("core", 9, 10), cov("sim", 0, 0)]);
        assert!(text.contains("core         9/10           90 %"));
        assert!(text.contains("sim          no code yet    -"));
    }
}
