use crate::arguments::{OutputFormat, Severity};
use crate::checks::{
    config::{check_fsmonitor, check_ssh_command},
    hooks::check_executable_hooks,
    structure::check_buried_bare_repo,
};
use crate::finding::Finding;
use owo_colors::OwoColorize;
use std::path::Path;
use std::path::PathBuf;

type CheckFn = fn(&Path) -> anyhow::Result<Vec<Finding>>;

const CHECKS: &[CheckFn] = &[
    check_fsmonitor,
    check_ssh_command,
    check_buried_bare_repo,
    check_executable_hooks,
];

pub fn scan(
    path: &PathBuf,
    output: &PathBuf,
    min_sev: Severity,
    fail_on: Option<Severity>,
    format: OutputFormat,
    quiet: bool,
) -> anyhow::Result<()> {
    let mut findings = Vec::new();

    for check in CHECKS {
        match check(path) {
            Ok(mut results) => findings.append(&mut results),
            Err(e) => {
                eprintln!("{}: check failed {}", "warning".yellow(), e);
            }
        }
    }
    Ok(())
}
