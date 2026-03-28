use crate::arguments::{OutputFormat, Severity};
use crate::checks::{
    config::{check_fsmonitor, check_ssh_command},
    hooks::check_executable_hooks,
    structure::check_buried_bare_repo,
};
use crate::finding::Finding;
use crate::safeprint;
use gix::date;
use gix::traverse::commit::find;
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

    let report_finished = format!(
        "\n{}\t:\t{}\n======================\nFINDINGS\n======================\n",
        "scan started".cyan(),
        date::Time::now_local_or_utc()
    );
    safeprint(quiet, report_finished.as_str());
    for check in CHECKS {
        match check(path) {
            Ok(mut results) => findings.append(&mut results),
            Err(e) => {
                eprintln!("{}: check failed {}", "warning".yellow(), e);
            }
        }
    }
    for finding in findings {
        let sev = match finding.severity {
            Severity::Info => format!("{:?}", finding.severity.blue()),
            Severity::Medium => format!("{:?}", finding.severity.yellow()),
            Severity::High => format!("{:?}", finding.severity.red()),
            Severity::Critical => format!("{:?}", finding.severity.purple()),
        };
        let message = format!("{}: {} - {}", sev, finding.name, finding.reason);
        safeprint(quiet, message.as_str());
    }
    let report_finished = format!(
        "\n======================\n{}\t:\t{}",
        "scan completed".cyan(),
        date::Time::now_local_or_utc()
    );
    safeprint(quiet, report_finished.as_str());
    Ok(())
}
