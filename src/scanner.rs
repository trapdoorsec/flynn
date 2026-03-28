use crate::arguments::{OutputFormat, Severity};
use crate::checks::{
    config::{check_fsmonitor, check_ssh_command},
    hooks::check_executable_hooks,
    structure::check_buried_bare_repo,
};
use crate::finding::Finding;
use crate::output;
use crate::safeprint;
use gix::date;
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
    output_path: &PathBuf,
    min_sev: Severity,
    fail_on: Option<Severity>,
    format: OutputFormat,
    quiet: bool,
) -> anyhow::Result<()> {
    let mut findings = Vec::new();

    safeprint(
        quiet,
        &format!(
            "\n{}\t:\t{}",
            "scan started".cyan(),
            date::Time::now_local_or_utc()
        ),
    );

    for check in CHECKS {
        match check(path) {
            Ok(mut results) => findings.append(&mut results),
            Err(e) => {
                eprintln!("{}: check failed: {}", "warning".yellow(), e);
            }
        }
    }

    findings.retain(|f| f.severity >= min_sev);
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    if !quiet {
        let console = output::text::print_text(&findings);
        println!("\n{}\n", console);
    }

    output::write_report(&findings, output_path, &format)?;
    safeprint(
        quiet,
        &format!(
            "{} written to {}\n{}\t:\t{}",
            "report".cyan(),
            output_path.display(),
            "scan completed".cyan(),
            date::Time::now_local_or_utc()
        ),
    );

    if let Some(threshold) = fail_on {
        if findings.iter().any(|f| f.severity >= threshold) {
            std::process::exit(2);
        }
    }

    Ok(())
}
