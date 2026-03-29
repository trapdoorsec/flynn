use crate::arguments::{OutputFormat, Severity};
use crate::checks::{
    attributes::check_attributes,
    config::{check_fsmonitor, check_ssh_command},
    encoding::check_encoding_evasion,
    hooks::check_executable_hooks,
    metadata::check_metadata,
    objects::check_objects,
    refs::check_refs,
    structure::check_buried_bare_repo,
    submodules::check_submodules,
    worktrees::check_worktrees,
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
    check_objects,
    check_refs,
    check_attributes,
    check_worktrees,
    check_submodules,
    check_metadata,
    check_encoding_evasion,
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
    let abs_output = std::fs::canonicalize(output_path).unwrap_or_else(|_| output_path.clone());
    let format_label = match format {
        OutputFormat::Text => "text",
        OutputFormat::Json => "json",
        OutputFormat::Sarif => "sarif",
    };
    safeprint(
        quiet,
        &format!(
            "{} ({}) written to {}\n{}\t:\t{}",
            "report".cyan(),
            format_label,
            abs_output.display(),
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
