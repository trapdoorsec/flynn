use std::path::PathBuf;

use crate::arguments::{OutputFormat, Severity};

pub fn scan(
    path: &PathBuf,
    output: &PathBuf,
    min_sev: Severity,
    fail_on: Option<Severity>,
    format: OutputFormat,
    quiet: bool,
) -> anyhow::Result<()> {
    Ok(())
}
