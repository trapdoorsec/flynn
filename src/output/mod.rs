pub mod json;
pub mod sarif;
pub mod text;

use crate::arguments::OutputFormat;
use crate::finding::Finding;
use std::path::Path;

pub fn write_report(
    findings: &[Finding],
    output: &Path,
    format: &OutputFormat,
) -> anyhow::Result<()> {
    match format {
        OutputFormat::Text => text::write_text(findings, output),
        OutputFormat::Json => json::write_json(findings, output),
        OutputFormat::Sarif => sarif::write_sarif(findings, output),
    }
}
