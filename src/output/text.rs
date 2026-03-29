use crate::arguments::Severity;
use crate::finding::Finding;
use comfy_table::{presets::UTF8_FULL, Cell, Color, ContentArrangement, Table};
use std::fs;
use std::path::Path;

fn severity_color(sev: &Severity) -> Color {
    match sev {
        Severity::Info => Color::Cyan,
        Severity::Medium => Color::Yellow,
        Severity::High => Color::Red,
        Severity::Critical => Color::Magenta,
    }
}

fn severity_label(sev: &Severity) -> &'static str {
    match sev {
        Severity::Info => "INFO",
        Severity::Medium => "MEDIUM",
        Severity::High => "HIGH",
        Severity::Critical => "CRITICAL",
    }
}

pub fn write_text(findings: &[Finding], output: &Path) -> anyhow::Result<()> {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_width(120)
        .set_header(vec![
            Cell::new("Severity"),
            Cell::new("Check"),
            Cell::new("Finding"),
            Cell::new("Reference"),
        ]);

    for finding in findings {
        let color = severity_color(&finding.severity);
        table.add_row(vec![
            Cell::new(severity_label(&finding.severity)).fg(color),
            Cell::new(&finding.name).fg(color),
            Cell::new(&finding.reason),
            Cell::new(&finding.reference),
        ]);
    }

    let rendered = table.to_string();
    fs::write(output, &rendered)?;
    Ok(())
}

pub fn print_text(findings: &[Finding]) -> String {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Severity"),
            Cell::new("Check"),
            Cell::new("Finding"),
            Cell::new("Reference"),
        ]);

    for finding in findings {
        let color = severity_color(&finding.severity);
        table.add_row(vec![
            Cell::new(severity_label(&finding.severity)).fg(color),
            Cell::new(&finding.name).fg(color),
            Cell::new(&finding.reason),
            Cell::new(&finding.reference),
        ]);
    }

    table.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arguments::Severity;
    use crate::finding::Finding;
    use tempfile::NamedTempFile;

    fn make_finding(severity: Severity, name: &str, reason: &str) -> Finding {
        Finding {
            severity,
            name: name.to_string(),
            reason: reason.to_string(),
            reference: String::new(),
        }
    }

    #[test]
    fn empty_findings_renders_header_only() {
        let output = print_text(&[]);
        assert!(output.contains("Severity"));
        assert!(output.contains("Check"));
        assert!(output.contains("Finding"));
        let line_count = output.lines().count();
        assert!(line_count <= 5, "header-only table should be at most 5 lines, got {line_count}");
    }

    #[test]
    fn long_reason_does_not_panic() {
        let long_reason = "a]".repeat(5000);
        let findings = vec![make_finding(Severity::High, "test-check", &long_reason)];
        let output = print_text(&findings);
        assert!(output.contains("HIGH"));
        assert!(output.contains("test-check"));
    }

    #[test]
    fn long_check_name_does_not_panic() {
        let long_name = format!("check-{}", "x".repeat(5000));
        let findings = vec![make_finding(Severity::Info, &long_name, "something bad")];
        let output = print_text(&findings);
        assert!(output.contains("INFO"));
        assert!(output.contains("something bad"));
    }

    #[test]
    fn all_columns_long_does_not_panic() {
        let findings = vec![make_finding(
            Severity::Critical,
            &format!("check-{}", "z".repeat(3000)),
            &"reason ".repeat(1000),
        )];
        let output = print_text(&findings);
        assert!(output.contains("CRITICAL"));
    }

    #[test]
    fn multiline_reason_preserved() {
        let reason = "line one\nline two\nline three";
        let findings = vec![make_finding(Severity::Medium, "multiline-check", reason)];
        let output = print_text(&findings);
        assert!(output.contains("line one"));
        assert!(output.contains("line two"));
        assert!(output.contains("line three"));
    }

    #[test]
    fn special_characters_in_fields() {
        let findings = vec![make_finding(
            Severity::High,
            "unicode-check-\u{200b}\u{feff}",
            "path: ../../etc/passwd | $HOME | `rm -rf /`",
        )];
        let output = print_text(&findings);
        assert!(output.contains("HIGH"));
        assert!(output.contains("../../etc/passwd"));
    }

    #[test]
    fn many_rows_does_not_panic() {
        let findings: Vec<Finding> = (0..500)
            .map(|i| make_finding(Severity::Info, &format!("check-{i}"), &format!("reason {i}")))
            .collect();
        let output = print_text(&findings);
        assert!(output.contains("check-0"));
        assert!(output.contains("check-499"));
    }

    #[test]
    fn write_text_creates_file() {
        let findings = vec![
            make_finding(Severity::Critical, "file-check", "written to disk"),
        ];
        let tmp = NamedTempFile::new().unwrap();
        write_text(&findings, tmp.path()).unwrap();
        let contents = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(contents.contains("CRITICAL"));
        assert!(contents.contains("file-check"));
        assert!(contents.contains("written to disk"));
    }

    #[test]
    fn write_text_long_reason_wraps_cleanly() {
        let long_reason = "word ".repeat(2000);
        let findings = vec![make_finding(Severity::High, "wrap-check", &long_reason)];
        let tmp = NamedTempFile::new().unwrap();
        write_text(&findings, tmp.path()).unwrap();
        let contents = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(contents.contains("HIGH"));
        assert!(contents.contains("word"));
        for line in contents.lines() {
            let display_width: usize = line.chars().count();
            assert!(
                display_width <= 200,
                "line exceeded 200 display chars (width={display_width})"
            );
        }
    }
}
