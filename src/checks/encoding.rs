use std::fs;
use std::path::Path;

use crate::arguments::Severity;
use crate::finding::Finding;

pub fn check_encoding_evasion(git_dir: &Path) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let config_path = git_dir.join("config");

    let bytes = match fs::read(&config_path) {
        Ok(b) => b,
        Err(_) => return Ok(vec![]),
    };

    // Null bytes
    if bytes.contains(&0) {
        findings.push(Finding {
            severity: Severity::High,
            name: "null bytes in config".to_string(),
            reason: "config file contains null (\\x00) bytes".to_string(),
        });
    }

    // Binary content (control chars that shouldn't appear in text config)
    let has_binary = bytes.iter().any(|&b| b < 0x09 || (b > 0x0d && b < 0x20 && b != 0x1b));
    if has_binary {
        findings.push(Finding {
            severity: Severity::High,
            name: "binary content in config".to_string(),
            reason: "config file contains binary/non-text content".to_string(),
        });
    }

    let content = String::from_utf8_lossy(&bytes);

    for line in content.lines() {
        let trimmed = line.trim();

        // Homoglyphs in section headers
        if trimmed.starts_with('[') {
            if let Some(end) = trimmed.rfind(']') {
                let header = &trimmed[1..end];
                let section_name = header.split('"').next().unwrap_or("").trim();
                if section_name.chars().any(|c| !c.is_ascii()) {
                    findings.push(Finding {
                        severity: Severity::Critical,
                        name: "homoglyph in config section".to_string(),
                        reason: format!(
                            "config section [{}] contains non-ASCII/unicode characters (possible cyrillic homoglyph attack)",
                            section_name
                        ),
                    });
                }
            }
            continue;
        }

        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }

        // Tab indentation tricks (mixed tabs/spaces or multiple tabs before key)
        if trimmed.contains('=') {
            let leading = &line[..line.len() - line.trim_start().len()];
            let tab_count = leading.chars().filter(|c| *c == '\t').count();
            let space_count = leading.chars().filter(|c| *c == ' ').count();
            if leading.len() > 1 && (tab_count > 1 || (tab_count > 0 && space_count > 0)) {
                findings.push(Finding {
                    severity: Severity::High,
                    name: "tab indentation trick".to_string(),
                    reason: format!("config key with unusual whitespace indentation: {}", trimmed),
                });
            }
        }

        // Long values and shell metacharacters
        if let Some(eq_pos) = trimmed.find('=') {
            let value = &trimmed[eq_pos + 1..];

            if value.len() > 10_000 {
                findings.push(Finding {
                    severity: Severity::Medium,
                    name: "oversized config value".to_string(),
                    reason: format!(
                        "config value is {} chars long (possible buffer overflow attempt)",
                        value.len()
                    ),
                });
            }

            let value_trimmed = value.trim();
            if value_trimmed.contains("$(") || value_trimmed.contains('`') {
                findings.push(Finding {
                    severity: Severity::High,
                    name: "shell metacharacters in config".to_string(),
                    reason: format!(
                        "config value contains shell metacharacters: {}",
                        &value_trimmed[..value_trimmed.len().min(100)]
                    ),
                });
            }
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arguments::Severity;
    use crate::checks::test_fixture::fixture_git_dir;

    fn has_finding(findings: &[Finding], needle: &str) -> bool {
        findings.iter().any(|f| f.name.contains(needle) || f.reason.contains(needle))
    }

    // ── tab indentation tricks ──────────────────────────────────────────

    #[test]
    fn detects_tab_indented_config_key() {
        let findings = check_encoding_evasion(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "tab") || has_finding(&findings, "whitespace") || has_finding(&findings, "indentation"),
            "should detect config keys with unusual tab indentation"
        );
    }

    // ── unicode homoglyphs ──────────────────────────────────────────────

    #[test]
    fn detects_homoglyph_config_key() {
        let findings = check_encoding_evasion(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "homoglyph") || has_finding(&findings, "unicode") || has_finding(&findings, "cyrillic"),
            "should detect Cyrillic homoglyph in config key name (cоre vs core)"
        );
    }

    #[test]
    fn homoglyph_severity_is_critical() {
        let findings = check_encoding_evasion(&fixture_git_dir()).unwrap();
        let f = findings.iter().find(|f|
            f.name.contains("homoglyph") || f.name.contains("unicode") || f.name.contains("cyrillic")
        );
        assert!(f.is_some(), "homoglyph finding missing");
        assert_eq!(f.unwrap().severity, Severity::Critical);
    }

    // ── null bytes in config ────────────────────────────────────────────

    #[test]
    fn detects_null_bytes_in_config() {
        let findings = check_encoding_evasion(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "null") || has_finding(&findings, "\\x00") || has_finding(&findings, "NUL"),
            "should detect null bytes in config values"
        );
    }

    // ── extremely long config values ────────────────────────────────────

    #[test]
    fn detects_long_config_value() {
        let findings = check_encoding_evasion(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "long") || has_finding(&findings, "length") || has_finding(&findings, "oversized"),
            "should detect extremely long config values (100k chars)"
        );
    }

    // ── shell metacharacters in non-exec fields ─────────────────────────

    #[test]
    fn detects_shell_metacharacters() {
        let findings = check_encoding_evasion(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "shell") || has_finding(&findings, "metachar") || has_finding(&findings, "$(" ),
            "should detect shell metacharacters in non-exec config fields"
        );
    }

    // ── binary content in config ────────────────────────────────────────

    #[test]
    fn detects_binary_content_in_config() {
        let findings = check_encoding_evasion(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "binary"),
            "should detect binary content in .git/config"
        );
    }

    #[test]
    fn binary_config_severity_at_least_high() {
        let findings = check_encoding_evasion(&fixture_git_dir()).unwrap();
        let f = findings.iter().find(|f| f.name.contains("binary"));
        assert!(f.is_some(), "binary config finding missing");
        assert!(f.unwrap().severity >= Severity::High);
    }
}
