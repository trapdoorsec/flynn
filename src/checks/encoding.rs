use std::path::Path;

use crate::finding::Finding;

pub fn check_encoding_evasion(git_dir: &Path) -> anyhow::Result<Vec<Finding>> {
    Ok(vec![])
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
