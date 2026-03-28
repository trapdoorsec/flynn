use std::path::Path;

use crate::finding::Finding;

pub fn check_metadata(git_dir: &Path) -> anyhow::Result<Vec<Finding>> {
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

    // ── sparse-checkout with unusual patterns ───────────────────────────

    #[test]
    fn detects_suspicious_sparse_checkout() {
        let findings = check_metadata(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "sparse-checkout") || has_finding(&findings, "sparse"),
            "should detect .git/info/sparse-checkout with unusual glob patterns"
        );
    }

    // ── info/exclude ────────────────────────────────────────────────────

    #[test]
    fn detects_info_exclude() {
        let findings = check_metadata(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "exclude"),
            "should detect .git/info/exclude (attacker hiding tracks)"
        );
    }

    // ── tampered description ────────────────────────────────────────────

    #[test]
    fn detects_tampered_description() {
        let findings = check_metadata(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "description"),
            "should detect .git/description modified from default"
        );
    }

    // ── unexpected [user] section ───────────────────────────────────────

    #[test]
    fn detects_user_section() {
        let findings = check_metadata(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "[user]") || has_finding(&findings, "user"),
            "should detect unexpected [user] section in config"
        );
    }

    // ── pushurl differing from url ──────────────────────────────────────

    #[test]
    fn detects_pushurl_mismatch() {
        let findings = check_metadata(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "pushurl"),
            "should detect [remote] pushurl differing from url"
        );
    }

    #[test]
    fn pushurl_mismatch_severity_at_least_high() {
        let findings = check_metadata(&fixture_git_dir()).unwrap();
        let f = findings.iter().find(|f| f.name.contains("pushurl") || f.reason.contains("pushurl"));
        assert!(f.is_some(), "pushurl finding missing");
        assert!(f.unwrap().severity >= Severity::High);
    }

    // ── ext:: remote URL ────────────────────────────────────────────────

    #[test]
    fn detects_ext_protocol_remote() {
        let findings = check_metadata(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "ext::"),
            "should detect remote URL using ext:: protocol"
        );
    }

    #[test]
    fn ext_protocol_severity_is_critical() {
        let findings = check_metadata(&fixture_git_dir()).unwrap();
        let f = findings.iter().find(|f| f.reason.contains("ext::") || f.name.contains("ext::"));
        assert!(f.is_some(), "ext:: finding missing");
        assert_eq!(f.unwrap().severity, Severity::Critical);
    }

    // ── fd:: remote URL ─────────────────────────────────────────────────

    #[test]
    fn detects_fd_protocol_remote() {
        let findings = check_metadata(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "fd::"),
            "should detect remote URL using fd:: protocol"
        );
    }

    // ── file:// remote URL ──────────────────────────────────────────────

    #[test]
    fn detects_file_protocol_remote() {
        let findings = check_metadata(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "file://") || has_finding(&findings, "file_protocol"),
            "should detect remote URL using file:// scheme"
        );
    }
}
