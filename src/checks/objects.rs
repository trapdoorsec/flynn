use std::path::Path;

use crate::finding::Finding;

pub fn check_objects(git_dir: &Path) -> anyhow::Result<Vec<Finding>> {
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

    // ── oversized loose objects ─────────────────────────────────────────

    #[test]
    fn detects_oversized_loose_object() {
        let findings = check_objects(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "oversized") || has_finding(&findings, "large"),
            "should detect oversized loose object in objects/de/"
        );
    }

    #[test]
    fn oversized_object_severity_at_least_medium() {
        let findings = check_objects(&fixture_git_dir()).unwrap();
        let f = findings.iter().find(|f| f.name.contains("oversized") || f.name.contains("large"));
        assert!(f.is_some(), "oversized object finding missing");
        assert!(f.unwrap().severity >= Severity::Medium);
    }

    // ── oversized pack files ────────────────────────────────────────────

    #[test]
    fn detects_oversized_pack_file() {
        let findings = check_objects(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "pack"),
            "should detect oversized pack file"
        );
    }

    // ── crafted / oversized index ───────────────────────────────────────

    #[test]
    fn detects_crafted_index() {
        let findings = check_objects(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "index"),
            "should detect crafted/oversized .git/index file"
        );
    }

    // ── alternates pointing to external path ────────────────────────────

    #[test]
    fn detects_alternates_file() {
        let findings = check_objects(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "alternates"),
            "should detect .git/objects/info/alternates pointing to external path"
        );
    }

    #[test]
    fn alternates_severity_is_critical() {
        let findings = check_objects(&fixture_git_dir()).unwrap();
        let f = findings.iter().find(|f| f.name.contains("alternates") && !f.name.contains("http"));
        assert!(f.is_some(), "alternates finding missing");
        assert_eq!(f.unwrap().severity, Severity::Critical);
    }

    // ── http-alternates ─────────────────────────────────────────────────

    #[test]
    fn detects_http_alternates() {
        let findings = check_objects(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "http-alternates") || has_finding(&findings, "http_alternates"),
            "should detect .git/objects/info/http-alternates"
        );
    }
}
