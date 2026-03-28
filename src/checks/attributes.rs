use std::path::Path;

use crate::finding::Finding;

pub fn check_attributes(git_dir: &Path) -> anyhow::Result<Vec<Finding>> {
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

    // ── filter= attribute ───────────────────────────────────────────────

    #[test]
    fn detects_filter_attribute() {
        let findings = check_attributes(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "filter"),
            "should detect filter= attribute in .gitattributes"
        );
    }

    // ── diff= attribute ─────────────────────────────────────────────────

    #[test]
    fn detects_diff_attribute() {
        let findings = check_attributes(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "diff"),
            "should detect diff= attribute in .gitattributes"
        );
    }

    // ── merge= attribute ────────────────────────────────────────────────

    #[test]
    fn detects_merge_attribute() {
        let findings = check_attributes(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "merge"),
            "should detect merge= attribute in .gitattributes"
        );
    }

    // ── high-value filename targeting ───────────────────────────────────

    #[test]
    fn detects_makefile_targeting() {
        let findings = check_attributes(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "Makefile") || has_finding(&findings, "high-value"),
            "should flag filter= targeting Makefile"
        );
    }

    #[test]
    fn detects_shell_script_targeting() {
        let findings = check_attributes(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, ".sh") || has_finding(&findings, "shell"),
            "should flag filter= targeting *.sh"
        );
    }

    // ── eol + filter combo ──────────────────────────────────────────────

    #[test]
    fn detects_eol_filter_combo() {
        let findings = check_attributes(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "eol"),
            "should detect eol= combined with filter hooks"
        );
    }

    // ── export-subst ────────────────────────────────────────────────────

    #[test]
    fn detects_export_subst() {
        let findings = check_attributes(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "export-subst") || has_finding(&findings, "export"),
            "should detect export-subst attribute"
        );
    }

    // ── ident ───────────────────────────────────────────────────────────

    #[test]
    fn detects_ident_attribute() {
        let findings = check_attributes(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "ident"),
            "should detect ident attribute"
        );
    }

    // ── .git/info/attributes ────────────────────────────────────────────

    #[test]
    fn detects_info_attributes() {
        let findings = check_attributes(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "info/attributes") || has_finding(&findings, "info_attributes"),
            "should detect .git/info/attributes with filter/diff/merge drivers"
        );
    }
}
