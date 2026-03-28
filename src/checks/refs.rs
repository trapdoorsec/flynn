use std::path::Path;

use crate::finding::Finding;

pub fn check_refs(git_dir: &Path) -> anyhow::Result<Vec<Finding>> {
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

    // ── detached HEAD (raw SHA) ─────────────────────────────────────────

    #[test]
    fn detects_detached_head() {
        let findings = check_refs(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "HEAD") || has_finding(&findings, "detached"),
            "should detect HEAD containing a raw SHA instead of symbolic ref"
        );
    }

    // ── HEAD pointing to non-existent ref ───────────────────────────────

    #[test]
    fn detects_head_pointing_to_nonexistent_ref() {
        let findings = check_refs(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "non-existent") || has_finding(&findings, "invalid") || has_finding(&findings, "HEAD"),
            "should detect HEAD pointing to a non-existent ref/object"
        );
    }

    // ── path-traversal ref names ────────────────────────────────────────

    #[test]
    fn detects_path_traversal_ref() {
        let findings = check_refs(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "traversal") || has_finding(&findings, ".."),
            "should detect ref names with path-traversal characters"
        );
    }

    // ── ref pointing to non-existent object ─────────────────────────────

    #[test]
    fn detects_orphan_ref() {
        let findings = check_refs(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "orphan") || has_finding(&findings, "0000000"),
            "should detect ref pointing to all-zeros / non-existent object"
        );
    }

    // ── packed-refs with suspicious names ────────────────────────────────

    #[test]
    fn detects_suspicious_packed_refs() {
        let findings = check_refs(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "packed-refs") || has_finding(&findings, "packed"),
            "should detect suspicious entries in packed-refs"
        );
    }

    // ── leftover state files ────────────────────────────────────────────

    #[test]
    fn detects_fetch_head() {
        let findings = check_refs(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "FETCH_HEAD"),
            "should detect unexpected FETCH_HEAD"
        );
    }

    #[test]
    fn detects_merge_head() {
        let findings = check_refs(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "MERGE_HEAD"),
            "should detect unexpected MERGE_HEAD"
        );
    }

    #[test]
    fn detects_cherry_pick_head() {
        let findings = check_refs(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "CHERRY_PICK_HEAD"),
            "should detect unexpected CHERRY_PICK_HEAD"
        );
    }

    #[test]
    fn detects_revert_head() {
        let findings = check_refs(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "REVERT_HEAD"),
            "should detect unexpected REVERT_HEAD"
        );
    }

    #[test]
    fn detects_orig_head() {
        let findings = check_refs(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "ORIG_HEAD"),
            "should detect unexpected ORIG_HEAD"
        );
    }
}
