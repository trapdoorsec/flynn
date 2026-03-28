use std::path::Path;

use crate::finding::Finding;

pub fn check_worktrees(git_dir: &Path) -> anyhow::Result<Vec<Finding>> {
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

    // ── worktrees present at all ────────────────────────────────────────

    #[test]
    fn detects_worktree_entries_present() {
        let findings = check_worktrees(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "worktree"),
            "should flag that .git/worktrees/ entries exist"
        );
    }

    // ── gitdir pointing outside expected path ───────────────────────────

    #[test]
    fn detects_worktree_gitdir_to_sensitive_path() {
        let findings = check_worktrees(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "/tmp") || has_finding(&findings, "sensitive") || has_finding(&findings, "outside"),
            "should detect worktree gitdir pointing to /tmp/sensitive-location"
        );
    }

    #[test]
    fn detects_worktree_gitdir_to_etc() {
        let findings = check_worktrees(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "/etc"),
            "should detect worktree gitdir pointing to /etc"
        );
    }

    // ── commondir pointing to unexpected location ───────────────────────

    #[test]
    fn detects_worktree_commondir_external() {
        let findings = check_worktrees(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "commondir"),
            "should detect worktree commondir pointing to unexpected location"
        );
    }

    // ── multiple worktrees to sensitive locations ────────────────────────

    #[test]
    fn detects_multiple_suspicious_worktrees() {
        let findings = check_worktrees(&fixture_git_dir()).unwrap();
        let worktree_findings: Vec<_> = findings.iter()
            .filter(|f| f.name.contains("worktree"))
            .collect();
        assert!(
            worktree_findings.len() >= 2,
            "should detect multiple worktree entries (found {})",
            worktree_findings.len()
        );
    }
}
