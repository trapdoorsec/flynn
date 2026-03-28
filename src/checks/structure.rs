use std::path::Path;

use crate::finding::Finding;

pub fn check_buried_bare_repo(git_dir: &Path) -> anyhow::Result<Vec<Finding>> {
    Ok(vec![])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arguments::Severity;
    use crate::checks::test_fixture::{fixture_git_dir, fixture_repo_dir};

    fn has_finding(findings: &[Finding], name_contains: &str) -> bool {
        findings.iter().any(|f| f.name.contains(name_contains))
    }

    // ── buried bare repo ────────────────────────────────────────────────

    #[test]
    fn detects_buried_bare_repo() {
        let findings = check_buried_bare_repo(&fixture_git_dir()).unwrap();
        assert!(
            findings.iter().any(|f| f.name.contains("buried") || f.name.contains("bare")),
            "should detect buried bare repo at vendor/innocent-lib/"
        );
    }

    #[test]
    fn buried_bare_repo_severity_is_critical() {
        let findings = check_buried_bare_repo(&fixture_git_dir()).unwrap();
        let f = findings.iter().find(|f| f.name.contains("buried") || f.name.contains("bare"));
        assert!(f.is_some(), "buried bare repo finding missing");
        assert_eq!(f.unwrap().severity, Severity::Critical);
    }

    // ── core.bare=false + core.worktree jailbreak ───────────────────────

    #[test]
    fn detects_bare_worktree_jailbreak() {
        let findings = check_buried_bare_repo(&fixture_git_dir()).unwrap();
        assert!(
            findings.iter().any(|f| f.reason.contains("worktree") || f.name.contains("jailbreak")),
            "should detect core.bare=false + core.worktree jailbreak pattern"
        );
    }

    // ── .git file redirect ──────────────────────────────────────────────

    #[test]
    fn detects_gitdir_file_redirect() {
        let findings = check_buried_bare_repo(&fixture_git_dir()).unwrap();
        assert!(
            findings.iter().any(|f| f.name.contains("gitdir") || f.reason.contains("gitdir")),
            "should detect .git file containing gitdir: redirect (subproject/.git)"
        );
    }

    #[test]
    fn detects_gitdir_pointing_outside_repo() {
        let findings = check_buried_bare_repo(&fixture_git_dir()).unwrap();
        assert!(
            findings.iter().any(|f| f.reason.contains("/tmp") || f.reason.contains("outside")),
            "should flag gitdir: pointing to absolute/external path"
        );
    }

    // ── core.worktree pointing outside repo ─────────────────────────────

    #[test]
    fn detects_worktree_outside_repo() {
        let findings = check_buried_bare_repo(&fixture_git_dir()).unwrap();
        assert!(
            findings.iter().any(|f| f.reason.contains("worktree") && (f.reason.contains("/tmp") || f.reason.contains("outside"))),
            "should detect core.worktree pointing outside the repo root"
        );
    }

    // ── symlinks within .git/ pointing outside ──────────────────────────

    #[test]
    fn detects_symlinks_in_git_dir() {
        let findings = check_buried_bare_repo(&fixture_git_dir()).unwrap();
        assert!(
            findings.iter().any(|f| f.name.contains("symlink") || f.reason.contains("symlink")),
            "should detect symlinks within .git/ pointing outside the repo"
        );
    }

    // ── unexpected subdirectories ───────────────────────────────────────

    #[test]
    fn detects_unexpected_subdirectory() {
        let findings = check_buried_bare_repo(&fixture_git_dir()).unwrap();
        assert!(
            findings.iter().any(|f| f.reason.contains("payload-staging") || f.name.contains("unexpected")),
            "should detect unexpected subdirectory inside .git/ (payload-staging/)"
        );
    }

    // ── multiple [core] sections ────────────────────────────────────────

    #[test]
    fn detects_duplicate_core_sections() {
        let findings = check_buried_bare_repo(&fixture_git_dir()).unwrap();
        assert!(
            findings.iter().any(|f| f.reason.contains("multiple") || f.reason.contains("duplicate") || f.name.contains("[core]")),
            "should detect multiple [core] sections in config"
        );
    }
}
