use std::fs;
use std::path::Path;

use crate::arguments::Severity;
use crate::finding::Finding;

pub fn check_worktrees(git_dir: &Path) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let worktrees_dir = git_dir.join("worktrees");

    if !worktrees_dir.is_dir() {
        return Ok(vec![]);
    }

    for entry in fs::read_dir(&worktrees_dir)? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        if !entry.path().is_dir() {
            continue;
        }

        let name = entry.file_name().to_string_lossy().to_string();

        findings.push(Finding {
            severity: Severity::Medium,
            name: format!("worktree: {}", name),
            reason: format!("worktree entry found: {}", name),
            reference: String::new(),
        });

        // Check gitdir file for sensitive paths
        let gitdir_path = entry.path().join("gitdir");
        if let Ok(content) = fs::read_to_string(&gitdir_path) {
            let target = content.trim();
            if target.starts_with('/') || target.contains("..") {
                findings.push(Finding {
                    severity: Severity::High,
                    name: format!("worktree gitdir: {}", name),
                    reason: format!("worktree {} gitdir points to {}", name, target),
                    reference: String::new(),
                });
            }
        }

        // Check commondir file
        let commondir_path = entry.path().join("commondir");
        if let Ok(content) = fs::read_to_string(&commondir_path) {
            let target = content.trim();
            findings.push(Finding {
                severity: Severity::High,
                name: format!("worktree commondir: {}", name),
                reason: format!("worktree {} commondir points to {}", name, target),
                reference: String::new(),
            });
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
