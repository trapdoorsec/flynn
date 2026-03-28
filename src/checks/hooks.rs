use std::path::Path;

use crate::finding::Finding;

pub fn check_executable_hooks(git_dir: &Path) -> anyhow::Result<Vec<Finding>> {
    Ok(vec![])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arguments::Severity;
    use crate::checks::test_fixture::fixture_git_dir;

    fn has_finding(findings: &[Finding], name_contains: &str) -> bool {
        findings.iter().any(|f| f.name.contains(name_contains))
    }

    // ── executable hooks with canonical names ───────────────────────────

    #[test]
    fn detects_executable_pre_commit_hook() {
        let findings = check_executable_hooks(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "pre-commit"),
            "should detect executable pre-commit hook"
        );
    }

    #[test]
    fn detects_executable_post_checkout_hook() {
        let findings = check_executable_hooks(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "post-checkout"),
            "should detect executable post-checkout hook"
        );
    }

    #[test]
    fn detects_executable_pre_push_hook() {
        let findings = check_executable_hooks(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "pre-push"),
            "should detect executable pre-push hook"
        );
    }

    #[test]
    fn detects_all_canonical_hooks() {
        let findings = check_executable_hooks(&fixture_git_dir()).unwrap();
        let expected = vec![
            "pre-commit", "post-commit", "pre-push", "post-checkout",
            "post-merge", "post-rewrite", "prepare-commit-msg", "commit-msg",
            "pre-rebase", "pre-auto-gc", "post-update", "pre-receive",
            "update", "proc-receive", "push-to-checkout", "fsmonitor-watchman",
            "p4-pre-submit", "p4-prepare-changelist", "p4-changelist",
            "p4-post-changelist",
        ];
        for hook_name in &expected {
            assert!(
                has_finding(&findings, hook_name),
                "should detect executable hook: {hook_name}"
            );
        }
    }

    // ── non-.sample hooks present ───────────────────────────────────────

    #[test]
    fn flags_non_sample_hooks() {
        let findings = check_executable_hooks(&fixture_git_dir()).unwrap();
        // should have findings for hooks that aren't .sample files
        assert!(
            !findings.is_empty(),
            "should flag non-.sample hooks present in hooks dir"
        );
    }

    // ── world-writable hooks ────────────────────────────────────────────

    #[test]
    fn detects_world_writable_hook() {
        let findings = check_executable_hooks(&fixture_git_dir()).unwrap();
        assert!(
            findings.iter().any(|f| f.name.contains("world-writable") || f.reason.contains("writable") || f.reason.contains("0777")),
            "should detect world-writable hook (post-commit has mode 0777)"
        );
    }

    // ── unusual shebangs ────────────────────────────────────────────────

    #[test]
    fn detects_python_shebang_hook() {
        let findings = check_executable_hooks(&fixture_git_dir()).unwrap();
        assert!(
            findings.iter().any(|f| f.reason.contains("python") || f.name.contains("shebang")),
            "should flag hook with python shebang"
        );
    }

    #[test]
    fn detects_node_shebang_hook() {
        let findings = check_executable_hooks(&fixture_git_dir()).unwrap();
        assert!(
            findings.iter().any(|f| f.reason.contains("node") || f.name.contains("shebang")),
            "should flag hook with node shebang"
        );
    }

    #[test]
    fn detects_perl_shebang_hook() {
        let findings = check_executable_hooks(&fixture_git_dir()).unwrap();
        assert!(
            findings.iter().any(|f| f.reason.contains("perl") || f.name.contains("shebang")),
            "should flag hook with perl shebang"
        );
    }

    // ── symlink hooks ───────────────────────────────────────────────────

    #[test]
    fn detects_symlink_hook_pointing_outside_repo() {
        let findings = check_executable_hooks(&fixture_git_dir()).unwrap();
        assert!(
            findings.iter().any(|f| f.reason.contains("symlink") || f.name.contains("symlink")),
            "should detect hook that is a symlink pointing outside the repo (post-merge -> /tmp/evil-hook-target)"
        );
    }
}
