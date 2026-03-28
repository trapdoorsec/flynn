use std::path::Path;

use crate::finding::Finding;

pub fn check_submodules(git_dir: &Path) -> anyhow::Result<Vec<Finding>> {
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

    // ── file:// URL ─────────────────────────────────────────────────────

    #[test]
    fn detects_file_protocol_url() {
        let findings = check_submodules(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "file://") || has_finding(&findings, "file_protocol"),
            "should detect submodule url using file:// scheme"
        );
    }

    // ── update = !command ───────────────────────────────────────────────

    #[test]
    fn detects_update_command_exec() {
        let findings = check_submodules(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "update") || has_finding(&findings, "!command") || has_finding(&findings, "exec"),
            "should detect .gitmodules with update = !command"
        );
    }

    #[test]
    fn update_command_severity_is_critical() {
        let findings = check_submodules(&fixture_git_dir()).unwrap();
        let f = findings.iter().find(|f|
            f.name.contains("update") || f.reason.contains("update = !")
        );
        assert!(f.is_some(), "update command finding missing");
        assert_eq!(f.unwrap().severity, Severity::Critical);
    }

    // ── ext:: scheme ────────────────────────────────────────────────────

    #[test]
    fn detects_ext_protocol() {
        let findings = check_submodules(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "ext::"),
            "should detect submodule url using ext:: scheme"
        );
    }

    // ── fd:: scheme ─────────────────────────────────────────────────────

    #[test]
    fn detects_fd_protocol() {
        let findings = check_submodules(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "fd::"),
            "should detect submodule url using fd:: scheme"
        );
    }

    // ── path traversal in submodule path ────────────────────────────────

    #[test]
    fn detects_path_traversal_submodule() {
        let findings = check_submodules(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "..") || has_finding(&findings, "traversal"),
            "should detect submodule path with .. components"
        );
    }

    // ── nested malicious repo in .git/modules/ ──────────────────────────

    #[test]
    fn detects_nested_module_malicious_config() {
        let findings = check_submodules(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "modules") || has_finding(&findings, "nested"),
            "should recurse-check .git/modules/ for malicious configs"
        );
    }

    #[test]
    fn detects_nested_module_malicious_hooks() {
        let findings = check_submodules(&fixture_git_dir()).unwrap();
        assert!(
            findings.iter().any(|f|
                (f.reason.contains("modules") || f.reason.contains("nested"))
                && (f.reason.contains("hook") || f.name.contains("hook"))
            ),
            "should detect malicious hooks inside .git/modules/ nested repos"
        );
    }
}
