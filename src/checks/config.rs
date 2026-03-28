use std::path::Path;

use crate::finding::Finding;

// all config key checks (fsmonitor, sshCommand, etc)
pub fn check_fsmonitor(git_dir: &Path) -> anyhow::Result<Vec<Finding>> {
    let test_finding = Finding {
        name: "Test Finding".to_string(),
        severity: crate::arguments::Severity::Info,
        reason: "Testing".to_string(),
    };
    Ok(vec![test_finding])
}

pub fn check_ssh_command(git_dir: &Path) -> anyhow::Result<Vec<Finding>> {
    let test_finding = Finding {
        name: "Test Finding".to_string(),
        severity: crate::arguments::Severity::Critical,
        reason: "Testing".to_string(),
    };
    Ok(vec![test_finding])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arguments::Severity;
    use crate::checks::test_fixture::fixture_git_dir;

    fn has_finding(findings: &[Finding], name_contains: &str) -> bool {
        findings.iter().any(|f| f.name.contains(name_contains))
    }

    // ── core.fsmonitor ──────────────────────────────────────────────────

    #[test]
    fn detects_core_fsmonitor() {
        let findings = check_fsmonitor(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "fsmonitor"),
            "should detect core.fsmonitor: got {:?}",
            findings.iter().map(|f| &f.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn fsmonitor_severity_is_critical() {
        let findings = check_fsmonitor(&fixture_git_dir()).unwrap();
        let f = findings.iter().find(|f| f.name.contains("fsmonitor"));
        assert!(f.is_some(), "fsmonitor finding missing");
        assert_eq!(f.unwrap().severity, Severity::Critical);
    }

    // ── core.sshCommand ─────────────────────────────────────────────────

    #[test]
    fn detects_core_ssh_command() {
        let findings = check_ssh_command(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "sshCommand"),
            "should detect core.sshCommand: got {:?}",
            findings.iter().map(|f| &f.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn ssh_command_severity_is_critical() {
        let findings = check_ssh_command(&fixture_git_dir()).unwrap();
        let f = findings.iter().find(|f| f.name.contains("sshCommand"));
        assert!(f.is_some(), "sshCommand finding missing");
        assert_eq!(f.unwrap().severity, Severity::Critical);
    }

    // ── core.gitProxy ───────────────────────────────────────────────────

    #[test]
    fn detects_core_git_proxy() {
        let findings = check_fsmonitor(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "gitProxy"),
            "should detect core.gitProxy"
        );
    }

    // ── core.editor ─────────────────────────────────────────────────────

    #[test]
    fn detects_core_editor() {
        let findings = check_fsmonitor(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "editor"),
            "should detect core.editor"
        );
    }

    // ── sequence.editor ─────────────────────────────────────────────────

    #[test]
    fn detects_sequence_editor() {
        let findings = check_fsmonitor(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "sequence.editor"),
            "should detect sequence.editor"
        );
    }

    // ── diff.external ───────────────────────────────────────────────────

    #[test]
    fn detects_diff_external() {
        let findings = check_fsmonitor(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "diff.external"),
            "should detect diff.external"
        );
    }

    // ── difftool / mergetool cmd ────────────────────────────────────────

    #[test]
    fn detects_difftool_cmd() {
        let findings = check_fsmonitor(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "difftool"),
            "should detect difftool.<name>.cmd"
        );
    }

    #[test]
    fn detects_mergetool_cmd() {
        let findings = check_fsmonitor(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "mergetool"),
            "should detect mergetool.<name>.cmd"
        );
    }

    // ── credential.helper ───────────────────────────────────────────────

    #[test]
    fn detects_credential_helper() {
        let findings = check_fsmonitor(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "credential"),
            "should detect credential.helper"
        );
    }

    // ── pager.<cmd> ─────────────────────────────────────────────────────

    #[test]
    fn detects_pager_cmd() {
        let findings = check_fsmonitor(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "pager"),
            "should detect pager.<cmd>"
        );
    }

    // ── filter.<name>.{clean,smudge,process} ────────────────────────────

    #[test]
    fn detects_filter_clean() {
        let findings = check_fsmonitor(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "filter") || has_finding(&findings, "clean"),
            "should detect filter.<name>.clean"
        );
    }

    #[test]
    fn detects_filter_smudge() {
        let findings = check_fsmonitor(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "smudge"),
            "should detect filter.<name>.smudge"
        );
    }

    #[test]
    fn detects_filter_process() {
        let findings = check_fsmonitor(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "process") || has_finding(&findings, "filter"),
            "should detect filter.<name>.process"
        );
    }

    // ── gpg.program / gpg.ssh.program / gpg.x509.program ───────────────

    #[test]
    fn detects_gpg_program() {
        let findings = check_fsmonitor(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "gpg.program") || has_finding(&findings, "gpg"),
            "should detect gpg.program"
        );
    }

    #[test]
    fn detects_gpg_ssh_program() {
        let findings = check_fsmonitor(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "gpg.ssh"),
            "should detect gpg.ssh.program"
        );
    }

    #[test]
    fn detects_gpg_x509_program() {
        let findings = check_fsmonitor(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "gpg.x509") || has_finding(&findings, "x509"),
            "should detect gpg.x509.program"
        );
    }

    // ── receive.procReceive ─────────────────────────────────────────────

    #[test]
    fn detects_receive_proc_receive() {
        let findings = check_fsmonitor(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "procReceive") || has_finding(&findings, "receive"),
            "should detect receive.procReceive"
        );
    }

    // ── uploadpack.packObjectsHook ──────────────────────────────────────

    #[test]
    fn detects_pack_objects_hook() {
        let findings = check_fsmonitor(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "packObjects") || has_finding(&findings, "uploadpack"),
            "should detect uploadpack.packObjectsHook"
        );
    }

    // ── core.pager ──────────────────────────────────────────────────────

    #[test]
    fn detects_core_pager() {
        let findings = check_fsmonitor(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "core.pager"),
            "should detect core.pager"
        );
    }

    // ── web.browser ─────────────────────────────────────────────────────

    #[test]
    fn detects_web_browser() {
        let findings = check_fsmonitor(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "web.browser") || has_finding(&findings, "browser"),
            "should detect web.browser"
        );
    }

    // ── sendemail.smtpserver ────────────────────────────────────────────

    #[test]
    fn detects_sendemail_smtpserver() {
        let findings = check_fsmonitor(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "sendemail") || has_finding(&findings, "smtpserver"),
            "should detect sendemail.smtpserver"
        );
    }

    // ── include.path / includeIf ────────────────────────────────────────

    #[test]
    fn detects_include_path() {
        let findings = check_fsmonitor(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "include"),
            "should detect include.path"
        );
    }

    #[test]
    fn detects_include_if_path() {
        let findings = check_fsmonitor(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "includeIf"),
            "should detect includeIf.*.path"
        );
    }

    // ── core.hooksPath ──────────────────────────────────────────────────

    #[test]
    fn detects_core_hooks_path() {
        let findings = check_fsmonitor(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "hooksPath"),
            "should detect core.hooksPath"
        );
    }

    // ── transfer.fsckObjects ────────────────────────────────────────────

    #[test]
    fn detects_transfer_fsck_objects() {
        let findings = check_fsmonitor(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "fsckObjects") || has_finding(&findings, "transfer"),
            "should detect transfer.fsckObjects"
        );
    }
}
