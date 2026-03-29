use std::fs;
use std::path::Path;

use crate::arguments::Severity;
use crate::finding::Finding;

fn dangerous_config_match(section: &str, key: &str, value: &str) -> Option<Finding> {
    let (name, severity) = match (section, key) {
        ("core", "fsmonitor") | ("core", "fsmonitorv2") => ("core.fsmonitor", Severity::Critical),
        ("core", "sshcommand") => ("core.sshCommand", Severity::Critical),
        ("core", "gitproxy") => ("core.gitProxy", Severity::Critical),
        ("core", "editor") => ("core.editor", Severity::High),
        ("core", "pager") => ("core.pager", Severity::High),
        ("core", "hookspath") => ("core.hooksPath", Severity::Critical),
        ("sequence", "editor") => ("sequence.editor", Severity::High),
        ("diff", "external") => ("diff.external", Severity::High),
        ("credential", "helper") => ("credential.helper", Severity::Critical),
        ("gpg", "program") => ("gpg.program", Severity::High),
        ("receive", "procreceive") => ("receive.procReceive", Severity::Critical),
        ("uploadpack", "packobjectshook") => ("uploadpack.packObjectsHook", Severity::Critical),
        ("web", "browser") => ("web.browser", Severity::High),
        ("sendemail", "smtpserver") => ("sendemail.smtpserver", Severity::High),
        ("transfer", "fsckobjects") => ("transfer.fsckObjects", Severity::Medium),
        _ => return None,
    };
    Some(Finding {
        severity,
        name: name.to_string(),
        reason: format!("{} = {}", name, value),
        reference: String::new(),
    })
}

fn parse_section_header(line: &str) -> Option<(String, Option<String>)> {
    let trimmed = line.trim();
    if !trimmed.starts_with('[') {
        return None;
    }
    let end = trimmed.rfind(']')?;
    let header = &trimmed[1..end];
    if let Some(quote_start) = header.find('"') {
        let section = header[..quote_start].trim().to_lowercase();
        let sub = header[quote_start + 1..].trim_end_matches('"').to_string();
        Some((section, Some(sub)))
    } else {
        Some((header.trim().to_lowercase(), None))
    }
}

pub fn check_fsmonitor(git_dir: &Path) -> anyhow::Result<Vec<Finding>> {
    let config_path = git_dir.join("config");
    let content = match fs::read(&config_path) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
        Err(_) => return Ok(vec![]),
    };

    let mut findings = Vec::new();
    let mut section = String::new();
    let mut subsection: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();

        if let Some((s, sub)) = parse_section_header(line) {
            section = s;
            subsection = sub;
            continue;
        }

        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }

        if let Some(eq_pos) = trimmed.find('=') {
            let key = trimmed[..eq_pos].trim().to_lowercase();
            let value = trimmed[eq_pos + 1..].trim();

            // Simple section.key matches (no subsection required)
            if subsection.is_none() {
                if let Some(finding) = dangerous_config_match(&section, &key, value) {
                    findings.push(finding);
                }
            }

            // Subsection-based matches
            if let Some(ref sub) = subsection {
                if section == "difftool" && key == "cmd" {
                    findings.push(Finding {
                        severity: Severity::High,
                        name: "difftool.cmd".to_string(),
                        reason: format!("difftool.{}.cmd = {}", sub, value),
                        reference: String::new(),
                    });
                }
                if section == "mergetool" && key == "cmd" {
                    findings.push(Finding {
                        severity: Severity::High,
                        name: "mergetool.cmd".to_string(),
                        reason: format!("mergetool.{}.cmd = {}", sub, value),
                        reference: String::new(),
                    });
                }
                if section == "gpg" && key == "program" {
                    let sub_lower = sub.to_lowercase();
                    if sub_lower == "ssh" {
                        findings.push(Finding {
                            severity: Severity::High,
                            name: "gpg.ssh.program".to_string(),
                            reason: format!("gpg.ssh.program = {}", value),
                            reference: String::new(),
                        });
                    } else if sub_lower == "x509" {
                        findings.push(Finding {
                            severity: Severity::High,
                            name: "gpg.x509.program".to_string(),
                            reason: format!("gpg.x509.program = {}", value),
                            reference: String::new(),
                        });
                    }
                }
                if section == "includeif" && key == "path" {
                    findings.push(Finding {
                        severity: Severity::Critical,
                        name: "includeIf.path".to_string(),
                        reason: format!("includeIf conditional include: {}", value),
                        reference: String::new(),
                    });
                }
            }

            // pager.* (any key under [pager] section)
            if section == "pager" && subsection.is_none() {
                findings.push(Finding {
                    severity: Severity::High,
                    name: format!("pager.{}", key),
                    reason: format!("pager.{} = {}", key, value),
                    reference: String::new(),
                });
            }

            // filter.*.{clean,smudge,process}
            if section == "filter" {
                if key == "clean" || key == "smudge" || key == "process" {
                    findings.push(Finding {
                        severity: Severity::Critical,
                        name: format!("filter.{}", key),
                        reason: format!("filter {} = {}", key, value),
                        reference: String::new(),
                    });
                }
            }

            // include.path (no subsection)
            if section == "include" && subsection.is_none() && key == "path" {
                findings.push(Finding {
                    severity: Severity::Critical,
                    name: "include.path".to_string(),
                    reason: format!("include.path = {}", value),
                    reference: String::new(),
                });
            }
        }
    }

    Ok(findings)
}

pub fn check_ssh_command(git_dir: &Path) -> anyhow::Result<Vec<Finding>> {
    let config_path = git_dir.join("config");
    let content = match fs::read(&config_path) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
        Err(_) => return Ok(vec![]),
    };

    let mut findings = Vec::new();
    let mut section = String::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if let Some((s, _)) = parse_section_header(line) {
            section = s;
            continue;
        }
        if let Some(eq_pos) = trimmed.find('=') {
            let key = trimmed[..eq_pos].trim().to_lowercase();
            let value = trimmed[eq_pos + 1..].trim();
            if section == "core" && key == "sshcommand" {
                findings.push(Finding {
                    severity: Severity::Critical,
                    name: "core.sshCommand".to_string(),
                    reason: format!("core.sshCommand = {}", value),
                    reference: String::new(),
                });
            }
        }
    }

    Ok(findings)
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
