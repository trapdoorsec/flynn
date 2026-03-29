use std::fs;
use std::path::Path;

use crate::arguments::Severity;
use crate::finding::Finding;

pub fn check_submodules(git_dir: &Path) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let repo_root = git_dir.parent().unwrap_or(git_dir);

    // Parse .gitmodules
    let gitmodules = repo_root.join(".gitmodules");
    if let Ok(content) = fs::read_to_string(&gitmodules) {
        for line in content.lines() {
            let trimmed = line.trim();
            if let Some(eq_pos) = trimmed.find('=') {
                let key = trimmed[..eq_pos].trim().to_lowercase();
                let value = trimmed[eq_pos + 1..].trim();

                match key.as_str() {
                    "url" => {
                        if value.starts_with("file://") {
                            findings.push(Finding {
                                severity: Severity::High,
                                name: "submodule file:// URL".to_string(),
                                reason: format!("submodule URL uses file:// scheme: {}", value),
                                reference: String::new(),
                            });
                        }
                        if value.starts_with("ext::") {
                            findings.push(Finding {
                                severity: Severity::Critical,
                                name: "submodule ext:: URL".to_string(),
                                reason: format!("submodule URL uses ext:: protocol: {}", value),
                                reference: String::new(),
                            });
                        }
                        if value.starts_with("fd::") {
                            findings.push(Finding {
                                severity: Severity::High,
                                name: "submodule fd:: URL".to_string(),
                                reason: format!("submodule URL uses fd:: protocol: {}", value),
                                reference: String::new(),
                            });
                        }
                    }
                    "update" => {
                        if value.starts_with('!') {
                            findings.push(Finding {
                                severity: Severity::Critical,
                                name: "submodule update command".to_string(),
                                reason: format!("submodule update = !command: {}", value),
                                reference: String::new(),
                            });
                        }
                    }
                    "path" => {
                        if value.contains("..") {
                            findings.push(Finding {
                                severity: Severity::Critical,
                                name: "submodule path traversal".to_string(),
                                reason: format!("submodule path contains .. components: {}", value),
                                reference: String::new(),
                            });
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Check .git/modules/ for nested malicious repos
    let modules_dir = git_dir.join("modules");
    if modules_dir.is_dir() {
        for entry in fs::read_dir(&modules_dir).into_iter().flatten().flatten() {
            if !entry.path().is_dir() {
                continue;
            }

            let name = entry.file_name().to_string_lossy().to_string();
            let module_dir = entry.path();

            // Check nested config for dangerous keys
            if let Ok(config) = fs::read_to_string(module_dir.join("config")) {
                let mut section = String::new();

                for line in config.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with('[') {
                        if let Some(end) = trimmed.rfind(']') {
                            section = trimmed[1..end].split('"').next().unwrap_or("").trim().to_lowercase();
                        }
                        continue;
                    }
                    if let Some(eq_pos) = trimmed.find('=') {
                        let key = trimmed[..eq_pos].trim().to_lowercase();
                        let value = trimmed[eq_pos + 1..].trim();

                        let dangerous_keys = ["fsmonitor", "sshcommand", "hookspath", "editor"];
                        if dangerous_keys.contains(&key.as_str()) {
                            findings.push(Finding {
                                severity: Severity::Critical,
                                name: format!("nested modules config: {}", name),
                                reason: format!("nested module {} has dangerous config: {} = {}", name, key, value),
                                reference: String::new(),
                            });
                        }

                        if section.starts_with("remote") && key == "url" {
                            if value.starts_with("ext::") || value.starts_with("fd::") {
                                findings.push(Finding {
                                    severity: Severity::Critical,
                                    name: format!("nested modules config: {}", name),
                                    reason: format!("nested module {} has dangerous remote URL: {}", name, value),
                                    reference: String::new(),
                                });
                            }
                        }
                    }
                }
            }

            // Check nested hooks
            let hooks_dir = module_dir.join("hooks");
            if hooks_dir.is_dir() {
                for hook_entry in fs::read_dir(&hooks_dir).into_iter().flatten().flatten() {
                    let hook_name = hook_entry.file_name().to_string_lossy().to_string();
                    if hook_name.ends_with(".sample") {
                        continue;
                    }
                    findings.push(Finding {
                        severity: Severity::Critical,
                        name: format!("nested module hook: {}", hook_name),
                        reason: format!("nested module {} has hook: {}", name, hook_name),
                        reference: String::new(),
                    });
                }
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
