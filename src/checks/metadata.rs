use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::arguments::Severity;
use crate::finding::Finding;

pub fn check_metadata(git_dir: &Path) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // Sparse-checkout
    let sparse = git_dir.join("info").join("sparse-checkout");
    if let Ok(content) = fs::read_to_string(&sparse) {
        let suspicious = content.lines().any(|l| {
            let t = l.trim();
            t.contains("..") || t.starts_with("/etc") || t.starts_with("/tmp") || t.contains("sensitive")
        });
        if suspicious || !content.trim().is_empty() {
            findings.push(Finding {
                severity: Severity::Medium,
                name: "sparse-checkout".to_string(),
                reason: "sparse-checkout contains unusual patterns".to_string(),
            });
        }
    }

    // info/exclude
    let exclude = git_dir.join("info").join("exclude");
    if let Ok(content) = fs::read_to_string(&exclude) {
        let entries: Vec<&str> = content
            .lines()
            .filter(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with('#')
            })
            .collect();
        if !entries.is_empty() {
            findings.push(Finding {
                severity: Severity::Medium,
                name: "info/exclude".to_string(),
                reason: format!("info/exclude has {} non-comment entries (may be hiding files)", entries.len()),
            });
        }
    }

    // Tampered description
    let description = git_dir.join("description");
    if let Ok(content) = fs::read_to_string(&description) {
        let default = "Unnamed repository; edit this file 'description' to name the repository.";
        if content.trim() != default {
            findings.push(Finding {
                severity: Severity::Info,
                name: "tampered description".to_string(),
                reason: "description file modified from default".to_string(),
            });
        }
    }

    // Parse config for [user], remotes, pushurl
    let config_path = git_dir.join("config");
    if let Ok(bytes) = fs::read(&config_path) {
        let content = String::from_utf8_lossy(&bytes);
        let mut section = String::new();
        let mut subsection: Option<String> = None;
        let mut remote_urls: HashMap<String, String> = HashMap::new();
        let mut remote_pushurls: HashMap<String, String> = HashMap::new();

        for line in content.lines() {
            let trimmed = line.trim();

            if trimmed.starts_with('[') {
                if let Some(end) = trimmed.rfind(']') {
                    let header = &trimmed[1..end];
                    if let Some(quote_start) = header.find('"') {
                        section = header[..quote_start].trim().to_lowercase();
                        subsection = Some(header[quote_start + 1..].trim_end_matches('"').to_string());
                    } else {
                        section = header.trim().to_lowercase();
                        subsection = None;
                    }
                }

                if section == "user" && subsection.is_none() {
                    findings.push(Finding {
                        severity: Severity::Medium,
                        name: "config [user] section".to_string(),
                        reason: "[user] section in local config".to_string(),
                    });
                }
                continue;
            }

            if let Some(eq_pos) = trimmed.find('=') {
                let key = trimmed[..eq_pos].trim().to_lowercase();
                let value = trimmed[eq_pos + 1..].trim().to_string();

                if section == "remote" {
                    if let Some(ref remote_name) = subsection {
                        if key == "url" {
                            if value.starts_with("ext::") {
                                findings.push(Finding {
                                    severity: Severity::Critical,
                                    name: "remote ext:: protocol".to_string(),
                                    reason: format!("remote '{}' uses ext:: URL: {}", remote_name, value),
                                });
                            }
                            if value.starts_with("fd::") {
                                findings.push(Finding {
                                    severity: Severity::High,
                                    name: "remote fd:: protocol".to_string(),
                                    reason: format!("remote '{}' uses fd:: URL: {}", remote_name, value),
                                });
                            }
                            if value.starts_with("file://") {
                                findings.push(Finding {
                                    severity: Severity::High,
                                    name: "remote file:// protocol".to_string(),
                                    reason: format!("remote '{}' uses file:// URL: {}", remote_name, value),
                                });
                            }
                            remote_urls.insert(remote_name.clone(), value.clone());
                        }
                        if key == "pushurl" {
                            remote_pushurls.insert(remote_name.clone(), value.clone());
                        }
                    }
                }
            }
        }

        // pushurl mismatches
        for (remote_name, pushurl) in &remote_pushurls {
            if let Some(url) = remote_urls.get(remote_name) {
                if pushurl != url {
                    findings.push(Finding {
                        severity: Severity::High,
                        name: "pushurl mismatch".to_string(),
                        reason: format!(
                            "remote '{}' pushurl ({}) differs from url ({})",
                            remote_name, pushurl, url
                        ),
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

    // ── sparse-checkout with unusual patterns ───────────────────────────

    #[test]
    fn detects_suspicious_sparse_checkout() {
        let findings = check_metadata(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "sparse-checkout") || has_finding(&findings, "sparse"),
            "should detect .git/info/sparse-checkout with unusual glob patterns"
        );
    }

    // ── info/exclude ────────────────────────────────────────────────────

    #[test]
    fn detects_info_exclude() {
        let findings = check_metadata(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "exclude"),
            "should detect .git/info/exclude (attacker hiding tracks)"
        );
    }

    // ── tampered description ────────────────────────────────────────────

    #[test]
    fn detects_tampered_description() {
        let findings = check_metadata(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "description"),
            "should detect .git/description modified from default"
        );
    }

    // ── unexpected [user] section ───────────────────────────────────────

    #[test]
    fn detects_user_section() {
        let findings = check_metadata(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "[user]") || has_finding(&findings, "user"),
            "should detect unexpected [user] section in config"
        );
    }

    // ── pushurl differing from url ──────────────────────────────────────

    #[test]
    fn detects_pushurl_mismatch() {
        let findings = check_metadata(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "pushurl"),
            "should detect [remote] pushurl differing from url"
        );
    }

    #[test]
    fn pushurl_mismatch_severity_at_least_high() {
        let findings = check_metadata(&fixture_git_dir()).unwrap();
        let f = findings.iter().find(|f| f.name.contains("pushurl") || f.reason.contains("pushurl"));
        assert!(f.is_some(), "pushurl finding missing");
        assert!(f.unwrap().severity >= Severity::High);
    }

    // ── ext:: remote URL ────────────────────────────────────────────────

    #[test]
    fn detects_ext_protocol_remote() {
        let findings = check_metadata(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "ext::"),
            "should detect remote URL using ext:: protocol"
        );
    }

    #[test]
    fn ext_protocol_severity_is_critical() {
        let findings = check_metadata(&fixture_git_dir()).unwrap();
        let f = findings.iter().find(|f| f.reason.contains("ext::") || f.name.contains("ext::"));
        assert!(f.is_some(), "ext:: finding missing");
        assert_eq!(f.unwrap().severity, Severity::Critical);
    }

    // ── fd:: remote URL ─────────────────────────────────────────────────

    #[test]
    fn detects_fd_protocol_remote() {
        let findings = check_metadata(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "fd::"),
            "should detect remote URL using fd:: protocol"
        );
    }

    // ── file:// remote URL ──────────────────────────────────────────────

    #[test]
    fn detects_file_protocol_remote() {
        let findings = check_metadata(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "file://") || has_finding(&findings, "file_protocol"),
            "should detect remote URL using file:// scheme"
        );
    }
}
