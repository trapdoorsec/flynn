use std::fs;
use std::path::Path;

use crate::arguments::Severity;
use crate::finding::Finding;

pub fn check_attributes(git_dir: &Path) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let repo_root = git_dir.parent().unwrap_or(git_dir);

    // Worktree .gitattributes
    let attrs_path = repo_root.join(".gitattributes");
    if let Ok(content) = fs::read_to_string(&attrs_path) {
        parse_attributes(&content, ".gitattributes", &mut findings);
    }

    // .git/info/attributes
    let info_attrs = git_dir.join("info").join("attributes");
    if let Ok(content) = fs::read_to_string(&info_attrs) {
        parse_attributes(&content, "info/attributes", &mut findings);
        findings.push(Finding {
            severity: Severity::High,
            name: "info/attributes".to_string(),
            reason: "info/attributes exists with filter/diff/merge drivers".to_string(),
        });
    }

    Ok(findings)
}

fn parse_attributes(content: &str, source: &str, findings: &mut Vec<Finding>) {
    let high_value_patterns = ["Makefile", "*.sh", "*.go", "build.gradle", "CMakeLists.txt"];

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let pattern = parts[0];
        let has_filter = parts[1..].iter().any(|a| a.starts_with("filter="));

        for attr in &parts[1..] {
            if attr.starts_with("filter=") {
                findings.push(Finding {
                    severity: Severity::Critical,
                    name: format!("filter attribute: {}", source),
                    reason: format!("{} on '{}' in {}", attr, pattern, source),
                });
                if high_value_patterns.contains(&pattern) {
                    findings.push(Finding {
                        severity: Severity::Critical,
                        name: "high-value filter target".to_string(),
                        reason: format!("{} targets '{}' in {}", attr, pattern, source),
                    });
                }
            }
            if attr.starts_with("diff=") {
                findings.push(Finding {
                    severity: Severity::High,
                    name: format!("diff attribute: {}", source),
                    reason: format!("{} on '{}' in {}", attr, pattern, source),
                });
            }
            if attr.starts_with("merge=") {
                findings.push(Finding {
                    severity: Severity::High,
                    name: format!("merge attribute: {}", source),
                    reason: format!("{} on '{}' in {}", attr, pattern, source),
                });
            }
            if attr.starts_with("eol=") && has_filter {
                findings.push(Finding {
                    severity: Severity::High,
                    name: "eol + filter combo".to_string(),
                    reason: format!("eol combined with filter on '{}' in {}", pattern, source),
                });
            }
            if *attr == "export-subst" {
                findings.push(Finding {
                    severity: Severity::Medium,
                    name: "export-subst attribute".to_string(),
                    reason: format!("export-subst on '{}' in {}", pattern, source),
                });
            }
            if *attr == "ident" {
                findings.push(Finding {
                    severity: Severity::Info,
                    name: "ident attribute".to_string(),
                    reason: format!("ident on '{}' in {}", pattern, source),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arguments::Severity;
    use crate::checks::test_fixture::fixture_git_dir;

    fn has_finding(findings: &[Finding], needle: &str) -> bool {
        findings.iter().any(|f| f.name.contains(needle) || f.reason.contains(needle))
    }

    // ── filter= attribute ───────────────────────────────────────────────

    #[test]
    fn detects_filter_attribute() {
        let findings = check_attributes(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "filter"),
            "should detect filter= attribute in .gitattributes"
        );
    }

    // ── diff= attribute ─────────────────────────────────────────────────

    #[test]
    fn detects_diff_attribute() {
        let findings = check_attributes(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "diff"),
            "should detect diff= attribute in .gitattributes"
        );
    }

    // ── merge= attribute ────────────────────────────────────────────────

    #[test]
    fn detects_merge_attribute() {
        let findings = check_attributes(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "merge"),
            "should detect merge= attribute in .gitattributes"
        );
    }

    // ── high-value filename targeting ───────────────────────────────────

    #[test]
    fn detects_makefile_targeting() {
        let findings = check_attributes(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "Makefile") || has_finding(&findings, "high-value"),
            "should flag filter= targeting Makefile"
        );
    }

    #[test]
    fn detects_shell_script_targeting() {
        let findings = check_attributes(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, ".sh") || has_finding(&findings, "shell"),
            "should flag filter= targeting *.sh"
        );
    }

    // ── eol + filter combo ──────────────────────────────────────────────

    #[test]
    fn detects_eol_filter_combo() {
        let findings = check_attributes(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "eol"),
            "should detect eol= combined with filter hooks"
        );
    }

    // ── export-subst ────────────────────────────────────────────────────

    #[test]
    fn detects_export_subst() {
        let findings = check_attributes(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "export-subst") || has_finding(&findings, "export"),
            "should detect export-subst attribute"
        );
    }

    // ── ident ───────────────────────────────────────────────────────────

    #[test]
    fn detects_ident_attribute() {
        let findings = check_attributes(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "ident"),
            "should detect ident attribute"
        );
    }

    // ── .git/info/attributes ────────────────────────────────────────────

    #[test]
    fn detects_info_attributes() {
        let findings = check_attributes(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "info/attributes") || has_finding(&findings, "info_attributes"),
            "should detect .git/info/attributes with filter/diff/merge drivers"
        );
    }
}
