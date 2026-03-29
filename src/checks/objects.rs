use std::fs;
use std::path::Path;

use crate::arguments::Severity;
use crate::finding::Finding;

pub fn check_objects(git_dir: &Path) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let objects_dir = git_dir.join("objects");

    // Oversized loose objects (2-char hex dirs containing large files)
    if objects_dir.is_dir() {
        for entry in fs::read_dir(&objects_dir).into_iter().flatten().flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.len() == 2 && name.chars().all(|c| c.is_ascii_hexdigit()) && entry.path().is_dir() {
                for obj in fs::read_dir(entry.path()).into_iter().flatten().flatten() {
                    if let Ok(meta) = obj.metadata() {
                        if meta.len() > 1_000_000 {
                            findings.push(Finding {
                                severity: Severity::High,
                                name: "oversized loose object".to_string(),
                                reason: format!(
                                    "loose object {}/{} is {}KB",
                                    name,
                                    obj.file_name().to_string_lossy(),
                                    meta.len() / 1024
                                ),
                                reference: String::new(),
                            });
                        }
                    }
                }
            }
        }
    }

    // Oversized pack files
    let pack_dir = objects_dir.join("pack");
    if pack_dir.is_dir() {
        for entry in fs::read_dir(&pack_dir).into_iter().flatten().flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".pack") {
                if let Ok(meta) = entry.metadata() {
                    if meta.len() > 1_000_000 {
                        findings.push(Finding {
                            severity: Severity::High,
                            name: "oversized pack file".to_string(),
                            reason: format!("pack file {} is {}KB", name, meta.len() / 1024),
                            reference: String::new(),
                        });
                    }
                }
            }
        }
    }

    // Oversized index file
    let index_path = git_dir.join("index");
    if let Ok(meta) = fs::metadata(&index_path) {
        if meta.len() > 100_000 {
            findings.push(Finding {
                severity: Severity::Medium,
                name: "oversized index".to_string(),
                reason: format!(".git/index is {}KB (possibly crafted)", meta.len() / 1024),
                reference: String::new(),
            });
        }
    }

    // alternates file
    let alternates = objects_dir.join("info").join("alternates");
    if let Ok(content) = fs::read_to_string(&alternates) {
        for line in content.lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                findings.push(Finding {
                    severity: Severity::Critical,
                    name: "alternates".to_string(),
                    reason: format!("alternates points to external path: {}", line),
                    reference: String::new(),
                });
            }
        }
    }

    // http-alternates file
    let http_alt = objects_dir.join("info").join("http-alternates");
    if let Ok(content) = fs::read_to_string(&http_alt) {
        for line in content.lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                findings.push(Finding {
                    severity: Severity::Critical,
                    name: "http-alternates".to_string(),
                    reason: format!("http-alternates references remote: {}", line),
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

    fn has_finding(findings: &[Finding], needle: &str) -> bool {
        findings.iter().any(|f| f.name.contains(needle) || f.reason.contains(needle))
    }

    // ── oversized loose objects ─────────────────────────────────────────

    #[test]
    fn detects_oversized_loose_object() {
        let findings = check_objects(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "oversized") || has_finding(&findings, "large"),
            "should detect oversized loose object in objects/de/"
        );
    }

    #[test]
    fn oversized_object_severity_at_least_medium() {
        let findings = check_objects(&fixture_git_dir()).unwrap();
        let f = findings.iter().find(|f| f.name.contains("oversized") || f.name.contains("large"));
        assert!(f.is_some(), "oversized object finding missing");
        assert!(f.unwrap().severity >= Severity::Medium);
    }

    // ── oversized pack files ────────────────────────────────────────────

    #[test]
    fn detects_oversized_pack_file() {
        let findings = check_objects(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "pack"),
            "should detect oversized pack file"
        );
    }

    // ── crafted / oversized index ───────────────────────────────────────

    #[test]
    fn detects_crafted_index() {
        let findings = check_objects(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "index"),
            "should detect crafted/oversized .git/index file"
        );
    }

    // ── alternates pointing to external path ────────────────────────────

    #[test]
    fn detects_alternates_file() {
        let findings = check_objects(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "alternates"),
            "should detect .git/objects/info/alternates pointing to external path"
        );
    }

    #[test]
    fn alternates_severity_is_critical() {
        let findings = check_objects(&fixture_git_dir()).unwrap();
        let f = findings.iter().find(|f| f.name.contains("alternates") && !f.name.contains("http"));
        assert!(f.is_some(), "alternates finding missing");
        assert_eq!(f.unwrap().severity, Severity::Critical);
    }

    // ── http-alternates ─────────────────────────────────────────────────

    #[test]
    fn detects_http_alternates() {
        let findings = check_objects(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "http-alternates") || has_finding(&findings, "http_alternates"),
            "should detect .git/objects/info/http-alternates"
        );
    }
}
