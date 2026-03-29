use std::fs;
use std::path::Path;

use walkdir::WalkDir;

use crate::arguments::Severity;
use crate::finding::Finding;

pub fn check_refs(git_dir: &Path) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // Check HEAD
    let head_path = git_dir.join("HEAD");
    if let Ok(content) = fs::read_to_string(&head_path) {
        let content = content.trim();
        if !content.starts_with("ref:") {
            findings.push(Finding {
                severity: Severity::Medium,
                name: "detached HEAD".to_string(),
                reason: format!("HEAD contains raw SHA instead of symbolic ref: {}", content),
                reference: String::new(),
            });
        }
    }

    // Walk refs/ for path traversal and orphan refs
    let refs_dir = git_dir.join("refs");
    if refs_dir.is_dir() {
        for entry in WalkDir::new(&refs_dir).into_iter().flatten() {
            if !entry.file_type().is_file() {
                continue;
            }

            let rel_path = entry.path().strip_prefix(git_dir).unwrap_or(entry.path());
            let path_str = rel_path.to_string_lossy();

            if path_str.contains("..") || path_str.contains("%2f") || path_str.contains("%2F") {
                findings.push(Finding {
                    severity: Severity::Critical,
                    name: "path traversal ref".to_string(),
                    reason: format!("ref with path traversal: {}", path_str),
                    reference: String::new(),
                });
            }

            if let Ok(content) = fs::read_to_string(entry.path()) {
                let sha = content.trim();
                if sha == "0000000000000000000000000000000000000000" {
                    findings.push(Finding {
                        severity: Severity::Medium,
                        name: "orphan ref".to_string(),
                        reason: format!("ref {} points to all-zeros (0000000...)", path_str),
                        reference: String::new(),
                    });
                }
            }
        }
    }

    // Check packed-refs for suspicious entries
    let packed_refs = git_dir.join("packed-refs");
    if let Ok(content) = fs::read_to_string(&packed_refs) {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() || line.starts_with('^') {
                continue;
            }
            if let Some(ref_name) = line.split_whitespace().nth(1) {
                if ref_name.contains("..") {
                    findings.push(Finding {
                        severity: Severity::Critical,
                        name: "suspicious packed-refs".to_string(),
                        reason: format!("packed-refs entry with path traversal: {}", ref_name),
                        reference: String::new(),
                    });
                }
            }
        }
    }

    // Leftover state files
    for state_file in &["FETCH_HEAD", "MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "ORIG_HEAD"] {
        if git_dir.join(state_file).exists() {
            findings.push(Finding {
                severity: Severity::Info,
                name: state_file.to_string(),
                reason: format!("{} present (interrupted operation or leftover state)", state_file),
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

    // ── detached HEAD (raw SHA) ─────────────────────────────────────────

    #[test]
    fn detects_detached_head() {
        let findings = check_refs(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "HEAD") || has_finding(&findings, "detached"),
            "should detect HEAD containing a raw SHA instead of symbolic ref"
        );
    }

    // ── HEAD pointing to non-existent ref ───────────────────────────────

    #[test]
    fn detects_head_pointing_to_nonexistent_ref() {
        let findings = check_refs(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "non-existent") || has_finding(&findings, "invalid") || has_finding(&findings, "HEAD"),
            "should detect HEAD pointing to a non-existent ref/object"
        );
    }

    // ── path-traversal ref names ────────────────────────────────────────

    #[test]
    fn detects_path_traversal_ref() {
        let findings = check_refs(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "traversal") || has_finding(&findings, ".."),
            "should detect ref names with path-traversal characters"
        );
    }

    // ── ref pointing to non-existent object ─────────────────────────────

    #[test]
    fn detects_orphan_ref() {
        let findings = check_refs(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "orphan") || has_finding(&findings, "0000000"),
            "should detect ref pointing to all-zeros / non-existent object"
        );
    }

    // ── packed-refs with suspicious names ────────────────────────────────

    #[test]
    fn detects_suspicious_packed_refs() {
        let findings = check_refs(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "packed-refs") || has_finding(&findings, "packed"),
            "should detect suspicious entries in packed-refs"
        );
    }

    // ── leftover state files ────────────────────────────────────────────

    #[test]
    fn detects_fetch_head() {
        let findings = check_refs(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "FETCH_HEAD"),
            "should detect unexpected FETCH_HEAD"
        );
    }

    #[test]
    fn detects_merge_head() {
        let findings = check_refs(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "MERGE_HEAD"),
            "should detect unexpected MERGE_HEAD"
        );
    }

    #[test]
    fn detects_cherry_pick_head() {
        let findings = check_refs(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "CHERRY_PICK_HEAD"),
            "should detect unexpected CHERRY_PICK_HEAD"
        );
    }

    #[test]
    fn detects_revert_head() {
        let findings = check_refs(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "REVERT_HEAD"),
            "should detect unexpected REVERT_HEAD"
        );
    }

    #[test]
    fn detects_orig_head() {
        let findings = check_refs(&fixture_git_dir()).unwrap();
        assert!(
            has_finding(&findings, "ORIG_HEAD"),
            "should detect unexpected ORIG_HEAD"
        );
    }
}
