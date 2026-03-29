use std::fs;
use std::path::Path;

use walkdir::WalkDir;

use crate::arguments::Severity;
use crate::finding::Finding;

pub fn check_buried_bare_repo(git_dir: &Path) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let repo_root = git_dir.parent().unwrap_or(git_dir);

    // Walk repo for buried bare repos and gitdir file redirects
    for entry in WalkDir::new(repo_root)
        .min_depth(1)
        .into_iter()
        .filter_entry(|e| !(e.file_type().is_dir() && e.file_name() == ".git"))
    {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        // Buried bare repo: directory with HEAD + objects + refs
        if entry.file_type().is_dir() {
            let dir = entry.path();
            if dir.join("HEAD").exists() && dir.join("objects").is_dir() && dir.join("refs").is_dir() {
                let rel = dir.strip_prefix(repo_root).unwrap_or(dir);
                findings.push(Finding {
                    severity: Severity::Critical,
                    name: "buried bare repo".to_string(),
                    reason: format!("bare repository found at {}", rel.display()),
                });

                // Check for worktree jailbreak in buried repo config
                if let Ok(config) = fs::read_to_string(dir.join("config")) {
                    for line in config.lines() {
                        let t = line.trim().to_lowercase();
                        if t.starts_with("worktree") && t.contains('=') {
                            let val = t.split('=').nth(1).unwrap_or("").trim().to_string();
                            findings.push(Finding {
                                severity: Severity::Critical,
                                name: "worktree jailbreak".to_string(),
                                reason: format!("buried repo has core.worktree = {} (potential jailbreak)", val),
                            });
                        }
                    }
                }
            }
        }

        // .git file (gitdir redirect)
        if entry.file_type().is_file() && entry.file_name() == ".git" {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                let content = content.trim();
                if content.starts_with("gitdir:") {
                    let target = content.strip_prefix("gitdir:").unwrap().trim();
                    findings.push(Finding {
                        severity: Severity::Critical,
                        name: "gitdir redirect".to_string(),
                        reason: format!("gitdir: redirect pointing to {}", target),
                    });
                }
            }
        }
    }

    // Check main config for core.worktree and duplicate [core] sections
    let config_path = git_dir.join("config");
    if let Ok(bytes) = fs::read(&config_path) {
        let content = String::from_utf8_lossy(&bytes);
        let mut in_core = false;
        let mut core_count = 0;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                let lower = trimmed.to_lowercase();
                if lower.starts_with("[core]") {
                    core_count += 1;
                    in_core = true;
                } else {
                    in_core = false;
                }
                continue;
            }

            if in_core {
                if let Some(eq) = trimmed.find('=') {
                    let key = trimmed[..eq].trim().to_lowercase();
                    let value = trimmed[eq + 1..].trim();
                    if key == "worktree" && (value.starts_with('/') || value.contains("..")) {
                        findings.push(Finding {
                            severity: Severity::Critical,
                            name: "external worktree".to_string(),
                            reason: format!("core.worktree points outside repo: {}", value),
                        });
                    }
                }
            }
        }

        if core_count > 1 {
            findings.push(Finding {
                severity: Severity::High,
                name: "duplicate [core] sections".to_string(),
                reason: format!("config has multiple [core] sections ({})", core_count),
            });
        }
    }

    // Check for symlinks and unexpected subdirectories in .git/
    let expected_dirs = [
        "branches", "hooks", "info", "logs", "modules", "objects",
        "refs", "worktrees", "rr-cache", "lfs",
    ];

    for entry in fs::read_dir(git_dir)? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let meta = match fs::symlink_metadata(entry.path()) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if meta.file_type().is_symlink() {
            let target = fs::read_link(entry.path()).unwrap_or_default();
            findings.push(Finding {
                severity: Severity::High,
                name: "symlink in .git".to_string(),
                reason: format!("symlink {} -> {}", entry.file_name().to_string_lossy(), target.display()),
            });
        }

        if meta.file_type().is_dir() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !expected_dirs.contains(&name.as_str()) {
                findings.push(Finding {
                    severity: Severity::Medium,
                    name: "unexpected .git subdirectory".to_string(),
                    reason: format!("unexpected directory in .git/: {}", name),
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
    use crate::checks::test_fixture::{fixture_git_dir, fixture_repo_dir};

    fn has_finding(findings: &[Finding], name_contains: &str) -> bool {
        findings.iter().any(|f| f.name.contains(name_contains))
    }

    // ── buried bare repo ────────────────────────────────────────────────

    #[test]
    fn detects_buried_bare_repo() {
        let findings = check_buried_bare_repo(&fixture_git_dir()).unwrap();
        assert!(
            findings.iter().any(|f| f.name.contains("buried") || f.name.contains("bare")),
            "should detect buried bare repo at vendor/innocent-lib/"
        );
    }

    #[test]
    fn buried_bare_repo_severity_is_critical() {
        let findings = check_buried_bare_repo(&fixture_git_dir()).unwrap();
        let f = findings.iter().find(|f| f.name.contains("buried") || f.name.contains("bare"));
        assert!(f.is_some(), "buried bare repo finding missing");
        assert_eq!(f.unwrap().severity, Severity::Critical);
    }

    // ── core.bare=false + core.worktree jailbreak ───────────────────────

    #[test]
    fn detects_bare_worktree_jailbreak() {
        let findings = check_buried_bare_repo(&fixture_git_dir()).unwrap();
        assert!(
            findings.iter().any(|f| f.reason.contains("worktree") || f.name.contains("jailbreak")),
            "should detect core.bare=false + core.worktree jailbreak pattern"
        );
    }

    // ── .git file redirect ──────────────────────────────────────────────

    #[test]
    fn detects_gitdir_file_redirect() {
        let findings = check_buried_bare_repo(&fixture_git_dir()).unwrap();
        assert!(
            findings.iter().any(|f| f.name.contains("gitdir") || f.reason.contains("gitdir")),
            "should detect .git file containing gitdir: redirect (subproject/.git)"
        );
    }

    #[test]
    fn detects_gitdir_pointing_outside_repo() {
        let findings = check_buried_bare_repo(&fixture_git_dir()).unwrap();
        assert!(
            findings.iter().any(|f| f.reason.contains("/tmp") || f.reason.contains("outside")),
            "should flag gitdir: pointing to absolute/external path"
        );
    }

    // ── core.worktree pointing outside repo ─────────────────────────────

    #[test]
    fn detects_worktree_outside_repo() {
        let findings = check_buried_bare_repo(&fixture_git_dir()).unwrap();
        assert!(
            findings.iter().any(|f| f.reason.contains("worktree") && (f.reason.contains("/tmp") || f.reason.contains("outside"))),
            "should detect core.worktree pointing outside the repo root"
        );
    }

    // ── symlinks within .git/ pointing outside ──────────────────────────

    #[test]
    fn detects_symlinks_in_git_dir() {
        let findings = check_buried_bare_repo(&fixture_git_dir()).unwrap();
        assert!(
            findings.iter().any(|f| f.name.contains("symlink") || f.reason.contains("symlink")),
            "should detect symlinks within .git/ pointing outside the repo"
        );
    }

    // ── unexpected subdirectories ───────────────────────────────────────

    #[test]
    fn detects_unexpected_subdirectory() {
        let findings = check_buried_bare_repo(&fixture_git_dir()).unwrap();
        assert!(
            findings.iter().any(|f| f.reason.contains("payload-staging") || f.name.contains("unexpected")),
            "should detect unexpected subdirectory inside .git/ (payload-staging/)"
        );
    }

    // ── multiple [core] sections ────────────────────────────────────────

    #[test]
    fn detects_duplicate_core_sections() {
        let findings = check_buried_bare_repo(&fixture_git_dir()).unwrap();
        assert!(
            findings.iter().any(|f| f.reason.contains("multiple") || f.reason.contains("duplicate") || f.name.contains("[core]")),
            "should detect multiple [core] sections in config"
        );
    }
}
