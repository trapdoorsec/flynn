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
