use std::path::Path;

use crate::finding::Finding;

// all config key checks (fsmonitor, sshCommand, etc)
pub fn check_fsmonitor(git_dir: &Path) -> anyhow::Result<Vec<Finding>> {
    Ok(vec![])
}

pub fn check_ssh_command(git_dir: &Path) -> anyhow::Result<Vec<Finding>> {
    Ok(vec![])
}
