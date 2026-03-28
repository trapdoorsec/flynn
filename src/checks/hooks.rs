use std::path::Path;

use crate::finding::Finding;

pub fn check_executable_hooks(git_dir: &Path) -> anyhow::Result<Vec<Finding>> {
    Ok(vec![])
}
