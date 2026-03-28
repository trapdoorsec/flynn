use std::path::Path;

use crate::finding::Finding;

//check for 'buried bare repo', .git file redirects, hooks
pub fn check_buried_bare_repo(git_dir: &Path) -> anyhow::Result<Vec<Finding>> {
    Ok(vec![])
}
