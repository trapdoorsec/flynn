use std::path::PathBuf;
use std::sync::Once;

static INIT: Once = Once::new();

/// Returns the path to the malicious fixture's .git directory.
/// Runs the setup script on first call. Panics if the fixture can't be built.
pub fn fixture_git_dir() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture_repo = manifest.join("test/fixtures/malicious_repo");
    let setup_script = manifest.join("test/setup_fixture.sh");

    INIT.call_once(|| {
        let status = std::process::Command::new("bash")
            .arg(&setup_script)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("failed to run setup_fixture.sh");
        assert!(status.success(), "setup_fixture.sh failed");
    });

    let git_dir = fixture_repo.join(".git");
    assert!(git_dir.exists(), "fixture .git dir missing: {}", git_dir.display());
    git_dir
}

/// Returns the path to the malicious fixture repo root (parent of .git).
pub fn fixture_repo_dir() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("test/fixtures/malicious_repo")
}
