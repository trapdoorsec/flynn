///
/// This is flynn
/// A tool to check for signs of a weaponized .git folders in a git repository
///
/// basic usage:
/// ```bash
/// $ flynn /path/to/repo
/// ```
///
/// report as json
/// ```bash
/// $ flynn --output=json /path/to/repo
/// ```
///
/// report as SARIF (for github action integration)
/// ```
/// $ flynn --output=sarif /path/to/repo
/// ```
mod checks;
mod output;

mod arguments;
mod finding;
mod scanner;
use std::path::PathBuf;

use anyhow::Context;
use arguments::Args;
use clap::Parser;
use owo_colors::OwoColorize;

use crate::scanner::scan;
const BANNER: &str = r#"


    ▐▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▌
    ▐                                                                                 ▌
    ▐                                                                                 ▌
    ▐                                                                                 ▌
    ▐                                                                                 ▌
    ▐  ________/\\\\\__/\\\\\\______________________________________________          ▌
    ▐   ______/\\\///__\////\\\______________________________________________         ▌
    ▐    _____/\\\_________\/\\\_______/\\\__/\\\_____________________________        ▌
    ▐     __/\\\\\\\\\______\/\\\______\//\\\/\\\___/\\/\\\\\\____/\\/\\\\\\___       ▌
    ▐      _\////\\\//_______\/\\\_______\//\\\\\___\/\\\////\\\__\/\\\////\\\__      ▌
    ▐       ____\/\\\_________\/\\\________\//\\\____\/\\\__\//\\\_\/\\\__\//\\\_     ▌
    ▐        ____\/\\\_________\/\\\_____/\\_/\\\_____\/\\\___\/\\\_\/\\\___\/\\\_    ▌
    ▐         ____\/\\\_______/\\\\\\\\\_\//\\\\/______\/\\\___\/\\\_\/\\\___\/\\\_   ▌
    ▐          ____\///_______\/////////___\////________\///____\///__\///____\///__  ▌
    ▐                                                                                 ▌
    ▐                         a malicious .git folder scanner                         ▌
    ▐                           <3 with love from akses Ɛ>                            ▌
    ▐                                                                                 ▌
    ▐▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▌


"#;

fn resolve_git_dir(path: &PathBuf) -> anyhow::Result<PathBuf> {
    if !path.exists() {
        anyhow::bail!(
            "git repo path does not exist. Make sure you point to the repository root for best results. {}",
            path.display()
        );
    }

    if !path.is_dir() {
        anyhow::bail!(
            "git repo path is not a directory. Make sure you point to the repository root for best results. {}",
            path.display()
        );
    }

    if path.ends_with(".git") {
        Ok(path.clone())
    } else {
        let git_dir = path.join(".git");
        if git_dir.exists() && git_dir.is_dir() {
            Ok(git_dir)
        } else {
            anyhow::bail!("no .git directory found in: {}", path.display());
        }
    }
}

fn resolve_output_file(output: &PathBuf) -> anyhow::Result<PathBuf> {
    let parent = output
        .parent()
        .context("output path has no parent directory")?;
    let filename = output.file_name().context("no filename for output")?;
    let filename_str = filename.to_string_lossy();

    if parent != std::path::Path::new("") && !parent.exists() {
        anyhow::bail!("output directory does not exist: {}", parent.display());
    }

    if filename_str.starts_with('.') && filename_str.chars().all(|c| c == '.') {
        anyhow::bail!("output filename is not valid: {}", filename_str);
    }

    Ok(output.to_path_buf())
}

fn safeprint(quiet: bool, string: &str) {
    if !quiet {
        println!("{}", string)
    }
}

fn run() -> anyhow::Result<()> {
    let args = Args::parse();
    let banner = format!("{}", BANNER.cyan());
    safeprint(args.quiet, banner.as_str());

    let git_dir = resolve_git_dir(&args.path)?;
    let output_file = resolve_output_file(&args.output)?;

    let fail_on_str = match &args.fail_on {
        Some(s) => format!("{:?}", s),
        None => "—".to_string(),
    };
    let mut config_table = comfy_table::Table::new();
    config_table
        .load_preset(comfy_table::presets::UTF8_FULL)
        .set_content_arrangement(comfy_table::ContentArrangement::Dynamic)
        .set_header(vec!["Option", "Value"])
        .add_row(vec!["target", &git_dir.display().to_string()])
        .add_row(vec!["format", &format!("{:?}", args.format)])
        .add_row(vec!["min severity", &format!("{:?}", args.min_severity)])
        .add_row(vec!["fail on", &fail_on_str])
        .add_row(vec!["output", &output_file.display().to_string()]);
    safeprint(args.quiet, &config_table.to_string());

    let report = scan(
        &git_dir,
        &output_file,
        args.min_severity,
        args.fail_on,
        args.format,
        args.quiet,
    )?;
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{}: {}", "error".red(), e);

        for cause in e.chain().skip(1) {
            eprintln!("\tcaused by: {}", cause)
        }

        std::process::exit(1);
    }
}
