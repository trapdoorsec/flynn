use clap::{Parser, ValueEnum};
use std::path::PathBuf;

/// arguments.rs
/// here we are defining what command line arguments are needed for the app to run
///
#[derive(Parser, Debug)]
#[command(
    name = "flynn",
    version,
    about = "Scan .git directories for malicious content"
)]
pub struct Args {
    #[arg(value_name = "PATH")]
    pub path: PathBuf,

    #[arg(short, long, value_name = "FORMAT", default_value = "text")]
    pub format: OutputFormat,

    #[arg(short, long, value_name = "LEVEL", default_value = "info")]
    pub min_severity: Severity,

    #[arg(long, value_name = "LEVEL")]
    pub fail_on: Option<Severity>,

    #[arg(short, long, value_name = "FILE", default_value = "flynn_output.txt")]
    pub output: PathBuf,

    #[arg(short, long, default_value_t = false)]
    pub quiet: bool,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum, serde::Serialize)]
pub enum Severity {
    Info,
    Medium,
    High,
    Critical,
}
