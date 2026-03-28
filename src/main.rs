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
use arguments::Args;
use clap::Parser;

fn banner() -> String {
    "this is a banner".to_string()
}

fn main() {
    let args = Args::parse();
    println!("{}", banner());
    println!("{:?}", args)
}
