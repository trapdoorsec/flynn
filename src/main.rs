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

mod finding;
mod scanner;
mod arguments;
use clap::Parser
fn main() {
 
}
