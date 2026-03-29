use crate::arguments::Severity;
use serde::Serialize;

#[derive(Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub name: String,
    pub reason: String,
    pub reference: String,
}
