use crate::arguments::Severity;

pub struct Finding {
    pub severity: Severity,
    pub name: String,
    pub reason: String,
}
