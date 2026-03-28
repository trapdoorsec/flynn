use crate::finding::Finding;
use std::fs;
use std::path::Path;

pub fn write_json(findings: &[Finding], output: &Path) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(findings)?;
    fs::write(output, json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arguments::Severity;
    use crate::finding::Finding;
    use serde_json::Value;
    use tempfile::NamedTempFile;

    fn make_finding(severity: Severity, name: &str, reason: &str) -> Finding {
        Finding {
            severity,
            name: name.to_string(),
            reason: reason.to_string(),
        }
    }

    fn write_and_parse(findings: &[Finding]) -> Value {
        let tmp = NamedTempFile::new().unwrap();
        write_json(findings, tmp.path()).unwrap();
        let contents = std::fs::read_to_string(tmp.path()).unwrap();
        serde_json::from_str(&contents).expect("output should be valid JSON")
    }

    #[test]
    fn empty_findings_produces_empty_array() {
        let val = write_and_parse(&[]);
        assert_eq!(val, Value::Array(vec![]));
    }

    #[test]
    fn single_finding_has_all_fields() {
        let val = write_and_parse(&[make_finding(Severity::High, "check-a", "something bad")]);
        let arr = val.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        let obj = arr[0].as_object().unwrap();
        assert_eq!(obj["severity"], "High");
        assert_eq!(obj["name"], "check-a");
        assert_eq!(obj["reason"], "something bad");
    }

    #[test]
    fn all_severity_levels_serialize() {
        let findings = vec![
            make_finding(Severity::Info, "a", "info"),
            make_finding(Severity::Medium, "b", "medium"),
            make_finding(Severity::High, "c", "high"),
            make_finding(Severity::Critical, "d", "critical"),
        ];
        let val = write_and_parse(&findings);
        let arr = val.as_array().unwrap();
        assert_eq!(arr[0]["severity"], "Info");
        assert_eq!(arr[1]["severity"], "Medium");
        assert_eq!(arr[2]["severity"], "High");
        assert_eq!(arr[3]["severity"], "Critical");
    }

    #[test]
    fn special_characters_produce_valid_json() {
        let findings = vec![
            make_finding(Severity::High, "check\"quotes", "reason with \"double quotes\""),
            make_finding(Severity::Medium, "check\\backslash", "path: ..\\..\\etc"),
            make_finding(Severity::Info, "check\nnewline", "line1\nline2\ttab"),
            make_finding(Severity::Critical, "check/slash", "a/b/c"),
        ];
        let val = write_and_parse(&findings);
        let arr = val.as_array().unwrap();
        assert_eq!(arr.len(), 4);
        assert_eq!(arr[0]["name"], "check\"quotes");
        assert_eq!(arr[1]["name"], "check\\backslash");
        assert_eq!(arr[2]["reason"], "line1\nline2\ttab");
    }

    #[test]
    fn unicode_produces_valid_json() {
        let findings = vec![
            make_finding(Severity::High, "\u{200b}zero-width", "homoglyph: \u{0430}\u{0435}"),
            make_finding(Severity::Medium, "emoji-check", "\u{1f4a5} boom"),
            make_finding(Severity::Info, "cjk", "\u{4e2d}\u{6587}\u{8def}\u{5f84}"),
        ];
        let val = write_and_parse(&findings);
        let arr = val.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert!(arr[0]["name"].as_str().unwrap().contains("zero-width"));
    }

    #[test]
    fn long_strings_produce_valid_json() {
        let findings = vec![make_finding(
            Severity::Critical,
            &"x".repeat(10_000),
            &"y".repeat(50_000),
        )];
        let val = write_and_parse(&findings);
        let arr = val.as_array().unwrap();
        assert_eq!(arr[0]["name"].as_str().unwrap().len(), 10_000);
        assert_eq!(arr[0]["reason"].as_str().unwrap().len(), 50_000);
    }

    #[test]
    fn many_findings_produce_valid_json() {
        let findings: Vec<Finding> = (0..1000)
            .map(|i| make_finding(Severity::Info, &format!("check-{i}"), &format!("reason-{i}")))
            .collect();
        let val = write_and_parse(&findings);
        let arr = val.as_array().unwrap();
        assert_eq!(arr.len(), 1000);
    }

    #[test]
    fn no_extra_fields_in_output() {
        let val = write_and_parse(&[make_finding(Severity::Info, "a", "b")]);
        let obj = val.as_array().unwrap()[0].as_object().unwrap();
        assert_eq!(obj.len(), 3, "finding should have exactly 3 fields: {:?}", obj.keys().collect::<Vec<_>>());
    }
}
