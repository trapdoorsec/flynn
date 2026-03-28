use crate::arguments::Severity;
use crate::finding::Finding;
use serde::Serialize;
use std::fs;
use std::path::Path;

#[derive(Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: &'static str,
    version: &'static str,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
struct SarifRule {
    id: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: SarifMessage,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

fn sarif_level(sev: &Severity) -> &'static str {
    match sev {
        Severity::Info => "note",
        Severity::Medium => "warning",
        Severity::High => "error",
        Severity::Critical => "error",
    }
}

pub fn write_sarif(findings: &[Finding], output: &Path) -> anyhow::Result<()> {
    let mut rules: Vec<SarifRule> = Vec::new();
    let mut seen_rules: Vec<String> = Vec::new();

    let results: Vec<SarifResult> = findings
        .iter()
        .map(|f| {
            if !seen_rules.contains(&f.name) {
                seen_rules.push(f.name.clone());
                rules.push(SarifRule {
                    id: f.name.clone(),
                    short_description: SarifMessage {
                        text: f.name.clone(),
                    },
                });
            }
            SarifResult {
                rule_id: f.name.clone(),
                level: sarif_level(&f.severity),
                message: SarifMessage {
                    text: f.reason.clone(),
                },
            }
        })
        .collect();

    let log = SarifLog {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "flynn",
                    version: env!("CARGO_PKG_VERSION"),
                    information_uri: "https://github.com/trapdoorsec/flynn",
                    rules,
                },
            },
            results,
        }],
    };

    let json = serde_json::to_string_pretty(&log)?;
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
        write_sarif(findings, tmp.path()).unwrap();
        let contents = std::fs::read_to_string(tmp.path()).unwrap();
        serde_json::from_str(&contents).expect("output should be valid JSON")
    }

    fn get_run(val: &Value) -> &Value {
        &val["runs"][0]
    }

    fn get_driver(val: &Value) -> &Value {
        &get_run(val)["tool"]["driver"]
    }

    #[test]
    fn top_level_schema_and_version() {
        let val = write_and_parse(&[]);
        assert_eq!(val["version"], "2.1.0");
        assert!(
            val["$schema"]
                .as_str()
                .unwrap()
                .contains("sarif-schema-2.1.0"),
            "$schema should reference SARIF 2.1.0"
        );
    }

    #[test]
    fn single_run_present() {
        let val = write_and_parse(&[]);
        let runs = val["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1);
    }

    #[test]
    fn tool_driver_metadata() {
        let val = write_and_parse(&[]);
        let driver = get_driver(&val);
        assert_eq!(driver["name"], "flynn");
        assert_eq!(driver["version"], env!("CARGO_PKG_VERSION"));
        assert!(
            driver["informationUri"]
                .as_str()
                .unwrap()
                .starts_with("https://"),
            "informationUri should be a URL"
        );
    }

    #[test]
    fn empty_findings_produces_empty_results_and_rules() {
        let val = write_and_parse(&[]);
        let run = get_run(&val);
        assert_eq!(run["results"].as_array().unwrap().len(), 0);
        assert_eq!(get_driver(&val)["rules"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn single_finding_produces_matching_result_and_rule() {
        let val = write_and_parse(&[make_finding(Severity::High, "check-a", "bad thing")]);
        let run = get_run(&val);

        let results = run["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["ruleId"], "check-a");
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[0]["message"]["text"], "bad thing");

        let rules = get_driver(&val)["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["id"], "check-a");
        assert_eq!(rules[0]["shortDescription"]["text"], "check-a");
    }

    #[test]
    fn severity_maps_to_correct_sarif_level() {
        let findings = vec![
            make_finding(Severity::Info, "a", ""),
            make_finding(Severity::Medium, "b", ""),
            make_finding(Severity::High, "c", ""),
            make_finding(Severity::Critical, "d", ""),
        ];
        let val = write_and_parse(&findings);
        let results = get_run(&val)["results"].as_array().unwrap();
        assert_eq!(results[0]["level"], "note");
        assert_eq!(results[1]["level"], "warning");
        assert_eq!(results[2]["level"], "error");
        assert_eq!(results[3]["level"], "error");
    }

    #[test]
    fn duplicate_check_names_produce_single_rule() {
        let findings = vec![
            make_finding(Severity::High, "same-check", "first instance"),
            make_finding(Severity::High, "same-check", "second instance"),
            make_finding(Severity::Medium, "same-check", "third instance"),
        ];
        let val = write_and_parse(&findings);

        let rules = get_driver(&val)["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1, "duplicate check names should deduplicate into one rule");
        assert_eq!(rules[0]["id"], "same-check");

        let results = get_run(&val)["results"].as_array().unwrap();
        assert_eq!(results.len(), 3, "all findings should still appear as results");
        for r in results {
            assert_eq!(r["ruleId"], "same-check");
        }
    }

    #[test]
    fn multiple_distinct_checks_produce_multiple_rules() {
        let findings = vec![
            make_finding(Severity::Info, "check-a", "reason a"),
            make_finding(Severity::High, "check-b", "reason b"),
            make_finding(Severity::Critical, "check-c", "reason c"),
        ];
        let val = write_and_parse(&findings);
        let rules = get_driver(&val)["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 3);

        let rule_ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert!(rule_ids.contains(&"check-a"));
        assert!(rule_ids.contains(&"check-b"));
        assert!(rule_ids.contains(&"check-c"));
    }

    #[test]
    fn every_result_rule_id_has_matching_rule() {
        let findings = vec![
            make_finding(Severity::Info, "alpha", "a"),
            make_finding(Severity::High, "beta", "b"),
            make_finding(Severity::High, "alpha", "a2"),
            make_finding(Severity::Critical, "gamma", "c"),
        ];
        let val = write_and_parse(&findings);
        let rules = get_driver(&val)["rules"].as_array().unwrap();
        let rule_ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();

        let results = get_run(&val)["results"].as_array().unwrap();
        for result in results {
            let rid = result["ruleId"].as_str().unwrap();
            assert!(
                rule_ids.contains(&rid),
                "result ruleId '{rid}' has no matching rule definition"
            );
        }
    }

    #[test]
    fn special_characters_produce_valid_sarif() {
        let findings = vec![
            make_finding(Severity::High, "check\"quotes", "reason with \"quotes\""),
            make_finding(Severity::Medium, "check\\slash", "back\\slash"),
            make_finding(Severity::Info, "check\nnewline", "line1\nline2"),
        ];
        let val = write_and_parse(&findings);
        let results = get_run(&val)["results"].as_array().unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0]["message"]["text"], "reason with \"quotes\"");
    }

    #[test]
    fn unicode_produces_valid_sarif() {
        let findings = vec![make_finding(
            Severity::High,
            "\u{200b}zero-width",
            "\u{0430}\u{0435} homoglyph \u{1f4a5}",
        )];
        let val = write_and_parse(&findings);
        let results = get_run(&val)["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0]["message"]["text"].as_str().unwrap().contains("homoglyph"));
    }

    #[test]
    fn long_strings_produce_valid_sarif() {
        let findings = vec![make_finding(
            Severity::Critical,
            &"x".repeat(10_000),
            &"y".repeat(50_000),
        )];
        let val = write_and_parse(&findings);
        let results = get_run(&val)["results"].as_array().unwrap();
        assert_eq!(results[0]["message"]["text"].as_str().unwrap().len(), 50_000);
    }

    #[test]
    fn many_findings_produce_valid_sarif() {
        let findings: Vec<Finding> = (0..500)
            .map(|i| make_finding(Severity::Info, &format!("check-{i}"), &format!("reason-{i}")))
            .collect();
        let val = write_and_parse(&findings);
        let results = get_run(&val)["results"].as_array().unwrap();
        assert_eq!(results.len(), 500);
        let rules = get_driver(&val)["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 500);
    }
}
