use std::collections::HashMap;
use std::path::{Path, PathBuf};

use netagent_models::Finding;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::analyzers::dns::{detect_nxdomain_enumeration, detect_nxdomain_spike};
use crate::storage::sqlite::SqliteStore;

/// A declarative analyzer rule manifest loaded from `rules/builtin/*.yaml`.
/// New detection rules can be shipped without touching Core code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleManifest {
    pub id: String,
    pub name: String,
    pub description: String,
    #[serde(default = "default_category")]
    pub category: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    /// Analyzer implementation key, e.g. `dns_nxdomain_spike`.
    pub analyzer: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub params: HashMap<String, Value>,
    #[serde(default)]
    pub recommended_actions: Vec<String>,
}

fn default_category() -> String {
    String::from("network_anomaly")
}

fn default_severity() -> String {
    String::from("medium")
}

fn default_enabled() -> bool {
    true
}

impl RuleManifest {
    pub fn param_f64(&self, key: &str) -> Option<f64> {
        self.params.get(key).and_then(Value::as_f64)
    }

    pub fn param_u64(&self, key: &str) -> Option<u64> {
        self.params.get(key).and_then(Value::as_u64)
    }

    pub fn param_usize(&self, key: &str) -> Option<usize> {
        self.param_u64(key).map(|value| value as usize)
    }
}

/// Load every `*.yaml` manifest under `rules/builtin` in the workspace.
pub fn load_rule_manifests() -> Result<Vec<RuleManifest>, String> {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.push("../../rules/builtin");
    load_rule_manifests_from(&dir)
}

pub fn load_rule_manifests_from(dir: &Path) -> Result<Vec<RuleManifest>, String> {
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut manifests = Vec::new();
    for entry in std::fs::read_dir(dir)
        .map_err(|error| format!("failed to read rules dir {}: {error}", dir.display()))?
    {
        let entry = entry.map_err(|error| format!("failed to read rules entry: {error}"))?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("yaml") {
            continue;
        }
        let contents = std::fs::read_to_string(&path)
            .map_err(|error| format!("failed to read rule {}: {error}", path.display()))?;
        let manifest: RuleManifest = serde_yaml::from_str(&contents)
            .map_err(|error| format!("failed to parse rule {}: {error}", path.display()))?;
        manifests.push(manifest);
    }
    manifests.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(manifests)
}

/// Run every enabled manifest rule and return the created findings.
pub fn run_all_rules(
    manifests: &[RuleManifest],
    store: &SqliteStore,
    finding_counter: &mut u64,
) -> Result<Vec<Finding>, String> {
    let mut findings = Vec::new();
    for manifest in manifests {
        if !manifest.enabled {
            continue;
        }
        let mut produced = run_rule(manifest, store, finding_counter)?;
        findings.append(&mut produced);
    }
    Ok(findings)
}

/// Dispatch a single manifest rule to its analyzer implementation.
pub fn run_rule(
    manifest: &RuleManifest,
    store: &SqliteStore,
    finding_counter: &mut u64,
) -> Result<Vec<Finding>, String> {
    let mut findings = match manifest.analyzer.as_str() {
        "dns_nxdomain_spike" => detect_nxdomain_spike(
            store,
            finding_counter,
            manifest
                .param_f64("threshold_ratio")
                .unwrap_or(0.3)
                .clamp(0.0, 1.0),
            manifest.param_usize("min_queries").unwrap_or(5),
        )?,
        "dns_nxdomain_enumeration" => detect_nxdomain_enumeration(
            store,
            finding_counter,
            manifest.param_usize("min_nxdomains").unwrap_or(5),
        )?,
        other => {
            return Err(format!(
                "rule {} declares unknown analyzer: {other}",
                manifest.id
            ))
        }
    };

    for finding in &mut findings {
        if finding.metadata.is_null() {
            finding.metadata = Value::Object(Default::default());
        }
        if let Some(metadata) = finding.metadata.as_object_mut() {
            metadata.insert(
                "rule_id".to_string(),
                Value::String(manifest.id.clone()),
            );
            metadata.insert(
                "rule_name".to_string(),
                Value::String(manifest.name.clone()),
            );
            metadata.insert(
                "rule_description".to_string(),
                Value::String(manifest.description.clone()),
            );
        }
        if finding.category.is_empty() {
            finding.category = manifest.category.clone();
        }
        if !manifest.recommended_actions.is_empty() {
            finding.recommended_actions = manifest.recommended_actions.clone();
        }
        // The analyzer inserted the finding before enrichment; upsert it so the
        // stored row carries the rule metadata too.
        store.insert_finding(finding)?;
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_rules_dir(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("netagent-rules-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create rules dir");
        dir
    }

    #[test]
    fn loads_manifests_from_directory_and_skips_non_yaml() {
        let dir = temp_rules_dir("load");
        fs::write(
            dir.join("dns_spike.yaml"),
            "id: r1\nname: Spike\ndescription: d\ncategory: dns_anomaly\nseverity: high\nanalyzer: dns_nxdomain_spike\nenabled: true\nparams:\n  threshold_ratio: 0.5\n  min_queries: 3\n",
        )
        .expect("write rule");
        fs::write(dir.join("ignore.txt"), "not a rule").expect("write junk");
        let manifests = load_rule_manifests_from(&dir).expect("load");
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].id, "r1");
        assert_eq!(manifests[0].param_f64("threshold_ratio"), Some(0.5));
        assert_eq!(manifests[0].param_usize("min_queries"), Some(3));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn disabled_and_unknown_analyzer_rules_are_handled() {
        let dir = temp_rules_dir("dispatch");
        fs::write(
            dir.join("enabled.yaml"),
            "id: ok\nname: Ok\ndescription: d\nanalyzer: dns_nxdomain_spike\nenabled: true\nparams:\n  threshold_ratio: 0.1\n  min_queries: 1\n",
        )
        .expect("write enabled rule");
        fs::write(
            dir.join("disabled.yaml"),
            "id: off\nname: Off\ndescription: d\nanalyzer: dns_nxdomain_enumeration\nenabled: false\nparams:\n  min_nxdomains: 1\n",
        )
        .expect("write disabled rule");
        fs::write(
            dir.join("bogus.yaml"),
            "id: bogus\nname: Bogus\ndescription: d\nanalyzer: does_not_exist\nenabled: true\n",
        )
        .expect("write bogus rule");
        let manifests = load_rule_manifests_from(&dir).expect("load");
        assert_eq!(manifests.len(), 3);

        let db_path = {
            let mut path = std::env::temp_dir();
            path.push(format!(
                "netagent-rules-db-{}-{}.db",
                "dispatch",
                std::process::id()
            ));
            let _ = fs::remove_file(&path);
            path
        };
        let store = crate::storage::sqlite::SqliteStore::open(&db_path).expect("open store");
        let mut counter = 0_u64;
        let err = run_all_rules(&manifests, &store, &mut counter).expect_err("bogus analyzer");
        assert!(err.contains("unknown analyzer"));
        let _ = fs::remove_file(db_path);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rules_attach_rule_metadata_to_findings() {
        let dir = temp_rules_dir("metadata");
        fs::write(
            dir.join("spike.yaml"),
            "id: dns_nxdomain_spike\nname: Spike\ndescription: d\ncategory: dns_anomaly\nseverity: high\nanalyzer: dns_nxdomain_spike\nenabled: true\nparams:\n  threshold_ratio: 0.3\n  min_queries: 2\n",
        )
        .expect("write spike rule");
        fs::write(
            dir.join("enum.yaml"),
            "id: dns_nxdomain_enumeration\nname: Enum\ndescription: d\ncategory: dns_enumeration\nseverity: medium\nanalyzer: dns_nxdomain_enumeration\nenabled: true\nparams:\n  min_nxdomains: 2\n",
        )
        .expect("write enum rule");
        let manifests = load_rule_manifests_from(&dir).expect("load");

        let db_path = {
            let mut path = std::env::temp_dir();
            path.push(format!(
                "netagent-rules-db-{}-{}.db",
                "metadata",
                std::process::id()
            ));
            let _ = fs::remove_file(&path);
            path
        };
        let store = crate::storage::sqlite::SqliteStore::open(&db_path).expect("open store");
        let events = vec![
            netagent_models::DnsEvent {
                id: "dns_1".to_string(),
                timestamp: "2026-06-03T10:00:00Z".to_string(),
                src_ip: "10.0.0.8".to_string(),
                dst_ip: "1.1.1.1".to_string(),
                query_name: "missing1.example".to_string(),
                query_type: "A".to_string(),
                response_code: "NXDOMAIN".to_string(),
                response_code_num: 3,
                answers: vec![],
            },
            netagent_models::DnsEvent {
                id: "dns_2".to_string(),
                timestamp: "2026-06-03T10:00:01Z".to_string(),
                src_ip: "10.0.0.8".to_string(),
                dst_ip: "1.1.1.1".to_string(),
                query_name: "missing2.example".to_string(),
                query_type: "A".to_string(),
                response_code: "NXDOMAIN".to_string(),
                response_code_num: 3,
                answers: vec![],
            },
            netagent_models::DnsEvent {
                id: "dns_3".to_string(),
                timestamp: "2026-06-03T10:00:02Z".to_string(),
                src_ip: "10.0.0.8".to_string(),
                dst_ip: "1.1.1.1".to_string(),
                query_name: "ok1.example".to_string(),
                query_type: "A".to_string(),
                response_code: "NOERROR".to_string(),
                response_code_num: 0,
                answers: vec!["93.184.216.34".to_string()],
            },
        ];
        store.insert_dns_events(&events).expect("insert events");

        let mut counter = 0_u64;
        let findings = run_all_rules(&manifests, &store, &mut counter).expect("run rules");
        assert_eq!(findings.len(), 2);
        let rule_ids = findings
            .iter()
            .map(|finding| {
                finding
                    .metadata
                    .get("rule_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string()
            })
            .collect::<Vec<_>>();
        assert!(rule_ids.contains(&"dns_nxdomain_spike".to_string()));
        assert!(rule_ids.contains(&"dns_nxdomain_enumeration".to_string()));
        assert_eq!(counter, 2);

        let _ = fs::remove_file(db_path);
        let _ = fs::remove_dir_all(&dir);
    }
}
