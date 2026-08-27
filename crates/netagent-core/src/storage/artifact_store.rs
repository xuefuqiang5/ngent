use netagent_models::{ArtifactKind, ArtifactRef};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Default)]
pub struct ArtifactStore {
    counter: u64,
    artifacts: Vec<ArtifactRef>,
}

impl ArtifactStore {
    pub fn write_raw_output(
        &mut self,
        tool_name: &str,
        content: &str,
    ) -> Result<ArtifactRef, String> {
        self.write_text_artifact(
            tool_name,
            "log",
            ArtifactKind::RawToolOutput,
            "Raw tool output",
            content,
        )
    }

    pub fn register_pcap(&mut self, path: &str, note: &str) -> ArtifactRef {
        self.counter += 1;
        let id = format!("artifact_{:04}", self.counter);
        let artifact = ArtifactRef {
            id,
            kind: ArtifactKind::Pcap,
            note: note.to_string(),
            path: path.to_string(),
        };
        self.artifacts.push(artifact.clone());
        artifact
    }

    pub fn write_report(&mut self, stem: &str, content: &str) -> Result<ArtifactRef, String> {
        self.write_text_artifact(stem, "md", ArtifactKind::Report, "Markdown report", content)
    }

    pub fn write_ioc_export(&mut self, stem: &str, content: &str) -> Result<ArtifactRef, String> {
        self.write_text_artifact(stem, "json", ArtifactKind::IocExport, "IOC export", content)
    }

    fn write_text_artifact(
        &mut self,
        stem: &str,
        extension: &str,
        kind: ArtifactKind,
        label: &str,
        content: &str,
    ) -> Result<ArtifactRef, String> {
        self.counter += 1;
        let id = format!("artifact_{:04}", self.counter);
        let base_dir = std::env::var("NETAGENT_ARTIFACT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let mut path = std::env::temp_dir();
                path.push("netagent-artifacts");
                path
            });
        fs::create_dir_all(&base_dir)
            .map_err(|error| format!("failed to create artifact dir: {error}"))?;

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let safe_stem = stem
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                    character
                } else {
                    '_'
                }
            })
            .collect::<String>();
        let mut path = PathBuf::from(&base_dir);
        path.push(format!(
            "{safe_stem}-{unique}-{}.{}",
            self.counter, extension
        ));
        fs::write(&path, content).map_err(|error| format!("failed to write artifact: {error}"))?;

        let artifact = ArtifactRef {
            id,
            kind,
            note: format!("{label} ({} bytes)", content.len()),
            path: path.to_string_lossy().to_string(),
        };
        self.artifacts.push(artifact.clone());
        Ok(artifact)
    }

    pub fn list_artifacts(&self) -> Vec<ArtifactRef> {
        self.artifacts.clone()
    }

    pub fn get_artifact(&self, artifact_id: &str) -> Option<&ArtifactRef> {
        self.artifacts
            .iter()
            .find(|artifact| artifact.id == artifact_id)
    }
}
