use netagent_models::{ArtifactKind, ArtifactRef};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Default)]
pub struct ArtifactStore {
    counter: u64,
    artifacts: Vec<ArtifactRef>,
}

impl ArtifactStore {
    pub fn write_raw_output(&mut self, tool_name: &str, content: &str) -> ArtifactRef {
        self.counter += 1;
        let id = format!("artifact_{:04}", self.counter);

        let artifact = ArtifactRef {
            id: id.clone(),
            kind: ArtifactKind::RawToolOutput,
            note: format!("Raw output stored for {tool_name}"),
            path: format!("artifacts/{id}.log"),
        }
        .with_embedded_content(content);
        self.artifacts.push(artifact.clone());
        artifact
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
        let mut base_dir = std::env::temp_dir();
        base_dir.push("netagent-artifacts");
        fs::create_dir_all(&base_dir)
            .map_err(|error| format!("failed to create artifact dir: {error}"))?;

        let mut path = PathBuf::from(&base_dir);
        path.push(format!("{stem}-{}.{}", self.counter, extension));
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
}

trait ArtifactRefExt {
    fn with_embedded_content(self, content: &str) -> ArtifactRef;
}

impl ArtifactRefExt for ArtifactRef {
    fn with_embedded_content(mut self, content: &str) -> ArtifactRef {
        self.note = format!("{} ({} bytes)", self.note, content.len());
        self
    }
}
