use netagent_models::{ArtifactKind, ArtifactRef};

#[derive(Debug, Default)]
pub struct ArtifactStore {
    counter: u64,
}

impl ArtifactStore {
    pub fn write_raw_output(&mut self, tool_name: &str, content: &str) -> ArtifactRef {
        self.counter += 1;
        let id = format!("artifact_{:04}", self.counter);

        ArtifactRef {
            id: id.clone(),
            kind: ArtifactKind::RawToolOutput,
            note: format!("Raw output stored for {tool_name}"),
            path: format!("artifacts/{id}.log"),
        }
        .with_embedded_content(content)
    }

    pub fn register_pcap(&mut self, path: &str, note: &str) -> ArtifactRef {
        self.counter += 1;
        let id = format!("artifact_{:04}", self.counter);

        ArtifactRef {
            id,
            kind: ArtifactKind::Pcap,
            note: note.to_string(),
            path: path.to_string(),
        }
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
