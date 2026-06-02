#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcEnvelope {
    pub version: &'static str,
}

impl Default for RpcEnvelope {
    fn default() -> Self {
        Self { version: "2.0" }
    }
}
