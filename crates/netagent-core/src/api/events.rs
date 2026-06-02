#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventEnvelope {
    pub event_type: String,
    pub note: String,
}
