#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolStub {
    pub id: &'static str,
    pub note: &'static str,
}

pub const TOOL_STUBS: [ToolStub; 2] = [
    ToolStub {
        id: "system.ping",
        note: "Reserved for Phase 1 mock JSON-RPC method.",
    },
    ToolStub {
        id: "system.list_interfaces",
        note: "Reserved for Phase 1 mock interface listing.",
    },
];
