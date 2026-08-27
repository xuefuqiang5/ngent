use std::fmt;
use std::path::Path;

use netagent_models::{
    AgentMode, DnsEvent, Finding, Flow, Message, MessagePart, MessageRole, PermissionReply,
    PermissionRequest, RunState, Session, Step, StepStatus, ToolCall, ToolCallStatus,
};
use rusqlite::{Connection, params};
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct StoredPendingPermission {
    pub request: PermissionRequest,
    pub continuation: Value,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecoverySummary {
    pub aborted_steps: usize,
    pub aborted_tool_calls: usize,
    pub errored_sessions: usize,
    pub waiting_permission_sessions: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PersistentCounters {
    pub permission: u64,
    pub capture_or_call: u64,
    pub tool_data: u64,
    pub finding: u64,
}

pub struct SqliteStore {
    conn: Connection,
}

impl fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteStore").finish_non_exhaustive()
    }
}

impl SqliteStore {
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| format!("failed to open sqlite db: {e}"))?;
        let store = SqliteStore { conn };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<(), String> {
        self.conn
            .execute_batch(
                "
                CREATE TABLE IF NOT EXISTS flows (
                    id TEXT PRIMARY KEY,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    src_ip TEXT NOT NULL,
                    src_port INTEGER NOT NULL DEFAULT 0,
                    dst_ip TEXT NOT NULL,
                    dst_port INTEGER NOT NULL DEFAULT 0,
                    protocol TEXT NOT NULL DEFAULT '',
                    service TEXT NOT NULL DEFAULT '',
                    bytes_in INTEGER NOT NULL DEFAULT 0,
                    bytes_out INTEGER NOT NULL DEFAULT 0,
                    packets_in INTEGER NOT NULL DEFAULT 0,
                    packets_out INTEGER NOT NULL DEFAULT 0,
                    state TEXT NOT NULL DEFAULT '',
                    metadata TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS dns_events (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    query_name TEXT NOT NULL DEFAULT '',
                    query_type TEXT NOT NULL DEFAULT '',
                    response_code TEXT NOT NULL DEFAULT '',
                    response_code_num INTEGER NOT NULL DEFAULT 0,
                    answers TEXT NOT NULL DEFAULT '[]'
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence TEXT NOT NULL DEFAULT 'low',
                    category TEXT NOT NULL DEFAULT '',
                    description TEXT NOT NULL DEFAULT '',
                    entities TEXT NOT NULL DEFAULT '[]',
                    evidence TEXT NOT NULL DEFAULT '[]',
                    recommended_actions TEXT NOT NULL DEFAULT '[]',
                    metadata TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    mode TEXT NOT NULL,
                    run_state TEXT NOT NULL,
                    max_steps INTEGER NOT NULL DEFAULT 8,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    parts TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS message_parts (
                    id TEXT PRIMARY KEY,
                    message_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    position INTEGER NOT NULL DEFAULT 0,
                    kind TEXT NOT NULL,
                    content TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );

                CREATE INDEX IF NOT EXISTS idx_message_parts_message
                    ON message_parts(message_id, position, id);

                CREATE TABLE IF NOT EXISTS steps (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attempt INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS tool_calls (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    step_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    input TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS permission_requests (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    tool_call_id TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    continuation_json TEXT NOT NULL DEFAULT '{}',
                    status TEXT NOT NULL DEFAULT 'pending',
                    reply_json TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                );

                CREATE INDEX IF NOT EXISTS idx_permission_requests_pending
                    ON permission_requests(status, created_at, id);

                CREATE TABLE IF NOT EXISTS permission_rules (
                    rule TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS agent_resumes (
                    session_id TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );
                ",
            )
            .map_err(|e| format!("failed to init schema: {e}"))?;

        self.ensure_column(
            "tool_calls",
            "updated_at",
            "TEXT NOT NULL DEFAULT '1970-01-01 00:00:00'",
        )?;
        self.ensure_column(
            "steps",
            "updated_at",
            "TEXT NOT NULL DEFAULT '1970-01-01 00:00:00'",
        )?;
        self.backfill_message_parts()
    }

    fn ensure_column(&self, table: &str, column: &str, definition: &str) -> Result<(), String> {
        let mut stmt = self
            .conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .map_err(|e| format!("failed to inspect {table} schema: {e}"))?;
        let columns = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|e| format!("failed to query {table} columns: {e}"))?;
        for existing in columns {
            if existing.map_err(|e| format!("failed to read {table} column: {e}"))? == column {
                return Ok(());
            }
        }

        self.conn
            .execute(
                &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
                [],
            )
            .map_err(|e| format!("failed to add {table}.{column}: {e}"))?;
        Ok(())
    }

    fn backfill_message_parts(&self) -> Result<(), String> {
        let legacy_messages = {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT id, session_id, parts FROM messages
                     WHERE NOT EXISTS (
                        SELECT 1 FROM message_parts WHERE message_id = messages.id
                     )",
                )
                .map_err(|e| format!("failed to prepare message part backfill: {e}"))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(|e| format!("failed to query legacy message parts: {e}"))?;
            let mut messages = Vec::new();
            for row in rows {
                messages
                    .push(row.map_err(|e| format!("failed to read legacy message parts: {e}"))?);
            }
            messages
        };

        for (message_id, session_id, parts_json) in legacy_messages {
            let parts = serde_json::from_str::<Vec<MessagePart>>(&parts_json).unwrap_or_default();
            self.insert_message_parts(&message_id, &session_id, &parts)?;
        }
        Ok(())
    }

    // ── Flows ──

    pub fn insert_flows(&self, flows: &[Flow]) -> Result<usize, String> {
        let mut count = 0;
        let mut stmt = self
            .conn
            .prepare(
                "INSERT OR REPLACE INTO flows
                 (id, start_time, end_time, src_ip, src_port, dst_ip, dst_port,
                  protocol, service, bytes_in, bytes_out, packets_in, packets_out, state, metadata)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            )
            .map_err(|e| format!("failed to prepare flow insert: {e}"))?;

        for flow in flows {
            stmt.execute(params![
                flow.id,
                flow.start_time,
                flow.end_time,
                flow.src_ip,
                flow.src_port,
                flow.dst_ip,
                flow.dst_port,
                flow.protocol,
                flow.service,
                flow.bytes_in,
                flow.bytes_out,
                flow.packets_in,
                flow.packets_out,
                flow.state,
                serde_json::to_string(&flow.metadata).unwrap_or_default(),
            ])
            .map_err(|e| format!("failed to insert flow: {e}"))?;
            count += 1;
        }
        Ok(count)
    }

    pub fn list_flows(&self) -> Result<Vec<Flow>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, start_time, end_time, src_ip, src_port, dst_ip, dst_port,
                        protocol, service, bytes_in, bytes_out, packets_in, packets_out,
                        state, metadata FROM flows ORDER BY start_time DESC",
            )
            .map_err(|e| format!("failed to prepare flow query: {e}"))?;

        let rows = stmt
            .query_map([], |row| {
                Ok(Flow {
                    id: row.get(0)?,
                    start_time: row.get(1)?,
                    end_time: row.get(2)?,
                    src_ip: row.get(3)?,
                    src_port: row.get(4)?,
                    dst_ip: row.get(5)?,
                    dst_port: row.get(6)?,
                    protocol: row.get(7)?,
                    service: row.get(8)?,
                    bytes_in: row.get(9)?,
                    bytes_out: row.get(10)?,
                    packets_in: row.get(11)?,
                    packets_out: row.get(12)?,
                    state: row.get(13)?,
                    metadata: row
                        .get::<_, String>(14)
                        .map(|s| serde_json::from_str(&s).unwrap_or_default())
                        .unwrap_or_default(),
                })
            })
            .map_err(|e| format!("failed to query flows: {e}"))?;

        let mut flows = Vec::new();
        for row in rows {
            flows.push(row.map_err(|e| format!("failed to read flow row: {e}"))?);
        }
        Ok(flows)
    }

    pub fn flow_count(&self) -> Result<usize, String> {
        self.conn
            .query_row("SELECT COUNT(*) FROM flows", [], |row| {
                row.get::<_, usize>(0)
            })
            .map_err(|e| format!("failed to count flows: {e}"))
    }

    // ── DNS Events ──

    pub fn insert_dns_events(&self, events: &[DnsEvent]) -> Result<usize, String> {
        let mut count = 0;
        let mut stmt = self
            .conn
            .prepare(
                "INSERT OR REPLACE INTO dns_events
                 (id, timestamp, src_ip, dst_ip, query_name, query_type,
                  response_code, response_code_num, answers)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )
            .map_err(|e| format!("failed to prepare dns insert: {e}"))?;

        for event in events {
            let answers_json = serde_json::to_string(&event.answers).unwrap_or_default();
            stmt.execute(params![
                event.id,
                event.timestamp,
                event.src_ip,
                event.dst_ip,
                event.query_name,
                event.query_type,
                event.response_code,
                event.response_code_num,
                answers_json,
            ])
            .map_err(|e| format!("failed to insert dns event: {e}"))?;
            count += 1;
        }
        Ok(count)
    }

    pub fn list_dns_events(&self) -> Result<Vec<DnsEvent>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, timestamp, src_ip, dst_ip, query_name, query_type,
                        response_code, response_code_num, answers
                 FROM dns_events ORDER BY timestamp DESC",
            )
            .map_err(|e| format!("failed to prepare dns query: {e}"))?;

        let rows = stmt
            .query_map([], |row| {
                let answers_str: String = row.get(8)?;
                let answers: Vec<String> = serde_json::from_str(&answers_str).unwrap_or_default();
                Ok(DnsEvent {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    src_ip: row.get(2)?,
                    dst_ip: row.get(3)?,
                    query_name: row.get(4)?,
                    query_type: row.get(5)?,
                    response_code: row.get(6)?,
                    response_code_num: row.get(7)?,
                    answers,
                })
            })
            .map_err(|e| format!("failed to query dns events: {e}"))?;

        let mut events = Vec::new();
        for row in rows {
            events.push(row.map_err(|e| format!("failed to read dns row: {e}"))?);
        }
        Ok(events)
    }

    pub fn nxdomain_stats_by_host(
        &self,
        threshold_ratio: f64,
    ) -> Result<Vec<(String, usize, usize, f64)>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT src_ip,
                        COUNT(*) AS total,
                        SUM(CASE WHEN response_code_num = 3 THEN 1 ELSE 0 END) AS nxdomain
                 FROM dns_events
                 GROUP BY src_ip
                 HAVING nxdomain > 0",
            )
            .map_err(|e| format!("failed to prepare nxdomain stats: {e}"))?;

        let rows = stmt
            .query_map([], |row| {
                let total: f64 = row.get::<_, usize>(1)? as f64;
                let nxdomain: f64 = row.get::<_, usize>(2)? as f64;
                let ratio = if total > 0.0 { nxdomain / total } else { 0.0 };
                Ok((row.get::<_, String>(0)?, row.get(1)?, row.get(2)?, ratio))
            })
            .map_err(|e| format!("failed to query nxdomain stats: {e}"))?;

        let mut spikes = Vec::new();
        for row in rows {
            spikes.push(row.map_err(|e| format!("failed to read nxdomain stats: {e}"))?);
        }

        // Keep only hosts whose NXDOMAIN ratio exceeds the threshold.
        Ok(spikes
            .into_iter()
            .filter(|(_, _, _, ratio)| *ratio >= threshold_ratio)
            .collect())
    }

    /// Distinct NXDOMAIN query names per source host.
    pub fn nxdomain_qname_counts_by_host(
        &self,
    ) -> Result<Vec<(String, usize, usize)>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT src_ip,
                        COUNT(DISTINCT query_name) AS distinct_names,
                        COUNT(*) AS nxdomain_responses
                 FROM dns_events
                 WHERE response_code_num = 3
                 GROUP BY src_ip",
            )
            .map_err(|e| format!("failed to prepare nxdomain qname stats: {e}"))?;

        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|e| format!("failed to query nxdomain qname stats: {e}"))?;

        let mut hosts = Vec::new();
        for row in rows {
            hosts.push(row.map_err(|e| format!("failed to read nxdomain qname stats: {e}"))?);
        }
        Ok(hosts)
    }

    // ── Findings ──

    pub fn insert_finding(&self, finding: &Finding) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO findings
                 (id, created_at, title, severity, confidence, category, description,
                  entities, evidence, recommended_actions, metadata)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    finding.id,
                    finding.created_at,
                    finding.title,
                    finding.severity,
                    finding.confidence,
                    finding.category,
                    finding.description,
                    serde_json::to_string(&finding.entities).unwrap_or_default(),
                    serde_json::to_string(&finding.evidence).unwrap_or_default(),
                    serde_json::to_string(&finding.recommended_actions).unwrap_or_default(),
                    serde_json::to_string(&finding.metadata).unwrap_or_default(),
                ],
            )
            .map_err(|e| format!("failed to insert finding: {e}"))?;
        Ok(())
    }

    pub fn load_finding_by_id(&self, id: &str) -> Result<Option<Finding>, String> {
        let findings = self.list_findings()?;
        Ok(findings.into_iter().find(|finding| finding.id == id))
    }

    pub fn list_findings(&self) -> Result<Vec<Finding>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, created_at, title, severity, confidence, category,
                        description, entities, evidence, recommended_actions, metadata
                 FROM findings ORDER BY created_at DESC",
            )
            .map_err(|e| format!("failed to prepare findings query: {e}"))?;

        let rows = stmt
            .query_map([], |row| {
                let entities_str: String = row.get(7)?;
                let evidence_str: String = row.get(8)?;
                let actions_str: String = row.get(9)?;
                let metadata_str: String = row.get(10)?;
                Ok(Finding {
                    id: row.get(0)?,
                    created_at: row.get(1)?,
                    title: row.get(2)?,
                    severity: row.get(3)?,
                    confidence: row.get(4)?,
                    category: row.get(5)?,
                    description: row.get(6)?,
                    entities: serde_json::from_str(&entities_str).unwrap_or_default(),
                    evidence: serde_json::from_str(&evidence_str).unwrap_or_default(),
                    recommended_actions: serde_json::from_str(&actions_str).unwrap_or_default(),
                    metadata: serde_json::from_str(&metadata_str).unwrap_or_default(),
                })
            })
            .map_err(|e| format!("failed to query findings: {e}"))?;

        let mut findings = Vec::new();
        for row in rows {
            findings.push(row.map_err(|e| format!("failed to read finding row: {e}"))?);
        }
        Ok(findings)
    }

    pub fn finding_count(&self) -> Result<usize, String> {
        self.conn
            .query_row("SELECT COUNT(*) FROM findings", [], |row| {
                row.get::<_, usize>(0)
            })
            .map_err(|e| format!("failed to count findings: {e}"))
    }

    // ── Sessions ──

    pub fn save_session(&self, session: &Session) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO sessions (id, mode, run_state, max_steps)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET
                    mode = excluded.mode,
                    run_state = excluded.run_state,
                    max_steps = excluded.max_steps,
                    updated_at = datetime('now')",
                rusqlite::params![
                    session.id,
                    serde_json::to_string(&session.mode).unwrap_or_default(),
                    serde_json::to_string(&session.run_state).unwrap_or_default(),
                    session.max_steps,
                ],
            )
            .map_err(|e| format!("failed to save session: {e}"))?;
        Ok(())
    }

    pub fn save_agent_turn(
        &self,
        session: &Session,
        messages: &[Message],
        step: &Step,
        tool_calls: &[ToolCall],
    ) -> Result<(), String> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("failed to begin agent turn transaction: {e}"))?;

        tx.execute(
            "INSERT INTO sessions (id, mode, run_state, max_steps)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET
                mode = excluded.mode,
                run_state = excluded.run_state,
                max_steps = excluded.max_steps,
                updated_at = datetime('now')",
            rusqlite::params![
                session.id,
                serde_json::to_string(&session.mode).unwrap_or_default(),
                serde_json::to_string(&session.run_state).unwrap_or_default(),
                session.max_steps,
            ],
        )
        .map_err(|e| format!("failed to save session in agent turn: {e}"))?;

        for message in messages {
            let parts_json = serde_json::to_string(&message.parts).unwrap_or_default();
            tx.execute(
                "INSERT OR REPLACE INTO messages (id, session_id, role, parts)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    message.id,
                    message.session_id,
                    serde_json::to_string(&message.role).unwrap_or_default(),
                    parts_json,
                ],
            )
            .map_err(|e| format!("failed to insert message in agent turn: {e}"))?;
            insert_message_parts_on(&tx, &message.id, &message.session_id, &message.parts)?;
        }

        tx.execute(
            "INSERT INTO steps (id, session_id, status, attempt)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET
                status = excluded.status,
                attempt = excluded.attempt,
                updated_at = datetime('now')",
            rusqlite::params![
                step.id,
                step.session_id,
                serde_json::to_string(&step.status).unwrap_or_default(),
                step.attempt,
            ],
        )
        .map_err(|e| format!("failed to insert step in agent turn: {e}"))?;

        for tool_call in tool_calls {
            tx.execute(
                "INSERT INTO tool_calls (id, session_id, step_id, tool_name, input, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(id) DO UPDATE SET
                    session_id = excluded.session_id,
                    step_id = excluded.step_id,
                    tool_name = excluded.tool_name,
                    input = excluded.input,
                    status = excluded.status,
                    updated_at = datetime('now')",
                rusqlite::params![
                    tool_call.id,
                    tool_call.session_id,
                    tool_call.step_id,
                    tool_call.tool_name,
                    tool_call.input,
                    serde_json::to_string(&tool_call.status).unwrap_or_default(),
                ],
            )
            .map_err(|e| format!("failed to insert tool call in agent turn: {e}"))?;
        }

        tx.commit()
            .map_err(|e| format!("failed to commit agent turn transaction: {e}"))
    }

    pub fn load_session(&self, id: &str) -> Result<Option<Session>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, mode, run_state, max_steps FROM sessions WHERE id = ?1")
            .map_err(|e| format!("failed to prepare session query: {e}"))?;

        let mut rows = stmt
            .query_map(rusqlite::params![id], |row| {
                let mode_str: String = row.get(1)?;
                let run_state_str: String = row.get(2)?;
                Ok(Session {
                    id: row.get(0)?,
                    mode: serde_json::from_str(&mode_str).unwrap_or(AgentMode::Observe),
                    run_state: serde_json::from_str(&run_state_str).unwrap_or(RunState::Idle),
                    max_steps: row.get(3)?,
                })
            })
            .map_err(|e| format!("failed to query session: {e}"))?;

        match rows.next() {
            Some(Ok(session)) => Ok(Some(session)),
            Some(Err(e)) => Err(format!("failed to read session row: {e}")),
            None => Ok(None),
        }
    }

    pub fn list_sessions(&self) -> Result<Vec<Session>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, mode, run_state, max_steps
                 FROM sessions ORDER BY updated_at DESC, created_at DESC, id DESC",
            )
            .map_err(|e| format!("failed to prepare session list query: {e}"))?;

        let rows = stmt
            .query_map([], |row| {
                let mode_str: String = row.get(1)?;
                let run_state_str: String = row.get(2)?;
                Ok(Session {
                    id: row.get(0)?,
                    mode: serde_json::from_str(&mode_str).unwrap_or(AgentMode::Observe),
                    run_state: serde_json::from_str(&run_state_str).unwrap_or(RunState::Idle),
                    max_steps: row.get(3)?,
                })
            })
            .map_err(|e| format!("failed to query sessions: {e}"))?;

        let mut sessions = Vec::new();
        for row in rows {
            sessions.push(row.map_err(|e| format!("failed to read session row: {e}"))?);
        }
        Ok(sessions)
    }

    // ── Messages ──

    pub fn insert_message(&self, message: &Message) -> Result<(), String> {
        let parts_json = serde_json::to_string(&message.parts).unwrap_or_default();
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("failed to begin message transaction: {e}"))?;
        tx.execute(
            "INSERT INTO messages (id, session_id, role, parts)
                 VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                message.id,
                message.session_id,
                serde_json::to_string(&message.role).unwrap_or_default(),
                parts_json,
            ],
        )
        .map_err(|e| format!("failed to insert message: {e}"))?;
        insert_message_parts_on(&tx, &message.id, &message.session_id, &message.parts)?;
        tx.commit()
            .map_err(|e| format!("failed to commit message transaction: {e}"))
    }

    pub fn load_messages(&self, session_id: &str) -> Result<Vec<Message>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, session_id, role, parts
                 FROM messages WHERE session_id = ?1 ORDER BY created_at ASC, id ASC",
            )
            .map_err(|e| format!("failed to prepare message query: {e}"))?;

        let rows = stmt
            .query_map(rusqlite::params![session_id], |row| {
                let role_str: String = row.get(2)?;
                let parts_str: String = row.get(3)?;
                Ok(Message {
                    id: row.get(0)?,
                    session_id: row.get(1)?,
                    role: serde_json::from_str(&role_str).unwrap_or(MessageRole::User),
                    parts: serde_json::from_str(&parts_str).unwrap_or_default(),
                })
            })
            .map_err(|e| format!("failed to query messages: {e}"))?;

        let mut messages = Vec::new();
        for row in rows {
            messages.push(row.map_err(|e| format!("failed to read message row: {e}"))?);
        }

        for message in &mut messages {
            let normalized_parts = self.load_message_parts(&message.id)?;
            if !normalized_parts.is_empty() {
                message.parts = normalized_parts;
            }
        }
        Ok(messages)
    }

    pub fn load_message_parts(&self, message_id: &str) -> Result<Vec<MessagePart>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, kind, content FROM message_parts
                 WHERE message_id = ?1 ORDER BY position ASC, id ASC",
            )
            .map_err(|e| format!("failed to prepare message part query: {e}"))?;
        let rows = stmt
            .query_map(rusqlite::params![message_id], |row| {
                let kind: String = row.get(1)?;
                Ok(MessagePart {
                    id: row.get(0)?,
                    kind: serde_json::from_str(&kind)
                        .unwrap_or(netagent_models::MessagePartKind::Text),
                    content: row.get(2)?,
                })
            })
            .map_err(|e| format!("failed to query message parts: {e}"))?;

        let mut parts = Vec::new();
        for row in rows {
            parts.push(row.map_err(|e| format!("failed to read message part row: {e}"))?);
        }
        Ok(parts)
    }

    pub fn insert_message_parts(
        &self,
        message_id: &str,
        session_id: &str,
        parts: &[MessagePart],
    ) -> Result<(), String> {
        insert_message_parts_on(&self.conn, message_id, session_id, parts)
    }

    // ── Steps ──

    pub fn insert_step(&self, step: &Step) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO steps (id, session_id, status, attempt)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    step.id,
                    step.session_id,
                    serde_json::to_string(&step.status).unwrap_or_default(),
                    step.attempt,
                ],
            )
            .map_err(|e| format!("failed to insert step: {e}"))?;
        Ok(())
    }

    pub fn load_steps(&self, session_id: &str) -> Result<Vec<Step>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, session_id, status, attempt
                 FROM steps WHERE session_id = ?1 ORDER BY created_at ASC, id ASC",
            )
            .map_err(|e| format!("failed to prepare step query: {e}"))?;

        let rows = stmt
            .query_map(rusqlite::params![session_id], |row| {
                let status_str: String = row.get(2)?;
                Ok(Step {
                    id: row.get(0)?,
                    session_id: row.get(1)?,
                    status: serde_json::from_str(&status_str).unwrap_or(StepStatus::Completed),
                    attempt: row.get(3)?,
                })
            })
            .map_err(|e| format!("failed to query steps: {e}"))?;

        let mut steps = Vec::new();
        for row in rows {
            steps.push(row.map_err(|e| format!("failed to read step row: {e}"))?);
        }
        Ok(steps)
    }

    // ── Tool Calls ──

    pub fn insert_tool_call(&self, tool_call: &ToolCall) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO tool_calls (id, session_id, step_id, tool_name, input, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(id) DO UPDATE SET
                    session_id = excluded.session_id,
                    step_id = excluded.step_id,
                    tool_name = excluded.tool_name,
                    input = excluded.input,
                    status = excluded.status,
                    updated_at = datetime('now')",
                rusqlite::params![
                    tool_call.id,
                    tool_call.session_id,
                    tool_call.step_id,
                    tool_call.tool_name,
                    tool_call.input,
                    serde_json::to_string(&tool_call.status).unwrap_or_default(),
                ],
            )
            .map_err(|e| format!("failed to insert tool_call: {e}"))?;
        Ok(())
    }

    pub fn update_tool_call_status(
        &self,
        tool_call_id: &str,
        status: ToolCallStatus,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE tool_calls
                 SET status = ?2, updated_at = datetime('now')
                 WHERE id = ?1",
                rusqlite::params![
                    tool_call_id,
                    serde_json::to_string(&status).unwrap_or_default(),
                ],
            )
            .map_err(|e| format!("failed to update tool_call status: {e}"))?;
        Ok(())
    }

    pub fn load_tool_calls(&self, session_id: &str) -> Result<Vec<ToolCall>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, session_id, step_id, tool_name, input, status
                 FROM tool_calls WHERE session_id = ?1 ORDER BY created_at ASC, id ASC",
            )
            .map_err(|e| format!("failed to prepare tool_call query: {e}"))?;

        let rows = stmt
            .query_map(rusqlite::params![session_id], |row| {
                let status_str: String = row.get(5)?;
                Ok(ToolCall {
                    id: row.get(0)?,
                    session_id: row.get(1)?,
                    step_id: row.get(2)?,
                    tool_name: row.get(3)?,
                    input: row.get(4)?,
                    status: serde_json::from_str(&status_str).unwrap_or(ToolCallStatus::Pending),
                })
            })
            .map_err(|e| format!("failed to query tool_calls: {e}"))?;

        let mut calls = Vec::new();
        for row in rows {
            calls.push(row.map_err(|e| format!("failed to read tool_call row: {e}"))?);
        }
        Ok(calls)
    }

    // ── Permission Requests ──

    pub fn save_pending_permission(
        &self,
        request: &PermissionRequest,
        continuation: &Value,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO permission_requests
                 (id, session_id, tool_call_id, request_json, continuation_json, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'pending')
                 ON CONFLICT(id) DO UPDATE SET
                    session_id = excluded.session_id,
                    tool_call_id = excluded.tool_call_id,
                    request_json = excluded.request_json,
                    continuation_json = excluded.continuation_json,
                    status = 'pending',
                    reply_json = NULL,
                    updated_at = datetime('now')",
                rusqlite::params![
                    request.id,
                    request.session_id,
                    request.tool.call_id,
                    serde_json::to_string(request).unwrap_or_default(),
                    serde_json::to_string(continuation).unwrap_or_else(|_| String::from("{}")),
                ],
            )
            .map_err(|e| format!("failed to save pending permission: {e}"))?;
        Ok(())
    }

    pub fn resolve_permission(&self, reply: &PermissionReply) -> Result<(), String> {
        let status = serde_json::to_value(reply.decision)
            .ok()
            .and_then(|value| value.as_str().map(str::to_string))
            .unwrap_or_else(|| String::from("resolved"));
        let updated = self
            .conn
            .execute(
                "UPDATE permission_requests
                 SET status = ?2, reply_json = ?3, updated_at = datetime('now')
                 WHERE id = ?1 AND status = 'pending'",
                rusqlite::params![
                    reply.request_id,
                    status,
                    serde_json::to_string(reply).unwrap_or_default(),
                ],
            )
            .map_err(|e| format!("failed to resolve permission: {e}"))?;
        if updated == 0 {
            return Err(format!(
                "pending permission not found in storage: {}",
                reply.request_id
            ));
        }
        Ok(())
    }

    pub fn list_pending_permissions(&self) -> Result<Vec<StoredPendingPermission>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT request_json, continuation_json
                 FROM permission_requests
                 WHERE status = 'pending'
                 ORDER BY created_at ASC, id ASC",
            )
            .map_err(|e| format!("failed to prepare pending permission query: {e}"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| format!("failed to query pending permissions: {e}"))?;

        let mut pending = Vec::new();
        for row in rows {
            let (request_json, continuation_json) =
                row.map_err(|e| format!("failed to read pending permission row: {e}"))?;
            let request = serde_json::from_str(&request_json)
                .map_err(|e| format!("failed to decode pending permission: {e}"))?;
            let continuation = serde_json::from_str(&continuation_json)
                .map_err(|e| format!("failed to decode permission continuation: {e}"))?;
            pending.push(StoredPendingPermission {
                request,
                continuation,
            });
        }
        Ok(pending)
    }

    pub fn save_permission_rules(&self, rules: &[String]) -> Result<(), String> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("failed to begin permission rule transaction: {e}"))?;
        for rule in rules {
            tx.execute(
                "INSERT OR IGNORE INTO permission_rules (rule) VALUES (?1)",
                rusqlite::params![rule],
            )
            .map_err(|e| format!("failed to save permission rule: {e}"))?;
        }
        tx.commit()
            .map_err(|e| format!("failed to commit permission rules: {e}"))
    }

    pub fn list_permission_rules(&self) -> Result<Vec<String>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT rule FROM permission_rules ORDER BY created_at ASC, rule ASC")
            .map_err(|e| format!("failed to prepare permission rule query: {e}"))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| format!("failed to query permission rules: {e}"))?;
        let mut rules = Vec::new();
        for row in rows {
            rules.push(row.map_err(|e| format!("failed to read permission rule: {e}"))?);
        }
        Ok(rules)
    }

    // ── Recovery ──

    pub fn persistent_counters(&self) -> Result<PersistentCounters, String> {
        let permission = self.max_suffix_from_query("SELECT id FROM permission_requests")?;
        let call = self.max_suffix_from_query("SELECT id FROM tool_calls")?;
        let flow = self.max_suffix_from_query("SELECT id FROM flows")?;
        let dns = self.max_suffix_from_query("SELECT id FROM dns_events")?;
        let finding = self.max_suffix_from_query("SELECT id FROM findings")?;

        Ok(PersistentCounters {
            permission,
            capture_or_call: call,
            tool_data: call.max(flow).max(dns),
            finding,
        })
    }

    fn max_suffix_from_query(&self, query: &str) -> Result<u64, String> {
        let mut stmt = self
            .conn
            .prepare(query)
            .map_err(|e| format!("failed to prepare id recovery query: {e}"))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| format!("failed to query persisted ids: {e}"))?;
        let mut maximum = 0;
        for row in rows {
            let id = row.map_err(|e| format!("failed to read persisted id: {e}"))?;
            let suffix = id
                .rsplit('_')
                .next()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0);
            maximum = maximum.max(suffix);
        }
        Ok(maximum)
    }

    pub fn reconcile_interrupted_runtime(&self) -> Result<RecoverySummary, String> {
        let running_step = serde_json::to_string(&StepStatus::Running).unwrap_or_default();
        let aborted_step = serde_json::to_string(&StepStatus::Aborted).unwrap_or_default();
        let pending_tool = serde_json::to_string(&ToolCallStatus::Pending).unwrap_or_default();
        let running_tool = serde_json::to_string(&ToolCallStatus::Running).unwrap_or_default();
        let aborted_tool = serde_json::to_string(&ToolCallStatus::Aborted).unwrap_or_default();
        let waiting_permission =
            serde_json::to_string(&RunState::WaitingPermission).unwrap_or_default();
        let error = serde_json::to_string(&RunState::Error).unwrap_or_default();
        let recoverable_states = [
            RunState::Busy,
            RunState::RunningTool,
            RunState::Capturing,
            RunState::Analyzing,
            RunState::Reporting,
            RunState::Retrying,
            RunState::Compacting,
            RunState::Canceling,
        ]
        .into_iter()
        .map(|state| serde_json::to_string(&state).unwrap_or_default())
        .collect::<Vec<_>>();

        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| format!("failed to begin recovery transaction: {e}"))?;
        let aborted_steps = tx
            .execute(
                "UPDATE steps SET status = ?2 WHERE status = ?1",
                rusqlite::params![running_step, aborted_step],
            )
            .map_err(|e| format!("failed to reconcile steps: {e}"))?;
        let aborted_tool_calls = tx
            .execute(
                "UPDATE tool_calls
                 SET status = ?3, updated_at = datetime('now')
                 WHERE status IN (?1, ?2)
                   AND id NOT IN (
                     SELECT tool_call_id FROM permission_requests WHERE status = 'pending'
                   )",
                rusqlite::params![pending_tool, running_tool, aborted_tool],
            )
            .map_err(|e| format!("failed to reconcile tool calls: {e}"))?;
        let errored_sessions = tx
            .execute(
                "UPDATE sessions
                 SET run_state = ?1, updated_at = datetime('now')
                 WHERE run_state IN (?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                   AND id NOT IN (
                     SELECT session_id FROM permission_requests WHERE status = 'pending'
                   )",
                rusqlite::params![
                    error,
                    recoverable_states[0],
                    recoverable_states[1],
                    recoverable_states[2],
                    recoverable_states[3],
                    recoverable_states[4],
                    recoverable_states[5],
                    recoverable_states[6],
                    recoverable_states[7],
                ],
            )
            .map_err(|e| format!("failed to reconcile sessions: {e}"))?;
        let waiting_permission_sessions = tx
            .execute(
                "UPDATE sessions
                 SET run_state = ?1, updated_at = datetime('now')
                 WHERE id IN (
                    SELECT session_id FROM permission_requests WHERE status = 'pending'
                 )",
                rusqlite::params![waiting_permission],
            )
            .map_err(|e| format!("failed to restore waiting permission sessions: {e}"))?;
        tx.commit()
            .map_err(|e| format!("failed to commit recovery transaction: {e}"))?;

        Ok(RecoverySummary {
            aborted_steps,
            aborted_tool_calls,
            errored_sessions,
            waiting_permission_sessions,
        })
    }

    pub fn update_session_run_state(
        &self,
        session_id: &str,
        run_state: RunState,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE sessions
                 SET run_state = ?2, updated_at = datetime('now')
                 WHERE id = ?1",
                rusqlite::params![
                    session_id,
                    serde_json::to_string(&run_state).unwrap_or_default(),
                ],
            )
            .map_err(|e| format!("failed to update session run state: {e}"))?;
        Ok(())
    }

    // ── Agent resume continuations ──

    /// Persist the bounded permission/capture outcome that the Agent loop
    /// should consume on the next `agent.resume` call.
    pub fn save_agent_resume(&self, session_id: &str, payload: &Value) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO agent_resumes (session_id, payload_json)
                 VALUES (?1, ?2)
                 ON CONFLICT(session_id) DO UPDATE SET
                    payload_json = excluded.payload_json,
                    created_at = datetime('now')",
                rusqlite::params![session_id, payload.to_string()],
            )
            .map_err(|e| format!("failed to save agent resume: {e}"))?;
        Ok(())
    }

    pub fn load_agent_resume(&self, session_id: &str) -> Result<Option<Value>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT payload_json FROM agent_resumes WHERE session_id = ?1")
            .map_err(|e| format!("failed to prepare agent resume query: {e}"))?;
        let mut rows = stmt
            .query_map(rusqlite::params![session_id], |row| row.get::<_, String>(0))
            .map_err(|e| format!("failed to query agent resume: {e}"))?;
        match rows.next() {
            Some(Ok(payload)) => serde_json::from_str(&payload)
                .map(Some)
                .map_err(|e| format!("failed to parse agent resume payload: {e}")),
            Some(Err(e)) => Err(format!("failed to read agent resume payload: {e}")),
            None => Ok(None),
        }
    }

    pub fn delete_agent_resume(&self, session_id: &str) -> Result<(), String> {
        self.conn
            .execute("DELETE FROM agent_resumes WHERE session_id = ?1", [session_id])
            .map_err(|e| format!("failed to delete agent resume: {e}"))?;
        Ok(())
    }
}

fn insert_message_parts_on(
    conn: &Connection,
    message_id: &str,
    session_id: &str,
    parts: &[MessagePart],
) -> Result<(), String> {
    for (position, part) in parts.iter().enumerate() {
        conn.execute(
            "INSERT OR REPLACE INTO message_parts
             (id, message_id, session_id, position, kind, content)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                part.id,
                message_id,
                session_id,
                position,
                serde_json::to_string(&part.kind).unwrap_or_default(),
                part.content,
            ],
        )
        .map_err(|e| format!("failed to insert message part: {e}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::SqliteStore;
    use rusqlite::Connection;

    #[test]
    fn migrates_legacy_steps_table_with_updated_at() {
        let path = std::env::temp_dir().join(format!(
            "netagent-legacy-steps-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let connection = Connection::open(&path).expect("open legacy database");
        connection
            .execute_batch(
                "CREATE TABLE steps (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attempt INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );",
            )
            .expect("create legacy steps table");
        drop(connection);

        let store = SqliteStore::open(&path).expect("migrate database");
        let has_updated_at = store
            .conn
            .prepare("PRAGMA table_info(steps)")
            .expect("inspect steps")
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query columns")
            .filter_map(Result::ok)
            .any(|column| column == "updated_at");
        assert!(has_updated_at);
        drop(store);
        let _ = std::fs::remove_file(path);
    }
}
