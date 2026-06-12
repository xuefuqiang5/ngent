use std::fmt;
use std::path::Path;

use netagent_models::{
    AgentMode, DnsEvent, Finding, Flow, Message, MessageRole, RunState, Session, Step, StepStatus,
    ToolCall, ToolCallStatus,
};
use rusqlite::{Connection, params};

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

                CREATE TABLE IF NOT EXISTS steps (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attempt INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS tool_calls (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    step_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    input TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );
                ",
            )
            .map_err(|e| format!("failed to init schema: {e}"))
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
            let entry = row.map_err(|e| format!("failed to read nxdomain row: {e}"))?;
            if entry.3 >= threshold_ratio {
                spikes.push(entry);
            }
        }
        Ok(spikes)
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
        user_message: &Message,
        assistant_message: &Message,
        step: &Step,
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

        for message in [user_message, assistant_message] {
            let parts_json = serde_json::to_string(&message.parts).unwrap_or_default();
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
            .map_err(|e| format!("failed to insert message in agent turn: {e}"))?;
        }

        tx.execute(
            "INSERT INTO steps (id, session_id, status, attempt)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                step.id,
                step.session_id,
                serde_json::to_string(&step.status).unwrap_or_default(),
                step.attempt,
            ],
        )
        .map_err(|e| format!("failed to insert step in agent turn: {e}"))?;

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
        self.conn
            .execute(
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
        Ok(())
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
        Ok(messages)
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
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
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
}
