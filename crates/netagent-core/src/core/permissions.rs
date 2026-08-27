use std::collections::HashMap;

use netagent_models::{
    PermissionDecision, PermissionKind, PermissionReply, PermissionReplyKind, PermissionRequest,
};

#[derive(Debug, Clone)]
pub struct PermissionOutcome {
    pub request: PermissionRequest,
    pub decision: PermissionDecision,
    pub feedback: Option<String>,
}

#[derive(Debug, Default)]
pub struct PermissionManager {
    pending: HashMap<String, PermissionRequest>,
    always_rules: Vec<String>,
}

impl PermissionManager {
    pub fn ask(&mut self, request: PermissionRequest) -> PermissionDecision {
        if self.evaluate(request.permission, &request.patterns) {
            return PermissionDecision::AllowedAlways;
        }

        self.pending.insert(request.id.clone(), request);
        PermissionDecision::Pending
    }

    pub fn reply(&mut self, reply: PermissionReply) -> Option<PermissionOutcome> {
        let request = self.pending.remove(&reply.request_id)?;
        let decision = match reply.decision {
            PermissionReplyKind::Once => PermissionDecision::AllowedOnce,
            PermissionReplyKind::Always => {
                self.persist_always_rule(&request.always);
                PermissionDecision::AllowedAlways
            }
            PermissionReplyKind::Reject | PermissionReplyKind::RejectWithFeedback => {
                PermissionDecision::Rejected
            }
        };

        Some(PermissionOutcome {
            request,
            decision,
            feedback: reply.feedback,
        })
    }

    pub fn list_pending(&self) -> Vec<PermissionRequest> {
        self.pending.values().cloned().collect()
    }

    pub fn restore_pending(&mut self, request: PermissionRequest) {
        self.pending.insert(request.id.clone(), request);
    }

    pub fn remove_pending(&mut self, request_id: &str) -> Option<PermissionRequest> {
        self.pending.remove(request_id)
    }

    pub fn evaluate(&self, permission: PermissionKind, patterns: &[String]) -> bool {
        let rules = self.merge_rulesets();
        patterns.iter().any(|pattern| {
            rules.contains(&format!("{}:{pattern}", permission_slug(permission)))
                || rules.contains(&format!("{}:*", permission_slug(permission)))
                || rules.contains(&format!("{}:{}:*", permission_slug(permission), pattern))
        })
    }

    pub fn merge_rulesets(&self) -> Vec<String> {
        self.always_rules.clone()
    }

    pub fn persist_always_rule(&mut self, rules: &[String]) {
        for rule in rules {
            if !self.always_rules.contains(rule) {
                self.always_rules.push(rule.clone());
            }
        }
    }

    pub fn reject_pending_for_session(&mut self, session_id: &str) -> Vec<PermissionRequest> {
        let pending = self.list_pending();
        let rejected: Vec<_> = pending
            .into_iter()
            .filter(|request| request.session_id == session_id)
            .collect();

        for request in &rejected {
            self.pending.remove(&request.id);
        }

        rejected
    }
}

fn permission_slug(permission: PermissionKind) -> &'static str {
    match permission {
        PermissionKind::CaptureLive => "capture_live",
    }
}
