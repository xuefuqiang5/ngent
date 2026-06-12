# Architecture Notes

This directory contains design records for NetAgent business abstractions that are too important to leave implicit in code.

Current documents:

- [Case Model](case_model.md): investigation boundary, ownership, status, scope, and Phase 10 default-case strategy.
- [Information Model](information_model.md): information identity, source, sensitivity, visibility, trust, compact, retention, and lifecycle policy.
- [Compact Policy And Investigation Snapshot](compact_policy.md): case-aware compacting, snapshot shape, ContextBuilder contract, and recovery rules.

Maintenance rule:

- Update these documents before or with any code change that modifies Case semantics, information policy, compacting, snapshot generation, or model-context construction.
- Do not add a new state machine without documenting legal states, legal transitions, ownership, recovery behavior, and model-context visibility.
- Keep Phase 10 implementation small: default active case, session/message persistence, investigation snapshots, and a ContextBuilder skeleton.
