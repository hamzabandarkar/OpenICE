use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

use crate::mode::OperatingMode;

/// A structured audit event recording an enforcement action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub kind: EventKind,
    pub target_process: Option<String>,
    pub target_pid: Option<u32>,
    pub target_path: Option<PathBuf>,
    pub mode: OperatingMode,
    pub backend: String,
    pub action: String,
    pub result: ActionResult,
    pub details: String,
    pub rollback_info: Option<RollbackEntry>,
}

impl AuditEvent {
    pub fn new(
        kind: EventKind,
        mode: OperatingMode,
        backend: &str,
        action: &str,
        details: &str,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            kind,
            target_process: None,
            target_pid: None,
            target_path: None,
            mode,
            backend: backend.to_string(),
            action: action.to_string(),
            result: ActionResult::Success,
            details: details.to_string(),
            rollback_info: None,
        }
    }

    pub fn with_target(mut self, name: &str, pid: Option<u32>, path: Option<PathBuf>) -> Self {
        self.target_process = Some(name.to_string());
        self.target_pid = pid;
        self.target_path = path;
        self
    }

    pub fn with_result(mut self, result: ActionResult) -> Self {
        self.result = result;
        self
    }

    pub fn with_rollback(mut self, rollback: RollbackEntry) -> Self {
        self.rollback_info = Some(rollback);
        self
    }
}

/// Categories of audit events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    ProcessDetected,
    ProcessKilled,
    NetworkBlocked,
    NetworkUnblocked,
    PersistenceRemoved,
    PersistenceDetected,
    ResourceLimited,
    LaunchBlocked,
    ChildProcessBlocked,
    PolicyLoaded,
    PolicyError,
    RollbackPerformed,
    ScanCompleted,
    Error,
}

/// Outcome of an enforcement action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum ActionResult {
    Success,
    Failed { reason: String },
    Skipped { reason: String },
    DryRun,
}

/// Information needed to undo an enforcement action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackEntry {
    pub action_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub undo_type: UndoType,
    pub description: String,
}

impl RollbackEntry {
    pub fn new(action_id: Uuid, undo_type: UndoType, description: &str) -> Self {
        Self {
            action_id,
            timestamp: Utc::now(),
            undo_type,
            description: description.to_string(),
        }
    }
}

/// Types of undo operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum UndoType {
    RemoveFirewallRule {
        rule_name: String,
    },
    RestoreRegistryValue {
        key: String,
        value_name: String,
        data: Vec<u8>,
        reg_type: u32,
    },
    RestoreScheduledTask {
        task_name: String,
    },
    RestoreStartupShortcut {
        path: PathBuf,
    },
    /// Process kills cannot be undone.
    NonReversible {
        reason: String,
    },
}
