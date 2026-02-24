use std::fs::{self, OpenOptions};
use std::io::{BufRead, Write};
use std::path::PathBuf;

use openice_core::error::OpenIceError;
use openice_core::mode::OperatingMode;
use openice_core::telemetry::event::{AuditEvent, EventKind, RollbackEntry, UndoType};

use openice_enforcement::network::firewall;

/// Get the default rollback log file path.
pub fn rollback_file_path() -> PathBuf {
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        PathBuf::from(local_app_data)
            .join("OpenICE")
            .join("rollback.jsonl")
    } else {
        PathBuf::from("rollback.jsonl")
    }
}

/// Record a rollback entry to the persistent log.
pub fn record_rollback(entry: &RollbackEntry) -> Result<(), OpenIceError> {
    let path = rollback_file_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            OpenIceError::RollbackError(format!("Failed to create rollback directory: {}", e))
        })?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| {
            OpenIceError::RollbackError(format!("Failed to open rollback file: {}", e))
        })?;

    let json = serde_json::to_string(entry).map_err(|e| {
        OpenIceError::RollbackError(format!("Failed to serialize rollback entry: {}", e))
    })?;

    writeln!(file, "{}", json).map_err(|e| {
        OpenIceError::RollbackError(format!("Failed to write rollback entry: {}", e))
    })?;

    Ok(())
}

/// Load all rollback entries from the persistent log.
pub fn load_rollback_entries() -> Result<Vec<RollbackEntry>, OpenIceError> {
    let path = rollback_file_path();
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = fs::File::open(&path).map_err(|e| {
        OpenIceError::RollbackError(format!("Failed to open rollback file: {}", e))
    })?;

    let reader = std::io::BufReader::new(file);
    let mut entries = Vec::new();

    for line in reader.lines() {
        let line = line.map_err(|e| {
            OpenIceError::RollbackError(format!("Failed to read rollback line: {}", e))
        })?;

        if line.trim().is_empty() {
            continue;
        }

        match serde_json::from_str::<RollbackEntry>(&line) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                tracing::warn!("Skipping malformed rollback entry: {}", e);
            }
        }
    }

    Ok(entries)
}

/// Execute a single rollback entry.
pub fn execute_rollback(entry: &RollbackEntry) -> Result<AuditEvent, OpenIceError> {
    match &entry.undo_type {
        UndoType::RemoveFirewallRule { rule_name } => {
            let events = firewall::unblock_outbound(rule_name, OperatingMode::Observe)?;
            let event = events.into_iter().next().unwrap_or_else(|| {
                AuditEvent::new(
                    EventKind::RollbackPerformed,
                    OperatingMode::Observe,
                    "Rollback",
                    "RemoveFirewallRule",
                    &format!("Removed firewall rule '{}'", rule_name),
                )
            });
            Ok(event)
        }
        UndoType::NonReversible { reason } => {
            let event = AuditEvent::new(
                EventKind::RollbackPerformed,
                OperatingMode::Observe,
                "Rollback",
                "NonReversible",
                &format!("Cannot undo: {}", reason),
            )
            .with_result(openice_core::telemetry::event::ActionResult::Skipped {
                reason: reason.clone(),
            });
            Ok(event)
        }
        UndoType::RestoreRegistryValue { key, value_name, .. } => {
            // Registry restoration would require writing back the value
            // For now, log that manual intervention is needed
            let event = AuditEvent::new(
                EventKind::RollbackPerformed,
                OperatingMode::Observe,
                "Rollback",
                "RestoreRegistryValue",
                &format!(
                    "Registry value restoration not yet automated: {}\\{}",
                    key, value_name
                ),
            )
            .with_result(openice_core::telemetry::event::ActionResult::Skipped {
                reason: "Automated registry restoration not yet implemented".to_string(),
            });
            Ok(event)
        }
        UndoType::RestoreScheduledTask { task_name } => {
            let event = AuditEvent::new(
                EventKind::RollbackPerformed,
                OperatingMode::Observe,
                "Rollback",
                "RestoreScheduledTask",
                &format!(
                    "Scheduled task restoration not yet automated: {}",
                    task_name
                ),
            )
            .with_result(openice_core::telemetry::event::ActionResult::Skipped {
                reason: "Automated task restoration not yet implemented".to_string(),
            });
            Ok(event)
        }
        UndoType::RestoreStartupShortcut { path } => {
            let event = AuditEvent::new(
                EventKind::RollbackPerformed,
                OperatingMode::Observe,
                "Rollback",
                "RestoreStartupShortcut",
                &format!(
                    "Startup shortcut restoration not yet automated: {}",
                    path.display()
                ),
            )
            .with_result(openice_core::telemetry::event::ActionResult::Skipped {
                reason: "Automated shortcut restoration not yet implemented".to_string(),
            });
            Ok(event)
        }
    }
}

/// Execute rollback for the last N entries.
pub fn rollback_last(count: usize) -> Result<Vec<AuditEvent>, OpenIceError> {
    let entries = load_rollback_entries()?;
    let mut events = Vec::new();

    let start = if entries.len() > count {
        entries.len() - count
    } else {
        0
    };

    for entry in entries[start..].iter().rev() {
        match execute_rollback(entry) {
            Ok(event) => events.push(event),
            Err(e) => {
                tracing::error!("Rollback failed for {}: {}", entry.description, e);
            }
        }
    }

    Ok(events)
}

/// Clear the rollback log.
pub fn clear_rollback_log() -> Result<(), OpenIceError> {
    let path = rollback_file_path();
    if path.exists() {
        fs::remove_file(&path).map_err(|e| {
            OpenIceError::RollbackError(format!("Failed to clear rollback log: {}", e))
        })?;
    }
    Ok(())
}
