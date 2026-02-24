use std::process::Command;

use openice_core::error::OpenIceError;
use openice_core::mode::OperatingMode;
use openice_core::telemetry::event::{
    ActionResult, AuditEvent, EventKind, RollbackEntry, UndoType,
};

/// A detected scheduled task.
#[derive(Debug, Clone)]
pub struct ScheduledTaskEntry {
    pub task_name: String,
    pub next_run: String,
    pub status: String,
    pub command: String,
}

/// Scan scheduled tasks for entries matching a target name.
pub fn scan_scheduled_tasks(target_name: &str) -> Result<Vec<ScheduledTaskEntry>, OpenIceError> {
    let output = Command::new("schtasks")
        .args(["/query", "/fo", "CSV", "/v"])
        .output()
        .map_err(|e| {
            OpenIceError::PersistenceError(format!("Failed to execute schtasks: {}", e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(OpenIceError::PersistenceError(format!(
            "schtasks query failed: {}",
            stderr
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let target_lower = target_name.to_lowercase();
    let mut tasks = Vec::new();

    for line in stdout.lines().skip(1) {
        // Skip header
        let line_lower = line.to_lowercase();
        if line_lower.contains(&target_lower) {
            // CSV fields: HostName, TaskName, NextRunTime, Status, ...
            let fields: Vec<&str> = line.split(',').map(|f| f.trim_matches('"')).collect();
            if fields.len() >= 4 {
                tasks.push(ScheduledTaskEntry {
                    task_name: fields[1].to_string(),
                    next_run: fields[2].to_string(),
                    status: fields[3].to_string(),
                    command: if fields.len() > 8 {
                        fields[8].to_string()
                    } else {
                        String::new()
                    },
                });
            }
        }
    }

    Ok(tasks)
}

/// Delete a scheduled task by name.
pub fn delete_scheduled_task(
    task_name: &str,
    mode: OperatingMode,
) -> Result<AuditEvent, OpenIceError> {
    let output = Command::new("schtasks")
        .args(["/delete", "/tn", task_name, "/f"])
        .output()
        .map_err(|e| {
            OpenIceError::PersistenceError(format!("Failed to execute schtasks delete: {}", e))
        })?;

    if output.status.success() {
        let mut event = AuditEvent::new(
            EventKind::PersistenceRemoved,
            mode,
            "PersistenceMonitor",
            "DeleteScheduledTask",
            &format!("Deleted scheduled task '{}'", task_name),
        );
        event.rollback_info = Some(RollbackEntry::new(
            event.id,
            UndoType::RestoreScheduledTask {
                task_name: task_name.to_string(),
            },
            &format!("Restore scheduled task '{}'", task_name),
        ));
        Ok(event)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let event = AuditEvent::new(
            EventKind::PersistenceRemoved,
            mode,
            "PersistenceMonitor",
            "DeleteScheduledTask",
            &format!(
                "Failed to delete scheduled task '{}': {}",
                task_name, stderr
            ),
        )
        .with_result(ActionResult::Failed {
            reason: stderr.to_string(),
        });
        Ok(event)
    }
}

/// Scan and remove all matching scheduled task persistence entries.
pub fn remove_persistence_scheduled_tasks(
    target_name: &str,
    mode: OperatingMode,
) -> Result<Vec<AuditEvent>, OpenIceError> {
    let tasks = scan_scheduled_tasks(target_name)?;
    let mut events = Vec::new();

    if tasks.is_empty() {
        let event = AuditEvent::new(
            EventKind::PersistenceDetected,
            mode,
            "PersistenceMonitor",
            "ScanScheduledTasks",
            &format!(
                "No scheduled task persistence entries found for '{}'",
                target_name
            ),
        )
        .with_result(ActionResult::Skipped {
            reason: "No matching tasks found".to_string(),
        });
        events.push(event);
    } else {
        for task in &tasks {
            tracing::info!(
                "Found scheduled task: {} (command: {})",
                task.task_name,
                task.command
            );
            match delete_scheduled_task(&task.task_name, mode) {
                Ok(event) => events.push(event),
                Err(e) => {
                    tracing::error!("Failed to delete task {}: {}", task.task_name, e);
                }
            }
        }
    }

    Ok(events)
}
