use std::fs;
use std::path::PathBuf;

use openice_core::error::OpenIceError;
use openice_core::mode::OperatingMode;
use openice_core::telemetry::event::{
    ActionResult, AuditEvent, EventKind, RollbackEntry, UndoType,
};

/// A file found in a startup folder.
#[derive(Debug, Clone)]
pub struct StartupEntry {
    pub path: PathBuf,
    pub file_name: String,
}

/// Get the paths to user and system startup folders.
fn get_startup_folders() -> Vec<PathBuf> {
    let mut folders = Vec::new();

    // User startup folder
    if let Ok(appdata) = std::env::var("APPDATA") {
        folders.push(
            PathBuf::from(appdata)
                .join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs")
                .join("Startup"),
        );
    }

    // All-users startup folder
    if let Ok(programdata) = std::env::var("ProgramData") {
        folders.push(
            PathBuf::from(programdata)
                .join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs")
                .join("Startup"),
        );
    }

    folders
}

/// Scan startup folders for entries matching a target name.
pub fn scan_startup_folders(target_name: &str) -> Result<Vec<StartupEntry>, OpenIceError> {
    let folders = get_startup_folders();
    let target_lower = target_name.to_lowercase();
    let mut entries = Vec::new();

    for folder in folders {
        if !folder.exists() {
            continue;
        }

        let dir_entries = fs::read_dir(&folder).map_err(|e| {
            OpenIceError::PersistenceError(format!(
                "Failed to read startup folder {}: {}",
                folder.display(),
                e
            ))
        })?;

        for entry in dir_entries {
            let entry = entry.map_err(|e| {
                OpenIceError::PersistenceError(format!("Failed to read directory entry: {}", e))
            })?;

            let file_name = entry.file_name().to_string_lossy().to_string();
            if file_name.to_lowercase().contains(&target_lower) {
                entries.push(StartupEntry {
                    path: entry.path(),
                    file_name,
                });
            }
        }
    }

    Ok(entries)
}

/// Remove a startup folder entry.
pub fn remove_startup_entry(
    entry: &StartupEntry,
    mode: OperatingMode,
) -> Result<AuditEvent, OpenIceError> {
    match fs::remove_file(&entry.path) {
        Ok(()) => {
            let mut event = AuditEvent::new(
                EventKind::PersistenceRemoved,
                mode,
                "PersistenceMonitor",
                "RemoveStartupEntry",
                &format!("Removed startup entry: {}", entry.path.display()),
            );
            event.rollback_info = Some(RollbackEntry::new(
                event.id,
                UndoType::RestoreStartupShortcut {
                    path: entry.path.clone(),
                },
                &format!("Restore startup shortcut '{}'", entry.file_name),
            ));
            Ok(event)
        }
        Err(e) => {
            let event = AuditEvent::new(
                EventKind::PersistenceRemoved,
                mode,
                "PersistenceMonitor",
                "RemoveStartupEntry",
                &format!(
                    "Failed to remove startup entry {}: {}",
                    entry.path.display(),
                    e
                ),
            )
            .with_result(ActionResult::Failed {
                reason: e.to_string(),
            });
            Ok(event)
        }
    }
}

/// Scan and remove all matching startup folder persistence entries.
pub fn remove_persistence_startup(
    target_name: &str,
    mode: OperatingMode,
) -> Result<Vec<AuditEvent>, OpenIceError> {
    let entries = scan_startup_folders(target_name)?;
    let mut events = Vec::new();

    if entries.is_empty() {
        let event = AuditEvent::new(
            EventKind::PersistenceDetected,
            mode,
            "PersistenceMonitor",
            "ScanStartupFolders",
            &format!(
                "No startup folder persistence entries found for '{}'",
                target_name
            ),
        )
        .with_result(ActionResult::Skipped {
            reason: "No matching entries found".to_string(),
        });
        events.push(event);
    } else {
        for entry in &entries {
            tracing::info!(
                "Found startup entry: {} at {}",
                entry.file_name,
                entry.path.display()
            );
            match remove_startup_entry(entry, mode) {
                Ok(event) => events.push(event),
                Err(e) => {
                    tracing::error!("Failed to remove {}: {}", entry.path.display(), e);
                }
            }
        }
    }

    Ok(events)
}
