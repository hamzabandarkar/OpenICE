use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::error::OpenIceError;
use crate::telemetry::event::{ActionResult, AuditEvent};

/// Trait for audit event sinks.
pub trait TelemetrySink: Send + Sync {
    fn emit(&self, event: &AuditEvent);
    fn flush(&self) -> Result<(), OpenIceError>;
}

/// Writes audit events to the console with human-readable formatting.
pub struct ConsoleSink;

impl ConsoleSink {
    pub fn new() -> Self {
        Self
    }
}

impl TelemetrySink for ConsoleSink {
    fn emit(&self, event: &AuditEvent) {
        let timestamp = event.timestamp.format("%H:%M:%S");
        let result_marker = match &event.result {
            ActionResult::Success => "+",
            ActionResult::Failed { .. } => "!",
            ActionResult::Skipped { .. } => "-",
            ActionResult::DryRun => "~",
        };

        let target = event
            .target_process
            .as_deref()
            .unwrap_or("unknown");

        let pid_str = event
            .target_pid
            .map(|p| format!(" (PID {})", p))
            .unwrap_or_default();

        println!(
            "[{}] [{}] {} {}{}: {}",
            timestamp, result_marker, event.action, target, pid_str, event.details
        );
    }

    fn flush(&self) -> Result<(), OpenIceError> {
        Ok(())
    }
}

/// Writes audit events as JSON lines to a file.
pub struct FileSink {
    path: PathBuf,
    file: Mutex<Option<std::fs::File>>,
}

impl FileSink {
    pub fn new(path: PathBuf) -> Result<Self, OpenIceError> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                OpenIceError::Other(format!(
                    "Failed to create log directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| {
                OpenIceError::Other(format!(
                    "Failed to open audit log file {}: {}",
                    path.display(),
                    e
                ))
            })?;

        Ok(Self {
            path,
            file: Mutex::new(Some(file)),
        })
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

impl TelemetrySink for FileSink {
    fn emit(&self, event: &AuditEvent) {
        if let Ok(mut guard) = self.file.lock() {
            if let Some(ref mut file) = *guard {
                if let Ok(json) = serde_json::to_string(event) {
                    let _ = writeln!(file, "{}", json);
                }
            }
        }
    }

    fn flush(&self) -> Result<(), OpenIceError> {
        if let Ok(mut guard) = self.file.lock() {
            if let Some(ref mut file) = *guard {
                file.flush().map_err(|e| {
                    OpenIceError::Other(format!("Failed to flush audit log: {}", e))
                })?;
            }
        }
        Ok(())
    }
}
