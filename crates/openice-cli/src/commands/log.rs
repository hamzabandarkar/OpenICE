use std::io::{BufRead, Write};
use std::path::Path;

use anyhow::Result;

use openice_core::telemetry::event::AuditEvent;

fn get_default_log_path() -> std::path::PathBuf {
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        std::path::PathBuf::from(local_app_data)
            .join("OpenICE")
            .join("logs")
            .join("audit.jsonl")
    } else {
        std::path::PathBuf::from("audit.jsonl")
    }
}

pub async fn run(
    tail: usize,
    export: Option<&Path>,
    json_output: bool,
    filter: Option<&str>,
) -> Result<()> {
    let log_path = get_default_log_path();

    // Also check the rollback directory for audit logs
    let alt_path = openice_engine::rollback::rollback_file_path()
        .parent()
        .map(|p| p.join("audit.jsonl"));

    let effective_path = if log_path.exists() {
        log_path
    } else if let Some(ref alt) = alt_path {
        if alt.exists() {
            alt.clone()
        } else {
            println!("No audit log found.");
            println!("Expected at: {}", log_path.display());
            return Ok(());
        }
    } else {
        println!("No audit log found.");
        return Ok(());
    };

    let file = std::fs::File::open(&effective_path)?;
    let reader = std::io::BufReader::new(file);

    let mut entries: Vec<AuditEvent> = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        match serde_json::from_str::<AuditEvent>(&line) {
            Ok(event) => {
                if let Some(kind_filter) = filter {
                    let kind_str = format!("{:?}", event.kind).to_lowercase();
                    if !kind_str.contains(&kind_filter.to_lowercase()) {
                        continue;
                    }
                }
                entries.push(event);
            }
            Err(e) => {
                tracing::debug!("Skipping malformed log entry: {}", e);
            }
        }
    }

    // Handle export
    if let Some(export_path) = export {
        let mut file = std::fs::File::create(export_path)?;
        for entry in &entries {
            let json = serde_json::to_string(entry)?;
            writeln!(file, "{}", json)?;
        }
        println!(
            "Exported {} entries to {}",
            entries.len(),
            export_path.display()
        );
        return Ok(());
    }

    // Display tail entries
    let start = if entries.len() > tail {
        entries.len() - tail
    } else {
        0
    };

    if entries.is_empty() {
        println!("Audit log is empty.");
        return Ok(());
    }

    println!(
        "Showing {} of {} total entries from {}:",
        entries.len() - start,
        entries.len(),
        effective_path.display()
    );
    println!();

    for event in &entries[start..] {
        if json_output {
            println!("{}", serde_json::to_string_pretty(event)?);
        } else {
            let timestamp = event.timestamp.format("%Y-%m-%d %H:%M:%S");
            let target = event
                .target_process
                .as_deref()
                .unwrap_or("-");
            let _pid = event
                .target_pid
                .map(|p| format!("PID {}", p))
                .unwrap_or_else(|| "-".to_string());

            println!(
                "[{}] {:?} | {} | {} | {} | {}",
                timestamp, event.kind, event.backend, event.action, target, event.details
            );
        }
    }

    Ok(())
}
