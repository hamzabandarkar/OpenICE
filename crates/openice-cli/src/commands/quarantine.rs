use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use openice_core::mode::OperatingMode;
use openice_core::telemetry::logger::AuditLogger;
use openice_core::telemetry::sink::{ConsoleSink, FileSink};
use openice_enforcement::network::firewall;
use openice_enforcement::persistence;
use openice_enforcement::process::kill;
use openice_engine::rollback;
use openice_engine::scanner;

pub async fn run(
    _config_dir: &Path,
    target: &str,
    dry_run: bool,
    log_file: Option<&Path>,
) -> Result<()> {
    let mode = OperatingMode::Quarantine;

    // Set up logging
    let mut logger = AuditLogger::new();
    logger.add_sink(Box::new(ConsoleSink::new()));

    if let Some(path) = log_file {
        let sink = FileSink::new(path.to_path_buf())
            .context("Failed to create log file sink")?;
        logger.add_sink(Box::new(sink));
    }

    println!("Quarantining target: {}", target);
    if dry_run {
        println!("DRY RUN: No actions will be executed.");
    }
    println!();

    // Find matching processes
    let processes = scanner::find_process(target)?;

    if processes.is_empty() {
        println!("No running processes found matching '{}'.", target);
        println!("Proceeding with network blocking and persistence removal...");
    } else {
        println!(
            "Found {} process(es) matching '{}':",
            processes.len(),
            target
        );
        for p in &processes {
            println!(
                "  PID {} - {} ({})",
                p.pid,
                p.name,
                p.executable_path.display()
            );
        }
        println!();
    }

    if dry_run {
        println!("[DRY RUN] Would kill {} process tree(s)", processes.len());
        println!("[DRY RUN] Would block outbound network");
        println!("[DRY RUN] Would remove persistence entries");
        return Ok(());
    }

    // Step 1: Kill process trees
    for proc_info in &processes {
        println!("Killing process tree for {} (PID {})...", proc_info.name, proc_info.pid);
        let events = kill::kill_process_tree(proc_info.pid, &proc_info.name, mode);
        for event in &events {
            logger.emit(event);
            if let Some(ref rb) = event.rollback_info {
                let _ = rollback::record_rollback(rb);
            }
        }
    }

    // Step 2: Block outbound network
    // Use the first matched process path, or try to construct from target name
    let exe_path = processes
        .first()
        .map(|p| p.executable_path.clone())
        .unwrap_or_else(|| PathBuf::from(target));

    if exe_path.exists() {
        let display_name = exe_path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| target.to_string());

        println!("Blocking outbound network for {}...", exe_path.display());
        let events = firewall::block_outbound(&exe_path, &display_name, mode)?;
        for event in &events {
            logger.emit(event);
            if let Some(ref rb) = event.rollback_info {
                let _ = rollback::record_rollback(rb);
            }
        }
    } else {
        println!(
            "Skipping network block: executable path not found for '{}'",
            target
        );
    }

    // Step 3: Remove persistence
    let persistence_name = processes
        .first()
        .map(|p| p.name.clone())
        .unwrap_or_else(|| target.to_string());

    println!("Removing persistence entries for '{}'...", persistence_name);
    let events = persistence::remove_all_persistence(&persistence_name, mode)?;
    for event in &events {
        logger.emit(event);
        if let Some(ref rb) = event.rollback_info {
            let _ = rollback::record_rollback(rb);
        }
    }

    println!();
    println!("Quarantine complete for '{}'.", target);
    println!("Use 'openice rollback' to undo reversible actions.");

    logger.flush()?;
    Ok(())
}
