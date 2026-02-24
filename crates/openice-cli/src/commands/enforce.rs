use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};

use openice_core::mode::OperatingMode;
use openice_core::policy::loader;
use openice_core::telemetry::logger::AuditLogger;
use openice_core::telemetry::sink::{ConsoleSink, FileSink};
use openice_engine::orchestrator;
use openice_core::identifier;

pub async fn run(
    config_dir: &Path,
    mode_str: &str,
    interval_secs: u64,
    once: bool,
    policy_filter: Option<&str>,
    dry_run: bool,
    log_file: Option<&Path>,
) -> Result<()> {
    let mode: OperatingMode = mode_str
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    let policies = loader::load_policies_from_dir(config_dir)?;

    if policies.is_empty() {
        anyhow::bail!("No policies loaded from {}", config_dir.display());
    }

    let filtered: Vec<_> = if let Some(filter) = policy_filter {
        policies
            .into_iter()
            .filter(|p| p.profile_name.eq_ignore_ascii_case(filter))
            .collect()
    } else {
        policies
    };

    // Set up audit logging
    let mut logger = AuditLogger::new();
    logger.add_sink(Box::new(ConsoleSink::new()));

    if let Some(path) = log_file {
        let sink = FileSink::new(path.to_path_buf())
            .context("Failed to create log file sink")?;
        logger.add_sink(Box::new(sink));
    } else {
        // Default log location
        let default_path = openice_engine::rollback::rollback_file_path()
            .parent()
            .map(|p| p.join("audit.jsonl"))
            .unwrap_or_else(|| std::path::PathBuf::from("audit.jsonl"));
        if let Ok(sink) = FileSink::new(default_path) {
            logger.add_sink(Box::new(sink));
        }
    }

    println!(
        "OpenICE enforcement starting [mode: {}, interval: {}s, dry_run: {}, policies: {}]",
        mode,
        interval_secs,
        dry_run,
        filtered.len()
    );

    if dry_run {
        println!("DRY RUN: No enforcement actions will be executed.");
    }

    println!();

    if once {
        let matchers = identifier::create_all_matchers();
        orchestrator::run_enforcement_pass(&filtered, mode, &matchers, &logger, dry_run)?;
    } else {
        println!("Press Ctrl+C to stop.");
        println!();

        orchestrator::run_enforcement_loop(
            &filtered,
            mode,
            Duration::from_secs(interval_secs),
            dry_run,
            &logger,
        )
        .await?;
    }

    Ok(())
}
