use anyhow::Result;

use openice_core::telemetry::logger::AuditLogger;
use openice_core::telemetry::sink::ConsoleSink;
use openice_engine::rollback;

pub async fn run(last: usize, all: bool) -> Result<()> {
    let logger = {
        let mut l = AuditLogger::new();
        l.add_sink(Box::new(ConsoleSink::new()));
        l
    };

    let entries = rollback::load_rollback_entries()?;

    if entries.is_empty() {
        println!("No rollback entries found.");
        return Ok(());
    }

    let count = if all { entries.len() } else { last };
    println!("Rolling back {} action(s)...", count.min(entries.len()));
    println!();

    let events = rollback::rollback_last(count)?;

    for event in &events {
        logger.emit(event);
    }

    println!();
    println!("Rollback complete. {} action(s) processed.", events.len());

    Ok(())
}
