use anyhow::Result;

use openice_enforcement::network::firewall;
use openice_engine::rollback;

pub async fn run() -> Result<()> {
    println!("OpenICE Status");
    println!("==============");
    println!();

    // Show active firewall rules
    println!("Active Firewall Rules:");
    match firewall::list_openice_rules() {
        Ok(rules) => {
            if rules.is_empty() {
                println!("  (none)");
            } else {
                for rule in &rules {
                    println!("  - {}", rule);
                }
            }
        }
        Err(e) => {
            println!("  Error querying rules: {}", e);
        }
    }
    println!();

    // Show rollback entries
    println!("Rollback History:");
    match rollback::load_rollback_entries() {
        Ok(entries) => {
            if entries.is_empty() {
                println!("  (none)");
            } else {
                let display_count = entries.len().min(10);
                for entry in entries.iter().rev().take(display_count) {
                    println!(
                        "  [{}] {} - {}",
                        entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
                        entry.action_id,
                        entry.description
                    );
                }
                if entries.len() > display_count {
                    println!("  ... and {} more", entries.len() - display_count);
                }
            }
        }
        Err(e) => {
            println!("  Error loading rollback history: {}", e);
        }
    }

    Ok(())
}
