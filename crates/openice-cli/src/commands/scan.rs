use std::path::Path;

use anyhow::Result;

use openice_core::identifier;
use openice_core::policy::loader;
use openice_core::policy::resolver;
use openice_engine::scanner;

pub async fn run(
    config_dir: &Path,
    policy_filter: Option<&str>,
    json_output: bool,
    _dry_run: bool,
) -> Result<()> {
    let policies = loader::load_policies_from_dir(config_dir)?;

    if policies.is_empty() {
        eprintln!("No policies loaded from {}", config_dir.display());
        eprintln!("Add policy files (.json) to the config directory.");
        return Ok(());
    }

    let filtered: Vec<_> = if let Some(filter) = policy_filter {
        policies
            .into_iter()
            .filter(|p| p.profile_name.eq_ignore_ascii_case(filter))
            .collect()
    } else {
        policies
    };

    println!("Scanning processes against {} policy(ies)...", filtered.len());
    println!();

    let processes = scanner::scan_all_processes()?;
    let matchers = identifier::create_all_matchers();

    let mut match_count = 0;

    for proc_info in &processes {
        let matches = resolver::resolve_matching_policies(proc_info, &filtered, &matchers)?;

        for policy_match in &matches {
            match_count += 1;

            if json_output {
                let output = serde_json::json!({
                    "pid": proc_info.pid,
                    "name": proc_info.name,
                    "path": proc_info.executable_path,
                    "command_line": proc_info.command_line,
                    "policy": policy_match.policy_name,
                    "mode": policy_match.mode.to_string(),
                    "match_details": policy_match.match_details.iter().map(|d| {
                        serde_json::json!({
                            "matcher": d.matcher_name,
                            "confidence": d.confidence,
                            "reason": d.reason,
                        })
                    }).collect::<Vec<_>>(),
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!(
                    "MATCH: {} (PID {}) -> policy '{}' [mode: {}]",
                    proc_info.name,
                    proc_info.pid,
                    policy_match.policy_name,
                    policy_match.mode,
                );
                for detail in &policy_match.match_details {
                    println!(
                        "  - [{}] {} (confidence: {:.0}%)",
                        detail.matcher_name,
                        detail.reason,
                        detail.confidence * 100.0,
                    );
                }
                println!();
            }
        }
    }

    if match_count == 0 {
        println!("No matching processes found.");
    } else {
        println!("Found {} match(es) across {} processes.", match_count, processes.len());
    }

    Ok(())
}
