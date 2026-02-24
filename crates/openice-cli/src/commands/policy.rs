use std::path::Path;

use anyhow::Result;

use openice_core::policy::loader;

pub async fn add(file: &Path) -> Result<()> {
    let policy = loader::load_policy(file)?;
    println!(
        "Policy '{}' loaded and validated successfully from {}",
        policy.profile_name,
        file.display()
    );
    println!("  Description: {}", policy.description);
    println!("  Priority: {}", policy.priority);
    println!("  Default mode: {}", policy.enforcement.default_mode);
    println!("  Identifier rules: {}", policy.identifiers.rules.len());
    println!();
    println!(
        "To use this policy, copy it to your config directory or specify it with --config."
    );
    Ok(())
}

pub async fn remove(name: &str) -> Result<()> {
    println!(
        "Policy removal requires deleting the policy file from the config directory."
    );
    println!("Look for a file with profile_name '{}' in your config directory.", name);
    Ok(())
}

pub async fn list(config_dir: &Path) -> Result<()> {
    let policies = loader::load_policies_from_dir(config_dir)?;

    if policies.is_empty() {
        println!("No policies found in {}", config_dir.display());
        return Ok(());
    }

    println!(
        "Loaded {} policy(ies) from {}:",
        policies.len(),
        config_dir.display()
    );
    println!();

    for policy in &policies {
        println!(
            "  {} [priority: {}, mode: {}, rules: {}, enabled: {}]",
            policy.profile_name,
            policy.priority,
            policy.enforcement.default_mode,
            policy.identifiers.rules.len(),
            policy.enabled,
        );
        if !policy.description.is_empty() {
            println!("    {}", policy.description);
        }
    }

    Ok(())
}

pub async fn validate(file: &Path) -> Result<()> {
    match loader::load_policy(file) {
        Ok(policy) => {
            println!("Policy '{}' is valid.", policy.profile_name);
            println!("  Version: {}", policy.version);
            println!("  Priority: {}", policy.priority);
            println!("  Default mode: {}", policy.enforcement.default_mode);
            println!("  Match mode: {:?}", policy.identifiers.match_mode);
            println!("  Identifier rules: {}", policy.identifiers.rules.len());
            for (i, rule) in policy.identifiers.rules.iter().enumerate() {
                println!("    {}. {:?}", i + 1, rule);
            }
        }
        Err(e) => {
            eprintln!("Policy validation FAILED: {}", e);
            std::process::exit(1);
        }
    }
    Ok(())
}

pub async fn show(config_dir: &Path, name: &str) -> Result<()> {
    let policies = loader::load_policies_from_dir(config_dir)?;

    let policy = policies
        .iter()
        .find(|p| p.profile_name.eq_ignore_ascii_case(name));

    match policy {
        Some(policy) => {
            let json = serde_json::to_string_pretty(policy)?;
            println!("{}", json);
        }
        None => {
            eprintln!("Policy '{}' not found.", name);
            eprintln!(
                "Available policies: {}",
                policies
                    .iter()
                    .map(|p| p.profile_name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            std::process::exit(1);
        }
    }

    Ok(())
}
