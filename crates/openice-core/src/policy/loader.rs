use std::path::Path;

use crate::error::OpenIceError;
use crate::policy::model::Policy;

/// Load a single policy from a JSON file.
pub fn load_policy(path: &Path) -> Result<Policy, OpenIceError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        OpenIceError::PolicyError(format!("Failed to read policy file {}: {}", path.display(), e))
    })?;

    let policy: Policy = serde_json::from_str(&content).map_err(|e| {
        OpenIceError::PolicyError(format!(
            "Failed to parse policy file {}: {}",
            path.display(),
            e
        ))
    })?;

    validate_policy(&policy)?;
    Ok(policy)
}

/// Load all policy JSON files from a directory.
pub fn load_policies_from_dir(dir: &Path) -> Result<Vec<Policy>, OpenIceError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut policies = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|e| {
        OpenIceError::PolicyError(format!(
            "Failed to read policy directory {}: {}",
            dir.display(),
            e
        ))
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| {
            OpenIceError::PolicyError(format!("Failed to read directory entry: {}", e))
        })?;

        let path = entry.path();
        if path.extension().map_or(false, |ext| ext == "json") {
            match load_policy(&path) {
                Ok(policy) => {
                    if policy.enabled {
                        tracing::info!(
                            "Loaded policy '{}' from {}",
                            policy.profile_name,
                            path.display()
                        );
                        policies.push(policy);
                    } else {
                        tracing::info!(
                            "Skipping disabled policy '{}' from {}",
                            policy.profile_name,
                            path.display()
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to load policy from {}: {}", path.display(), e);
                }
            }
        }
    }

    // Sort by priority (higher priority first)
    policies.sort_by(|a, b| b.priority.cmp(&a.priority));
    Ok(policies)
}

/// Validate a policy for correctness.
pub fn validate_policy(policy: &Policy) -> Result<(), OpenIceError> {
    if policy.profile_name.is_empty() {
        return Err(OpenIceError::PolicyError(
            "Policy profile_name cannot be empty".to_string(),
        ));
    }

    if policy.identifiers.rules.is_empty() {
        return Err(OpenIceError::PolicyError(format!(
            "Policy '{}' has no identifier rules",
            policy.profile_name
        )));
    }

    // Validate enforcement mode name
    let valid_modes = ["observe", "contain", "quarantine", "lockdown"];
    if !valid_modes.contains(&policy.enforcement.default_mode.as_str()) {
        return Err(OpenIceError::PolicyError(format!(
            "Policy '{}' has invalid default_mode '{}'. Expected one of: {}",
            policy.profile_name,
            policy.enforcement.default_mode,
            valid_modes.join(", ")
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_empty_name() {
        let policy = Policy {
            profile_name: String::new(),
            description: String::new(),
            version: 1,
            priority: 100,
            enabled: true,
            identifiers: crate::policy::model::IdentifierConfig {
                match_mode: crate::policy::model::MatchMode::Any,
                rules: vec![crate::policy::model::IdentifierRule::ProcessName {
                    value: "test.exe".to_string(),
                }],
            },
            enforcement: crate::policy::model::EnforcementConfig {
                default_mode: "quarantine".to_string(),
                modes: Default::default(),
            },
            metadata: Default::default(),
        };
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn test_validate_no_rules() {
        let policy = Policy {
            profile_name: "test".to_string(),
            description: String::new(),
            version: 1,
            priority: 100,
            enabled: true,
            identifiers: crate::policy::model::IdentifierConfig {
                match_mode: crate::policy::model::MatchMode::Any,
                rules: vec![],
            },
            enforcement: crate::policy::model::EnforcementConfig {
                default_mode: "quarantine".to_string(),
                modes: Default::default(),
            },
            metadata: Default::default(),
        };
        assert!(validate_policy(&policy).is_err());
    }
}
