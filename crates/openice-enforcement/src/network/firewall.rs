use std::path::Path;
use std::process::Command;

use openice_core::error::OpenIceError;
use openice_core::mode::OperatingMode;
use openice_core::telemetry::event::{
    ActionResult, AuditEvent, EventKind, RollbackEntry, UndoType,
};

const RULE_PREFIX: &str = "OpenICE_Block_";

/// Add a Windows Firewall outbound block rule for a specific executable.
pub fn block_outbound(
    executable_path: &Path,
    display_name: &str,
    mode: OperatingMode,
) -> Result<Vec<AuditEvent>, OpenIceError> {
    let rule_name = format!("{}{}", RULE_PREFIX, display_name.replace(' ', "_"));
    let exe_path_str = executable_path.to_string_lossy();

    // Check if rule already exists
    if rule_exists(&rule_name)? {
        let event = AuditEvent::new(
            EventKind::NetworkBlocked,
            mode,
            "NetworkIsolation",
            "BlockOutbound",
            &format!(
                "Firewall rule '{}' already exists for {}",
                rule_name, exe_path_str
            ),
        )
        .with_target(display_name, None, Some(executable_path.to_path_buf()))
        .with_result(ActionResult::Skipped {
            reason: "Rule already exists".to_string(),
        });
        return Ok(vec![event]);
    }

    let output = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={}", rule_name),
            "dir=out",
            &format!("program={}", exe_path_str),
            "action=block",
            "enable=yes",
        ])
        .output()
        .map_err(|e| {
            OpenIceError::NetworkError(format!("Failed to execute netsh: {}", e))
        })?;

    if output.status.success() {
        let mut event = AuditEvent::new(
            EventKind::NetworkBlocked,
            mode,
            "NetworkIsolation",
            "BlockOutbound",
            &format!(
                "Blocked outbound traffic for {} via firewall rule '{}'",
                exe_path_str, rule_name
            ),
        )
        .with_target(display_name, None, Some(executable_path.to_path_buf()));

        event.rollback_info = Some(RollbackEntry::new(
            event.id,
            UndoType::RemoveFirewallRule {
                rule_name: rule_name.clone(),
            },
            &format!("Remove firewall rule '{}'", rule_name),
        ));

        Ok(vec![event])
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let event = AuditEvent::new(
            EventKind::NetworkBlocked,
            mode,
            "NetworkIsolation",
            "BlockOutbound",
            &format!(
                "Failed to create firewall rule '{}': {}",
                rule_name, stderr
            ),
        )
        .with_target(display_name, None, Some(executable_path.to_path_buf()))
        .with_result(ActionResult::Failed {
            reason: stderr.to_string(),
        });
        Ok(vec![event])
    }
}

/// Remove a Windows Firewall rule by name.
pub fn unblock_outbound(
    rule_name: &str,
    mode: OperatingMode,
) -> Result<Vec<AuditEvent>, OpenIceError> {
    let output = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={}", rule_name),
        ])
        .output()
        .map_err(|e| {
            OpenIceError::NetworkError(format!("Failed to execute netsh: {}", e))
        })?;

    if output.status.success() {
        let event = AuditEvent::new(
            EventKind::NetworkUnblocked,
            mode,
            "NetworkIsolation",
            "UnblockOutbound",
            &format!("Removed firewall rule '{}'", rule_name),
        );
        Ok(vec![event])
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let event = AuditEvent::new(
            EventKind::NetworkUnblocked,
            mode,
            "NetworkIsolation",
            "UnblockOutbound",
            &format!("Failed to remove firewall rule '{}': {}", rule_name, stderr),
        )
        .with_result(ActionResult::Failed {
            reason: stderr.to_string(),
        });
        Ok(vec![event])
    }
}

/// Check if a firewall rule with the given name already exists.
fn rule_exists(rule_name: &str) -> Result<bool, OpenIceError> {
    let output = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "show",
            "rule",
            &format!("name={}", rule_name),
        ])
        .output()
        .map_err(|e| {
            OpenIceError::NetworkError(format!("Failed to query firewall rules: {}", e))
        })?;

    // If the rule exists, netsh returns success. If not, it returns an error.
    Ok(output.status.success())
}

/// List all OpenICE-created firewall rules.
pub fn list_openice_rules() -> Result<Vec<String>, OpenIceError> {
    let output = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "show",
            "rule",
            "name=all",
            "dir=out",
        ])
        .output()
        .map_err(|e| {
            OpenIceError::NetworkError(format!("Failed to list firewall rules: {}", e))
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut rules = Vec::new();

    for line in stdout.lines() {
        if let Some(name) = line.strip_prefix("Rule Name:") {
            let name = name.trim();
            if name.starts_with(RULE_PREFIX) {
                rules.push(name.to_string());
            }
        }
    }

    Ok(rules)
}
