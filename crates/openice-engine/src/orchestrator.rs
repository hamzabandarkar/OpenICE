use std::time::Duration;

use openice_core::error::OpenIceError;
use openice_core::identifier;
use openice_core::mode::OperatingMode;
use openice_core::policy::model::Policy;
use openice_core::policy::resolver;
use openice_core::telemetry::event::{ActionResult, AuditEvent, EventKind};
use openice_core::telemetry::logger::AuditLogger;
use openice_core::traits::{EnforcementAction, EnforcementTarget, IdentifierMatcher, PersistenceType};

use openice_enforcement::network::firewall;
use openice_enforcement::persistence;
use openice_enforcement::process::kill;

use crate::action;
use crate::rollback;
use crate::scanner;

/// Run a single enforcement pass: scan, match, plan, enforce, log.
pub fn run_enforcement_pass(
    policies: &[Policy],
    mode: OperatingMode,
    matchers: &[Box<dyn IdentifierMatcher>],
    logger: &AuditLogger,
    dry_run: bool,
) -> Result<(), OpenIceError> {
    let processes = scanner::scan_all_processes()?;

    let scan_event = AuditEvent::new(
        EventKind::ScanCompleted,
        mode,
        "Engine",
        "ScanProcesses",
        &format!("Scanned {} running processes", processes.len()),
    );
    logger.emit(&scan_event);

    for proc_info in &processes {
        let matches = resolver::resolve_matching_policies(proc_info, policies, matchers)?;

        for policy_match in &matches {
            let effective_mode = resolver::effective_mode(policy_match, Some(mode));

            let detect_event = AuditEvent::new(
                EventKind::ProcessDetected,
                effective_mode,
                "Engine",
                "PolicyMatch",
                &format!(
                    "Process '{}' (PID {}) matched policy '{}'",
                    proc_info.name, proc_info.pid, policy_match.policy_name
                ),
            )
            .with_target(
                &proc_info.name,
                Some(proc_info.pid),
                Some(proc_info.executable_path.clone()),
            );
            logger.emit(&detect_event);

            let actions = action::plan_actions(effective_mode, &policy_match.policy);

            for enforcement_action in &actions {
                if dry_run {
                    let event = AuditEvent::new(
                        EventKind::ProcessDetected,
                        effective_mode,
                        "Engine",
                        &format!("{:?}", enforcement_action),
                        &format!(
                            "[DRY RUN] Would execute {:?} on {} (PID {})",
                            enforcement_action, proc_info.name, proc_info.pid
                        ),
                    )
                    .with_target(
                        &proc_info.name,
                        Some(proc_info.pid),
                        Some(proc_info.executable_path.clone()),
                    )
                    .with_result(ActionResult::DryRun);
                    logger.emit(&event);
                    continue;
                }

                let target = EnforcementTarget::from_process_info(proc_info);
                let events = execute_action(enforcement_action, &target, effective_mode)?;

                for event in &events {
                    logger.emit(event);
                    if let Some(ref rb) = event.rollback_info {
                        if let Err(e) = rollback::record_rollback(rb) {
                            tracing::error!("Failed to record rollback: {}", e);
                        }
                    }
                }
            }
        }
    }

    logger.flush()?;
    Ok(())
}

/// Execute a single enforcement action.
fn execute_action(
    action: &EnforcementAction,
    target: &EnforcementTarget,
    mode: OperatingMode,
) -> Result<Vec<AuditEvent>, OpenIceError> {
    match action {
        EnforcementAction::KillProcessTree => {
            if let Some(pid) = target.pid {
                Ok(kill::kill_process_tree(pid, &target.display_name, mode))
            } else {
                Ok(vec![AuditEvent::new(
                    EventKind::Error,
                    mode,
                    "Engine",
                    "KillProcessTree",
                    "Cannot kill process tree: no PID available",
                )
                .with_result(ActionResult::Failed {
                    reason: "No PID".to_string(),
                })])
            }
        }

        EnforcementAction::BlockOutboundNetwork => {
            if let Some(ref path) = target.executable_path {
                firewall::block_outbound(path, &target.display_name, mode)
            } else {
                Ok(vec![AuditEvent::new(
                    EventKind::Error,
                    mode,
                    "Engine",
                    "BlockOutbound",
                    "Cannot block network: no executable path available",
                )
                .with_result(ActionResult::Failed {
                    reason: "No executable path".to_string(),
                })])
            }
        }

        EnforcementAction::UnblockOutboundNetwork => {
            let rule_name = format!(
                "OpenICE_Block_{}",
                target.display_name.replace(' ', "_")
            );
            firewall::unblock_outbound(&rule_name, mode)
        }

        EnforcementAction::RemovePersistence(persistence_type) => match persistence_type {
            PersistenceType::All => {
                persistence::remove_all_persistence(&target.display_name, mode)
            }
            PersistenceType::RegistryRunKey => {
                persistence::registry::remove_persistence_registry(&target.display_name, mode)
            }
            PersistenceType::ScheduledTask => {
                persistence::scheduled_tasks::remove_persistence_scheduled_tasks(
                    &target.display_name,
                    mode,
                )
            }
            PersistenceType::StartupFolder => {
                persistence::startup_folder::remove_persistence_startup(&target.display_name, mode)
            }
            PersistenceType::Service => {
                let event = AuditEvent::new(
                    EventKind::PersistenceRemoved,
                    mode,
                    "PersistenceMonitor",
                    "RemoveService",
                    "Service persistence removal not yet implemented",
                )
                .with_result(ActionResult::Skipped {
                    reason: "Not yet implemented (Phase 2)".to_string(),
                });
                Ok(vec![event])
            }
        },

        EnforcementAction::LimitResources(_limits) => {
            let event = AuditEvent::new(
                EventKind::ResourceLimited,
                mode,
                "ResourceGovernance",
                "LimitResources",
                "Resource limiting not yet implemented",
            )
            .with_result(ActionResult::Skipped {
                reason: "Not yet implemented (Phase 2)".to_string(),
            });
            Ok(vec![event])
        }

        EnforcementAction::BlockLaunch => {
            let event = AuditEvent::new(
                EventKind::LaunchBlocked,
                mode,
                "Lockdown",
                "BlockLaunch",
                "Launch blocking via WDAC/AppLocker not yet implemented",
            )
            .with_result(ActionResult::Skipped {
                reason: "Not yet implemented (Phase 3)".to_string(),
            });
            Ok(vec![event])
        }

        EnforcementAction::BlockChildShells => {
            if let Some(pid) = target.pid {
                openice_enforcement::process::child_block::block_child_shells(
                    pid,
                    &target.display_name,
                    mode,
                )
            } else {
                Ok(vec![AuditEvent::new(
                    EventKind::Error,
                    mode,
                    "Engine",
                    "BlockChildShells",
                    "Cannot block child shells: no PID available",
                )
                .with_result(ActionResult::Failed {
                    reason: "No PID".to_string(),
                })])
            }
        }
    }
}

/// Run the enforcement loop continuously.
pub async fn run_enforcement_loop(
    policies: &[Policy],
    mode: OperatingMode,
    interval: Duration,
    dry_run: bool,
    logger: &AuditLogger,
) -> Result<(), OpenIceError> {
    let matchers = identifier::create_all_matchers();

    loop {
        if let Err(e) = run_enforcement_pass(policies, mode, &matchers, logger, dry_run) {
            tracing::error!("Enforcement pass failed: {}", e);
        }

        tokio::time::sleep(interval).await;
    }
}
