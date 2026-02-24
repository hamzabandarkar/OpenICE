use openice_core::mode::OperatingMode;
use openice_core::policy::model::Policy;
use openice_core::traits::{EnforcementAction, PersistenceType};

/// Determine what enforcement actions to take given a mode and policy.
pub fn plan_actions(mode: OperatingMode, policy: &Policy) -> Vec<EnforcementAction> {
    match mode {
        OperatingMode::Observe => {
            // Observe mode: no enforcement actions, just logging
            vec![]
        }
        OperatingMode::Contain => {
            let config = &policy.enforcement.modes.contain;
            let mut actions = Vec::new();

            if config.block_network {
                actions.push(EnforcementAction::BlockOutboundNetwork);
            }
            if config.block_child_shells {
                actions.push(EnforcementAction::BlockChildShells);
            }
            if config.limit_cpu_percent.is_some() || config.limit_memory_mb.is_some() {
                actions.push(EnforcementAction::LimitResources(
                    openice_core::traits::ResourceLimits {
                        cpu_percent: config.limit_cpu_percent,
                        memory_mb: config.limit_memory_mb,
                    },
                ));
            }

            actions
        }
        OperatingMode::Quarantine => {
            let config = &policy.enforcement.modes.quarantine;
            let mut actions = Vec::new();

            if config.kill_process_tree {
                actions.push(EnforcementAction::KillProcessTree);
            }
            if config.block_network {
                actions.push(EnforcementAction::BlockOutboundNetwork);
            }
            if config.remove_persistence {
                actions.push(EnforcementAction::RemovePersistence(PersistenceType::All));
            }

            actions
        }
        OperatingMode::Lockdown => {
            vec![
                EnforcementAction::BlockLaunch,
                EnforcementAction::KillProcessTree,
                EnforcementAction::BlockOutboundNetwork,
                EnforcementAction::RemovePersistence(PersistenceType::All),
            ]
        }
    }
}
