pub mod registry;
pub mod scheduled_tasks;
pub mod services;
pub mod startup_folder;

use openice_core::error::OpenIceError;
use openice_core::mode::OperatingMode;
use openice_core::telemetry::event::AuditEvent;

/// Remove all persistence mechanisms for a target.
pub fn remove_all_persistence(
    target_name: &str,
    mode: OperatingMode,
) -> Result<Vec<AuditEvent>, OpenIceError> {
    let mut events = Vec::new();

    // Registry Run keys
    match registry::remove_persistence_registry(target_name, mode) {
        Ok(e) => events.extend(e),
        Err(e) => tracing::error!("Registry persistence scan failed: {}", e),
    }

    // Scheduled tasks
    match scheduled_tasks::remove_persistence_scheduled_tasks(target_name, mode) {
        Ok(e) => events.extend(e),
        Err(e) => tracing::error!("Scheduled task scan failed: {}", e),
    }

    // Startup folder
    match startup_folder::remove_persistence_startup(target_name, mode) {
        Ok(e) => events.extend(e),
        Err(e) => tracing::error!("Startup folder scan failed: {}", e),
    }

    // Services (stub - log but don't fail)
    match services::scan_services(target_name) {
        Ok(_) => {}
        Err(e) => tracing::debug!("Service scan: {}", e),
    }

    Ok(events)
}
