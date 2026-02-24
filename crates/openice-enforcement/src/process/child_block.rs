use openice_core::error::OpenIceError;
use openice_core::telemetry::event::{ActionResult, AuditEvent, EventKind};
use openice_core::mode::OperatingMode;

/// Block child shell processes spawned by a target.
/// Stub implementation for Phase 1 — will use Job Objects or ETW in later phases.
pub fn block_child_shells(
    _parent_pid: u32,
    parent_name: &str,
    mode: OperatingMode,
) -> Result<Vec<AuditEvent>, OpenIceError> {
    let event = AuditEvent::new(
        EventKind::ChildProcessBlocked,
        mode,
        "ProcessControl",
        "BlockChildShells",
        &format!(
            "Child shell blocking not yet implemented for {}",
            parent_name
        ),
    )
    .with_result(ActionResult::Skipped {
        reason: "Not yet implemented (Phase 2)".to_string(),
    });

    Ok(vec![event])
}
