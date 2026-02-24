use openice_core::error::OpenIceError;

/// Windows Filtering Platform (WFP) based network filtering.
/// Stub implementation for Phase 2+.
///
/// WFP provides per-process granularity for network filtering without
/// shelling out to netsh. This will be the preferred backend once implemented.
pub fn block_outbound_wfp(
    _executable_path: &std::path::Path,
    _display_name: &str,
) -> Result<(), OpenIceError> {
    Err(OpenIceError::NotImplemented(
        "WFP-based network filtering is not yet implemented. Using netsh backend.".to_string(),
    ))
}

pub fn unblock_outbound_wfp(_rule_id: &str) -> Result<(), OpenIceError> {
    Err(OpenIceError::NotImplemented(
        "WFP-based network filtering is not yet implemented.".to_string(),
    ))
}
