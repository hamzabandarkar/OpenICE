use openice_core::error::OpenIceError;

/// Windows service monitoring for persistence detection.
/// Stub implementation for Phase 2+.
pub fn scan_services(_target_name: &str) -> Result<Vec<String>, OpenIceError> {
    Err(OpenIceError::NotImplemented(
        "Service monitoring is not yet implemented (Phase 2)".to_string(),
    ))
}

pub fn remove_service(_service_name: &str) -> Result<(), OpenIceError> {
    Err(OpenIceError::NotImplemented(
        "Service removal is not yet implemented (Phase 2)".to_string(),
    ))
}
