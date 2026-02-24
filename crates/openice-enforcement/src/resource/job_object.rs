use openice_core::error::OpenIceError;
use openice_core::traits::ResourceLimits;

/// Apply resource limits to a process using Windows Job Objects.
/// Stub implementation for Phase 2+.
pub fn apply_resource_limits(_pid: u32, _limits: &ResourceLimits) -> Result<(), OpenIceError> {
    Err(OpenIceError::NotImplemented(
        "Resource governance via Job Objects is not yet implemented (Phase 2)".to_string(),
    ))
}

/// Remove resource limits from a process.
pub fn remove_resource_limits(_pid: u32) -> Result<(), OpenIceError> {
    Err(OpenIceError::NotImplemented(
        "Resource governance removal is not yet implemented (Phase 2)".to_string(),
    ))
}
