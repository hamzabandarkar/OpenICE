use openice_core::error::OpenIceError;

/// Generate AppLocker deny rules for an executable.
/// Stub implementation for Phase 3+.
pub fn generate_deny_rule(
    _executable_path: &std::path::Path,
    _hash: Option<&str>,
) -> Result<String, OpenIceError> {
    Err(OpenIceError::NotImplemented(
        "AppLocker rule generation is not yet implemented (Phase 3)".to_string(),
    ))
}

pub fn apply_rules(_rules_xml: &str) -> Result<(), OpenIceError> {
    Err(OpenIceError::NotImplemented(
        "AppLocker rule deployment is not yet implemented (Phase 3)".to_string(),
    ))
}

pub fn rollback_rules() -> Result<(), OpenIceError> {
    Err(OpenIceError::NotImplemented(
        "AppLocker rule rollback is not yet implemented (Phase 3)".to_string(),
    ))
}
