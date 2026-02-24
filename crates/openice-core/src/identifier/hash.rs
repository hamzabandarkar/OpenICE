use sha2::{Digest, Sha256};
use std::fs;

use crate::error::OpenIceError;
use crate::policy::model::IdentifierRule;
use crate::traits::{IdentifierMatcher, MatchResult, ProcessInfo};

/// Matches processes by SHA-256 hash of their executable.
pub struct HashMatcher;

impl HashMatcher {
    pub fn new() -> Self {
        Self
    }

    /// Compute SHA-256 hash of a file.
    pub fn compute_sha256(path: &std::path::Path) -> Result<String, OpenIceError> {
        let data = fs::read(path).map_err(|e| {
            OpenIceError::IdentifierError(format!(
                "Failed to read file for hashing {}: {}",
                path.display(),
                e
            ))
        })?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let result = hasher.finalize();
        Ok(format!("{:x}", result))
    }
}

impl IdentifierMatcher for HashMatcher {
    fn name(&self) -> &str {
        "hash"
    }

    fn matches(
        &self,
        process_info: &ProcessInfo,
        rule: &IdentifierRule,
    ) -> Result<MatchResult, OpenIceError> {
        if let IdentifierRule::Hash { value, .. } = rule {
            let file_hash = match Self::compute_sha256(&process_info.executable_path) {
                Ok(h) => h,
                Err(_) => return Ok(MatchResult::NoMatch),
            };

            if file_hash.eq_ignore_ascii_case(value) {
                Ok(MatchResult::Match {
                    confidence: 1.0,
                    reason: format!(
                        "SHA-256 hash match: {} ({})",
                        &file_hash[..16],
                        process_info.executable_path.display()
                    ),
                })
            } else {
                Ok(MatchResult::NoMatch)
            }
        } else {
            Ok(MatchResult::NoMatch)
        }
    }
}
