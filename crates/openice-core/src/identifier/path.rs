use crate::error::OpenIceError;
use crate::policy::model::IdentifierRule;
use crate::traits::{IdentifierMatcher, MatchResult, ProcessInfo};

/// Matches processes by executable path using glob patterns.
pub struct PathMatcher;

impl PathMatcher {
    pub fn new() -> Self {
        Self
    }
}

impl IdentifierMatcher for PathMatcher {
    fn name(&self) -> &str {
        "path"
    }

    fn matches(
        &self,
        process_info: &ProcessInfo,
        rule: &IdentifierRule,
    ) -> Result<MatchResult, OpenIceError> {
        match rule {
            IdentifierRule::Path {
                pattern,
                case_sensitive,
            } => {
                let options = glob::MatchOptions {
                    case_sensitive: *case_sensitive,
                    ..Default::default()
                };

                let path_str = process_info.executable_path.to_string_lossy();
                // Normalize backslashes to forward slashes for glob matching
                let normalized = path_str.replace('\\', "/");
                let normalized_pattern = pattern.replace('\\', "/");

                let pattern = glob::Pattern::new(&normalized_pattern).map_err(|e| {
                    OpenIceError::IdentifierError(format!("Invalid glob pattern '{}': {}", pattern, e))
                })?;

                if pattern.matches_with(&normalized, options) {
                    Ok(MatchResult::Match {
                        confidence: 0.9,
                        reason: format!(
                            "Path pattern match: {} matches {}",
                            process_info.executable_path.display(),
                            normalized_pattern
                        ),
                    })
                } else {
                    Ok(MatchResult::NoMatch)
                }
            }
            IdentifierRule::ProcessName { value } => {
                let matches = if cfg!(windows) {
                    process_info.name.eq_ignore_ascii_case(value)
                } else {
                    process_info.name == *value
                };

                if matches {
                    Ok(MatchResult::Match {
                        confidence: 0.8,
                        reason: format!("Process name match: {}", process_info.name),
                    })
                } else {
                    Ok(MatchResult::NoMatch)
                }
            }
            _ => Ok(MatchResult::NoMatch),
        }
    }
}
