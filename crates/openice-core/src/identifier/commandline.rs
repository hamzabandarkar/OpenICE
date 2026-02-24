use regex::Regex;

use crate::error::OpenIceError;
use crate::policy::model::IdentifierRule;
use crate::traits::{IdentifierMatcher, MatchResult, ProcessInfo};

/// Matches processes by command-line arguments using string or regex patterns.
pub struct CommandLineMatcher;

impl CommandLineMatcher {
    pub fn new() -> Self {
        Self
    }
}

impl IdentifierMatcher for CommandLineMatcher {
    fn name(&self) -> &str {
        "command_line"
    }

    fn matches(
        &self,
        process_info: &ProcessInfo,
        rule: &IdentifierRule,
    ) -> Result<MatchResult, OpenIceError> {
        if let IdentifierRule::CommandLine { pattern, regex } = rule {
            let matched = if *regex {
                let re = Regex::new(pattern).map_err(|e| {
                    OpenIceError::IdentifierError(format!(
                        "Invalid regex pattern '{}': {}",
                        pattern, e
                    ))
                })?;
                re.is_match(&process_info.command_line)
            } else {
                process_info
                    .command_line
                    .to_lowercase()
                    .contains(&pattern.to_lowercase())
            };

            if matched {
                Ok(MatchResult::Match {
                    confidence: 0.7,
                    reason: format!(
                        "Command-line match: '{}' matches pattern '{}'",
                        process_info.command_line, pattern
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
