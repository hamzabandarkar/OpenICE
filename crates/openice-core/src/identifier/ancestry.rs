use crate::error::OpenIceError;
use crate::policy::model::IdentifierRule;
use crate::traits::{IdentifierMatcher, MatchResult, ProcessInfo};

/// Matches processes by parent/child ancestry patterns.
/// Stub implementation for Phase 1.
pub struct AncestryMatcher;

impl AncestryMatcher {
    pub fn new() -> Self {
        Self
    }
}

impl IdentifierMatcher for AncestryMatcher {
    fn name(&self) -> &str {
        "ancestry"
    }

    fn matches(
        &self,
        _process_info: &ProcessInfo,
        _rule: &IdentifierRule,
    ) -> Result<MatchResult, OpenIceError> {
        // Ancestry matching requires walking the full process tree,
        // which will be implemented in a later phase.
        Ok(MatchResult::NoMatch)
    }
}
