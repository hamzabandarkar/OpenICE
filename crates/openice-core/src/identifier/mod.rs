pub mod ancestry;
pub mod commandline;
pub mod hash;
pub mod path;

use crate::traits::IdentifierMatcher;

/// Create all available identifier matchers.
pub fn create_all_matchers() -> Vec<Box<dyn IdentifierMatcher>> {
    vec![
        Box::new(hash::HashMatcher::new()),
        Box::new(path::PathMatcher::new()),
        Box::new(commandline::CommandLineMatcher::new()),
        Box::new(ancestry::AncestryMatcher::new()),
    ]
}
