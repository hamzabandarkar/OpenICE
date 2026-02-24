use crate::error::OpenIceError;
use crate::mode::OperatingMode;
use crate::policy::model::{MatchMode, Policy};
use crate::traits::{IdentifierMatcher, MatchResult, ProcessInfo};

/// Resolve which policies match a given process, returning them in priority order.
pub fn resolve_matching_policies(
    process: &ProcessInfo,
    policies: &[Policy],
    matchers: &[Box<dyn IdentifierMatcher>],
) -> Result<Vec<PolicyMatch>, OpenIceError> {
    let mut matches = Vec::new();

    for policy in policies {
        if !policy.enabled {
            continue;
        }

        if let Some(policy_match) = check_policy_match(process, policy, matchers)? {
            matches.push(policy_match);
        }
    }

    // Already sorted by priority from loader, but ensure it
    matches.sort_by(|a, b| b.priority.cmp(&a.priority));
    Ok(matches)
}

/// Check if a process matches a single policy.
fn check_policy_match(
    process: &ProcessInfo,
    policy: &Policy,
    matchers: &[Box<dyn IdentifierMatcher>],
) -> Result<Option<PolicyMatch>, OpenIceError> {
    let mut rule_matches = Vec::new();
    let mut any_matched = false;

    for rule in &policy.identifiers.rules {
        let mut rule_matched = false;

        for matcher in matchers {
            if let Ok(result) = matcher.matches(process, rule) {
                if let MatchResult::Match { confidence, reason } = result {
                    rule_matches.push(RuleMatchDetail {
                        matcher_name: matcher.name().to_string(),
                        confidence,
                        reason,
                    });
                    rule_matched = true;
                    any_matched = true;
                    break;
                }
            }
        }

        // In "all" mode, if any rule fails to match, the whole policy doesn't match
        if policy.identifiers.match_mode == MatchMode::All && !rule_matched {
            return Ok(None);
        }
    }

    // In "any" mode, at least one rule must match
    if policy.identifiers.match_mode == MatchMode::Any && !any_matched {
        return Ok(None);
    }

    let mode = policy
        .enforcement
        .default_mode
        .parse::<OperatingMode>()
        .map_err(|e| OpenIceError::PolicyError(e))?;

    Ok(Some(PolicyMatch {
        policy_name: policy.profile_name.clone(),
        priority: policy.priority,
        mode,
        policy: policy.clone(),
        match_details: rule_matches,
    }))
}

/// Result of matching a process against a policy.
#[derive(Debug)]
pub struct PolicyMatch {
    pub policy_name: String,
    pub priority: u32,
    pub mode: OperatingMode,
    pub policy: Policy,
    pub match_details: Vec<RuleMatchDetail>,
}

#[derive(Debug)]
pub struct RuleMatchDetail {
    pub matcher_name: String,
    pub confidence: f32,
    pub reason: String,
}

/// Get the effective mode: use the override if provided, otherwise the policy's default.
pub fn effective_mode(policy_match: &PolicyMatch, mode_override: Option<OperatingMode>) -> OperatingMode {
    mode_override.unwrap_or(policy_match.mode)
}
