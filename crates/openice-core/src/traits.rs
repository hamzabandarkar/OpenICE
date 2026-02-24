use std::path::PathBuf;

use crate::error::OpenIceError;
use crate::telemetry::event::AuditEvent;

/// Information about a running process, used for identification matching.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub executable_path: PathBuf,
    pub command_line: String,
    pub parent_pid: Option<u32>,
    pub parent_name: Option<String>,
}

/// Describes what process/binary we are acting on.
#[derive(Debug, Clone)]
pub struct EnforcementTarget {
    pub pid: Option<u32>,
    pub executable_path: Option<PathBuf>,
    pub hash: Option<String>,
    pub display_name: String,
}

impl EnforcementTarget {
    pub fn from_process_info(info: &ProcessInfo) -> Self {
        Self {
            pid: Some(info.pid),
            executable_path: Some(info.executable_path.clone()),
            hash: None,
            display_name: info.name.clone(),
        }
    }

    pub fn from_path(path: PathBuf) -> Self {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path.to_string_lossy().to_string());
        Self {
            pid: None,
            executable_path: Some(path),
            hash: None,
            display_name: name,
        }
    }
}

/// What enforcement action to take.
#[derive(Debug, Clone)]
pub enum EnforcementAction {
    KillProcessTree,
    BlockOutboundNetwork,
    UnblockOutboundNetwork,
    RemovePersistence(PersistenceType),
    LimitResources(ResourceLimits),
    BlockLaunch,
    BlockChildShells,
}

/// Types of persistence mechanisms.
#[derive(Debug, Clone)]
pub enum PersistenceType {
    RegistryRunKey,
    ScheduledTask,
    StartupFolder,
    Service,
    All,
}

/// Resource limit configuration.
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    pub cpu_percent: Option<u32>,
    pub memory_mb: Option<u64>,
}

/// Status of an enforcement action.
#[derive(Debug)]
pub enum EnforcementStatus {
    Active { details: String },
    Inactive,
    Unknown,
}

/// Trait for enforcement backends.
pub trait EnforcementBackend: Send + Sync {
    /// Human-readable name for logging.
    fn name(&self) -> &str;

    /// Apply enforcement for a matched target.
    fn enforce(
        &self,
        target: &EnforcementTarget,
        action: &EnforcementAction,
    ) -> Result<Vec<AuditEvent>, OpenIceError>;

    /// Undo a previously applied enforcement.
    fn rollback(
        &self,
        target: &EnforcementTarget,
        action: &EnforcementAction,
    ) -> Result<Vec<AuditEvent>, OpenIceError>;

    /// Check current status of enforcement for a target.
    fn status(&self, target: &EnforcementTarget) -> Result<EnforcementStatus, OpenIceError>;
}

/// Result of an identifier match.
#[derive(Debug)]
pub enum MatchResult {
    Match { confidence: f32, reason: String },
    NoMatch,
}

/// Trait for identifier matchers.
pub trait IdentifierMatcher: Send + Sync {
    fn name(&self) -> &str;
    fn matches(
        &self,
        process_info: &ProcessInfo,
        rule: &crate::policy::model::IdentifierRule,
    ) -> Result<MatchResult, OpenIceError>;
}
