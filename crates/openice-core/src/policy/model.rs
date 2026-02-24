use serde::{Deserialize, Serialize};

/// A complete containment policy profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub profile_name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default = "default_priority")]
    pub priority: u32,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub identifiers: IdentifierConfig,
    pub enforcement: EnforcementConfig,
    #[serde(default)]
    pub metadata: PolicyMetadata,
}

fn default_version() -> u32 {
    1
}
fn default_priority() -> u32 {
    100
}
fn default_true() -> bool {
    true
}

/// How identifiers should be matched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentifierConfig {
    /// "any" = match if any rule matches, "all" = match only if all rules match
    #[serde(default = "default_match_mode")]
    pub match_mode: MatchMode,
    pub rules: Vec<IdentifierRule>,
}

fn default_match_mode() -> MatchMode {
    MatchMode::Any
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MatchMode {
    Any,
    All,
}

/// A single identifier rule for matching processes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IdentifierRule {
    Hash {
        #[serde(default = "default_algorithm")]
        algorithm: String,
        value: String,
    },
    Path {
        pattern: String,
        #[serde(default)]
        case_sensitive: bool,
    },
    ProcessName {
        value: String,
    },
    CommandLine {
        pattern: String,
        #[serde(default)]
        regex: bool,
    },
    Signer {
        publisher: String,
    },
}

fn default_algorithm() -> String {
    "sha256".to_string()
}

/// Enforcement configuration per operating mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementConfig {
    pub default_mode: String,
    #[serde(default)]
    pub modes: EnforcementModes,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnforcementModes {
    #[serde(default)]
    pub observe: ObserveConfig,
    #[serde(default)]
    pub contain: ContainConfig,
    #[serde(default)]
    pub quarantine: QuarantineConfig,
    #[serde(default)]
    pub lockdown: LockdownConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObserveConfig {
    #[serde(default = "default_true")]
    pub log_process_tree: bool,
    #[serde(default = "default_true")]
    pub log_network: bool,
    #[serde(default = "default_true")]
    pub log_file_access: bool,
    #[serde(default = "default_true")]
    pub log_persistence: bool,
}

impl Default for ObserveConfig {
    fn default() -> Self {
        Self {
            log_process_tree: true,
            log_network: true,
            log_file_access: true,
            log_persistence: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainConfig {
    #[serde(default = "default_true")]
    pub block_network: bool,
    #[serde(default = "default_true")]
    pub block_child_shells: bool,
    #[serde(default)]
    pub limit_cpu_percent: Option<u32>,
    #[serde(default)]
    pub limit_memory_mb: Option<u64>,
    #[serde(default)]
    pub protected_directories: Vec<String>,
}

impl Default for ContainConfig {
    fn default() -> Self {
        Self {
            block_network: true,
            block_child_shells: true,
            limit_cpu_percent: None,
            limit_memory_mb: None,
            protected_directories: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineConfig {
    #[serde(default = "default_true")]
    pub kill_process_tree: bool,
    #[serde(default = "default_true")]
    pub block_network: bool,
    #[serde(default = "default_true")]
    pub remove_persistence: bool,
    #[serde(default = "default_true")]
    pub prevent_respawn: bool,
    #[serde(default = "default_respawn_interval")]
    pub respawn_check_interval_secs: u64,
}

fn default_respawn_interval() -> u64 {
    3
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            kill_process_tree: true,
            block_network: true,
            remove_persistence: true,
            prevent_respawn: true,
            respawn_check_interval_secs: 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockdownConfig {
    #[serde(default)]
    pub generate_wdac_policy: bool,
    #[serde(default)]
    pub generate_applocker_rules: bool,
    #[serde(default = "default_true")]
    pub block_by_hash: bool,
    #[serde(default)]
    pub block_by_signer: bool,
}

impl Default for LockdownConfig {
    fn default() -> Self {
        Self {
            generate_wdac_policy: false,
            generate_applocker_rules: false,
            block_by_hash: true,
            block_by_signer: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyMetadata {
    #[serde(default)]
    pub created: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}
