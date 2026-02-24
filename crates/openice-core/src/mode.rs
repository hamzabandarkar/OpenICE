use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Operating modes for OpenICE enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperatingMode {
    /// No blocking. Full telemetry collection, process tree mapping, network/file logging.
    Observe,
    /// Agent may execute but with restrictions: network blocked, child shells blocked,
    /// protected dirs denied, CPU/memory limited.
    Contain,
    /// Aggressive: immediate termination, launch interception, firewall rules,
    /// persistence removal, recursive process tree kill.
    Quarantine,
    /// Strongest: execution denied at launch via OS policy (WDAC/AppLocker),
    /// binary hash/signer deny rules, survives reboot.
    Lockdown,
}

impl fmt::Display for OperatingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OperatingMode::Observe => write!(f, "observe"),
            OperatingMode::Contain => write!(f, "contain"),
            OperatingMode::Quarantine => write!(f, "quarantine"),
            OperatingMode::Lockdown => write!(f, "lockdown"),
        }
    }
}

impl FromStr for OperatingMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "observe" => Ok(OperatingMode::Observe),
            "contain" => Ok(OperatingMode::Contain),
            "quarantine" => Ok(OperatingMode::Quarantine),
            "lockdown" => Ok(OperatingMode::Lockdown),
            _ => Err(format!(
                "Invalid mode '{}'. Expected: observe, contain, quarantine, lockdown",
                s
            )),
        }
    }
}
