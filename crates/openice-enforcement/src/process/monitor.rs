use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use openice_core::error::OpenIceError;

use sysinfo::System;

/// Monitors process creation by periodic polling.
/// A future version will use WMI event subscriptions for real-time monitoring.
pub struct ProcessMonitor {
    /// Set of known PIDs from the last scan.
    known_pids: Arc<Mutex<HashSet<u32>>>,
    system: Arc<Mutex<System>>,
}

/// Information about a newly detected process.
#[derive(Debug, Clone)]
pub struct DetectedProcess {
    pub pid: u32,
    pub name: String,
    pub exe_path: String,
    pub command_line: String,
    pub parent_pid: Option<u32>,
}

impl ProcessMonitor {
    pub fn new() -> Self {
        let mut sys = System::new();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

        let pids: HashSet<u32> = sys
            .processes()
            .keys()
            .map(|pid| pid.as_u32())
            .collect();

        Self {
            known_pids: Arc::new(Mutex::new(pids)),
            system: Arc::new(Mutex::new(sys)),
        }
    }

    /// Scan for new processes since the last check.
    /// Returns processes that appeared since the last call.
    pub fn scan_new_processes(&self) -> Result<Vec<DetectedProcess>, OpenIceError> {
        let mut sys = self.system.lock().map_err(|e| {
            OpenIceError::ProcessError(format!("Failed to lock system: {}", e))
        })?;
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

        let mut known = self.known_pids.lock().map_err(|e| {
            OpenIceError::ProcessError(format!("Failed to lock known_pids: {}", e))
        })?;

        let current_pids: HashSet<u32> = sys
            .processes()
            .keys()
            .map(|pid| pid.as_u32())
            .collect();

        let new_pids: Vec<u32> = current_pids.difference(&known).copied().collect();
        let mut detected = Vec::new();

        for &pid in &new_pids {
            let sysinfo_pid = sysinfo::Pid::from_u32(pid);
            if let Some(process) = sys.process(sysinfo_pid) {
                detected.push(DetectedProcess {
                    pid,
                    name: process.name().to_string_lossy().to_string(),
                    exe_path: process
                        .exe()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default(),
                    command_line: process.cmd().iter().map(|s| s.to_string_lossy()).collect::<Vec<_>>().join(" "),
                    parent_pid: process.parent().map(|p| p.as_u32()),
                });
            }
        }

        // Update known set
        *known = current_pids;

        Ok(detected)
    }

    /// Get all currently running processes.
    pub fn scan_all_processes(&self) -> Result<Vec<DetectedProcess>, OpenIceError> {
        let mut sys = self.system.lock().map_err(|e| {
            OpenIceError::ProcessError(format!("Failed to lock system: {}", e))
        })?;
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

        let mut processes = Vec::new();
        for (pid, process) in sys.processes() {
            processes.push(DetectedProcess {
                pid: pid.as_u32(),
                name: process.name().to_string_lossy().to_string(),
                exe_path: process
                    .exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default(),
                command_line: process.cmd().iter().map(|s| s.to_string_lossy()).collect::<Vec<_>>().join(" "),
                parent_pid: process.parent().map(|p| p.as_u32()),
            });
        }

        Ok(processes)
    }
}

impl Default for ProcessMonitor {
    fn default() -> Self {
        Self::new()
    }
}
