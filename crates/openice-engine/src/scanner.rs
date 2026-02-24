use openice_core::error::OpenIceError;
use openice_core::traits::ProcessInfo;

use sysinfo::System;

/// Scan all running processes and return their info.
pub fn scan_all_processes() -> Result<Vec<ProcessInfo>, OpenIceError> {
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    let self_pid = std::process::id();
    let mut processes = Vec::new();

    for (pid, process) in sys.processes() {
        let pid_u32 = pid.as_u32();

        // Self-exclusion: never match our own process
        if pid_u32 == self_pid {
            continue;
        }

        let exe_path = process
            .exe()
            .map(|p| p.to_path_buf())
            .unwrap_or_default();

        processes.push(ProcessInfo {
            pid: pid_u32,
            name: process.name().to_string_lossy().to_string(),
            executable_path: exe_path,
            command_line: process.cmd().iter().map(|s| s.to_string_lossy()).collect::<Vec<_>>().join(" "),
            parent_pid: process.parent().map(|p| p.as_u32()),
            parent_name: None, // Would need a second pass to resolve
        });
    }

    Ok(processes)
}

/// Scan for a specific process by name or PID.
pub fn find_process(target: &str) -> Result<Vec<ProcessInfo>, OpenIceError> {
    let all = scan_all_processes()?;

    // Try parsing as PID first
    if let Ok(pid) = target.parse::<u32>() {
        return Ok(all.into_iter().filter(|p| p.pid == pid).collect());
    }

    // Match by name (case-insensitive on Windows)
    let target_lower = target.to_lowercase();
    Ok(all
        .into_iter()
        .filter(|p| p.name.to_lowercase() == target_lower)
        .collect())
}
