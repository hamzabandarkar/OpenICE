use std::collections::{HashMap, HashSet, VecDeque};

use openice_core::error::OpenIceError;
use openice_core::mode::OperatingMode;
use openice_core::telemetry::event::{ActionResult, AuditEvent, EventKind, RollbackEntry, UndoType};

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

/// Kill a process and all its descendants.
/// Returns a list of audit events describing what happened.
pub fn kill_process_tree(pid: u32, process_name: &str, mode: OperatingMode) -> Vec<AuditEvent> {
    let mut events = Vec::new();

    // Build the full tree of descendants
    match build_process_tree(pid) {
        Ok(descendants) => {
            // Kill in reverse order (leaves first, then root)
            let mut kill_order: Vec<u32> = descendants.into_iter().collect();
            kill_order.sort(); // Sort for deterministic order
            // Remove root and re-add at end
            kill_order.retain(|&p| p != pid);
            kill_order.push(pid);

            for target_pid in &kill_order {
                match terminate_process(*target_pid) {
                    Ok(()) => {
                        let mut event = AuditEvent::new(
                            EventKind::ProcessKilled,
                            mode,
                            "ProcessControl",
                            "KillProcess",
                            &format!("Terminated process PID {}", target_pid),
                        );
                        event.target_pid = Some(*target_pid);
                        event.target_process = Some(process_name.to_string());
                        event.rollback_info = Some(RollbackEntry::new(
                            event.id,
                            UndoType::NonReversible {
                                reason: "Process termination cannot be undone".to_string(),
                            },
                            &format!("Killed PID {}", target_pid),
                        ));
                        events.push(event);
                    }
                    Err(e) => {
                        let mut event = AuditEvent::new(
                            EventKind::ProcessKilled,
                            mode,
                            "ProcessControl",
                            "KillProcess",
                            &format!("Failed to terminate PID {}: {}", target_pid, e),
                        );
                        event.target_pid = Some(*target_pid);
                        event.target_process = Some(process_name.to_string());
                        event.result = ActionResult::Failed {
                            reason: e.to_string(),
                        };
                        events.push(event);
                    }
                }
            }
        }
        Err(e) => {
            let mut event = AuditEvent::new(
                EventKind::Error,
                mode,
                "ProcessControl",
                "KillProcessTree",
                &format!("Failed to build process tree for PID {}: {}", pid, e),
            );
            event.target_pid = Some(pid);
            event.target_process = Some(process_name.to_string());
            event.result = ActionResult::Failed {
                reason: e.to_string(),
            };
            events.push(event);
        }
    }

    events
}

/// Build a set of all descendant PIDs for a given root PID.
fn build_process_tree(root_pid: u32) -> Result<HashSet<u32>, OpenIceError> {
    // Take a snapshot of all processes
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(|e| {
        OpenIceError::ProcessError(format!("CreateToolhelp32Snapshot failed: {}", e))
    })?;

    let mut parent_map: HashMap<u32, Vec<u32>> = HashMap::new();

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    unsafe {
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let child_pid = entry.th32ProcessID;
                let parent_pid = entry.th32ParentProcessID;
                parent_map
                    .entry(parent_pid)
                    .or_default()
                    .push(child_pid);

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }

    // BFS from root to collect all descendants
    let mut descendants = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(root_pid);
    descendants.insert(root_pid);

    while let Some(current) = queue.pop_front() {
        if let Some(children) = parent_map.get(&current) {
            for &child in children {
                if descendants.insert(child) {
                    queue.push_back(child);
                }
            }
        }
    }

    Ok(descendants)
}

/// Terminate a single process by PID.
fn terminate_process(pid: u32) -> Result<(), OpenIceError> {
    unsafe {
        let handle: HANDLE = OpenProcess(PROCESS_TERMINATE, false, pid).map_err(|e| {
            OpenIceError::ProcessError(format!(
                "OpenProcess failed for PID {}: {}",
                pid, e
            ))
        })?;

        let result = TerminateProcess(handle, 1);
        let _ = CloseHandle(handle);

        result.map_err(|e| {
            OpenIceError::ProcessError(format!(
                "TerminateProcess failed for PID {}: {}",
                pid, e
            ))
        })
    }
}

/// Find all PIDs matching a given process name.
pub fn find_processes_by_name(name: &str) -> Result<Vec<(u32, String)>, OpenIceError> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(|e| {
        OpenIceError::ProcessError(format!("CreateToolhelp32Snapshot failed: {}", e))
    })?;

    let mut results = Vec::new();
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    unsafe {
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let proc_name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len())],
                );

                if proc_name.eq_ignore_ascii_case(name) {
                    results.push((entry.th32ProcessID, proc_name));
                }

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }

    Ok(results)
}
