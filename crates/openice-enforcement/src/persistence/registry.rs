use openice_core::error::OpenIceError;
use openice_core::mode::OperatingMode;
use openice_core::telemetry::event::{
    ActionResult, AuditEvent, EventKind, RollbackEntry, UndoType,
};

use windows::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER,
    HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, KEY_READ, REG_SZ,
};

use windows::core::{PCWSTR, PWSTR};

/// Well-known registry Run key paths.
const RUN_KEY_PATHS: &[(&str, HKEY, &str)] = &[
    (
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    ),
    (
        "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        HKEY_CURRENT_USER,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    ),
    (
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ),
    (
        "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        HKEY_CURRENT_USER,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ),
];

/// Detected registry persistence entry.
#[derive(Debug, Clone)]
pub struct RegistryEntry {
    pub key_path: String,
    pub value_name: String,
    pub value_data: String,
    pub hkey: HKEY,
    pub subkey: String,
}

/// Scan registry Run keys for entries matching a target executable.
pub fn scan_run_keys(target_name: &str) -> Result<Vec<RegistryEntry>, OpenIceError> {
    let mut found = Vec::new();
    let target_lower = target_name.to_lowercase();

    for &(display_path, root_key, subkey_path) in RUN_KEY_PATHS {
        match scan_single_key(root_key, subkey_path, display_path, &target_lower) {
            Ok(entries) => found.extend(entries),
            Err(e) => {
                tracing::debug!("Could not scan {}: {}", display_path, e);
            }
        }
    }

    Ok(found)
}

fn scan_single_key(
    root: HKEY,
    subkey: &str,
    display_path: &str,
    target_lower: &str,
) -> Result<Vec<RegistryEntry>, OpenIceError> {
    let subkey_wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let mut hkey = HKEY::default();

    unsafe {
        RegOpenKeyExW(root, PCWSTR(subkey_wide.as_ptr()), 0, KEY_READ, &mut hkey)
            .ok()
            .map_err(|e| {
                OpenIceError::PersistenceError(format!("Failed to open {}: {}", display_path, e))
            })?;
    }

    let mut entries = Vec::new();
    let mut index: u32 = 0;

    loop {
        let mut name_buf = [0u16; 256];
        let mut name_len = name_buf.len() as u32;
        let mut data_buf = [0u8; 1024];
        let mut data_len = data_buf.len() as u32;
        let mut value_type = 0u32;

        let result = unsafe {
            RegEnumValueW(
                hkey,
                index,
                PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
                None,
                Some(&mut value_type),
                Some(data_buf.as_mut_ptr()),
                Some(&mut data_len),
            )
        };

        if result.is_err() {
            break;
        }

        if value_type == REG_SZ.0 {
            let value_name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            let data_str = if data_len >= 2 {
                let u16_slice: &[u16] = unsafe {
                    std::slice::from_raw_parts(
                        data_buf.as_ptr() as *const u16,
                        (data_len as usize) / 2,
                    )
                };
                // Remove trailing null
                let end = u16_slice
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(u16_slice.len());
                String::from_utf16_lossy(&u16_slice[..end])
            } else {
                String::new()
            };

            if data_str.to_lowercase().contains(target_lower)
                || value_name.to_lowercase().contains(target_lower)
            {
                entries.push(RegistryEntry {
                    key_path: format!("{}\\{}", display_path, value_name),
                    value_name: value_name.clone(),
                    value_data: data_str,
                    hkey: root,
                    subkey: subkey.to_string(),
                });
            }
        }

        index += 1;
    }

    unsafe {
        let _ = RegCloseKey(hkey);
    }

    Ok(entries)
}

/// Remove a specific registry Run key value.
pub fn remove_run_key_value(
    entry: &RegistryEntry,
    mode: OperatingMode,
) -> Result<AuditEvent, OpenIceError> {
    let subkey_wide: Vec<u16> = entry
        .subkey
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let value_wide: Vec<u16> = entry
        .value_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut hkey = HKEY::default();

    unsafe {
        RegOpenKeyExW(
            entry.hkey,
            PCWSTR(subkey_wide.as_ptr()),
            0,
            KEY_ALL_ACCESS,
            &mut hkey,
        )
        .ok()
        .map_err(|e| {
            OpenIceError::PersistenceError(format!(
                "Failed to open registry key for deletion: {}",
                e
            ))
        })?;

        let result = RegDeleteValueW(hkey, PCWSTR(value_wide.as_ptr()));
        let _ = RegCloseKey(hkey);

        if result.is_ok() {
            let mut event = AuditEvent::new(
                EventKind::PersistenceRemoved,
                mode,
                "PersistenceMonitor",
                "RemoveRegistryRunKey",
                &format!(
                    "Removed registry value '{}' from {}",
                    entry.value_name, entry.key_path
                ),
            );
            event.rollback_info = Some(RollbackEntry::new(
                event.id,
                UndoType::RestoreRegistryValue {
                    key: entry.key_path.clone(),
                    value_name: entry.value_name.clone(),
                    data: entry.value_data.as_bytes().to_vec(),
                    reg_type: REG_SZ.0,
                },
                &format!("Restore registry value '{}'", entry.value_name),
            ));
            Ok(event)
        } else {
            let event = AuditEvent::new(
                EventKind::PersistenceRemoved,
                mode,
                "PersistenceMonitor",
                "RemoveRegistryRunKey",
                &format!(
                    "Failed to remove registry value '{}': {:?}",
                    entry.value_name, result
                ),
            )
            .with_result(ActionResult::Failed {
                reason: format!("{:?}", result),
            });
            Ok(event)
        }
    }
}

/// Scan and remove all matching registry persistence entries.
pub fn remove_persistence_registry(
    target_name: &str,
    mode: OperatingMode,
) -> Result<Vec<AuditEvent>, OpenIceError> {
    let entries = scan_run_keys(target_name)?;
    let mut events = Vec::new();

    if entries.is_empty() {
        let event = AuditEvent::new(
            EventKind::PersistenceDetected,
            mode,
            "PersistenceMonitor",
            "ScanRegistryRunKeys",
            &format!("No registry persistence entries found for '{}'", target_name),
        )
        .with_result(ActionResult::Skipped {
            reason: "No matching entries found".to_string(),
        });
        events.push(event);
    } else {
        for entry in &entries {
            tracing::info!("Found persistence entry: {} -> {}", entry.key_path, entry.value_data);
            match remove_run_key_value(entry, mode) {
                Ok(event) => events.push(event),
                Err(e) => {
                    tracing::error!("Failed to remove {}: {}", entry.key_path, e);
                }
            }
        }
    }

    Ok(events)
}
