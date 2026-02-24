use std::time::Duration;

use openice_core::mode::OperatingMode;
use openice_core::telemetry::event::AuditEvent;

use super::kill;

/// Guard that continuously checks for and kills respawned target processes.
pub struct RespawnGuard {
    target_name: String,
    check_interval: Duration,
    mode: OperatingMode,
}

impl RespawnGuard {
    pub fn new(target_name: &str, check_interval_secs: u64, mode: OperatingMode) -> Self {
        Self {
            target_name: target_name.to_string(),
            check_interval: Duration::from_secs(check_interval_secs),
            mode,
        }
    }

    /// Run a single respawn check. Returns audit events if any processes were killed.
    pub fn check_and_kill(&self) -> Vec<AuditEvent> {
        let mut all_events = Vec::new();

        match kill::find_processes_by_name(&self.target_name) {
            Ok(processes) => {
                for (pid, name) in processes {
                    tracing::info!(
                        "Respawn detected: {} (PID {}), killing process tree",
                        name,
                        pid
                    );
                    let events = kill::kill_process_tree(pid, &name, self.mode);
                    all_events.extend(events);
                }
            }
            Err(e) => {
                tracing::error!("Respawn guard scan failed: {}", e);
            }
        }

        all_events
    }

    /// Run the respawn guard loop asynchronously. Runs until the token is cancelled.
    pub async fn run_loop(&self, cancel: tokio::sync::watch::Receiver<bool>) -> Vec<AuditEvent> {
        let mut all_events = Vec::new();

        loop {
            if *cancel.borrow() {
                break;
            }

            let events = self.check_and_kill();
            all_events.extend(events);

            tokio::time::sleep(self.check_interval).await;
        }

        all_events
    }

    pub fn target_name(&self) -> &str {
        &self.target_name
    }

    pub fn check_interval(&self) -> Duration {
        self.check_interval
    }
}
