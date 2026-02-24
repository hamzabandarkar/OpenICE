use crate::error::OpenIceError;
use crate::telemetry::event::AuditEvent;
use crate::telemetry::sink::TelemetrySink;

/// Multi-sink audit logger that dispatches events to all registered sinks.
pub struct AuditLogger {
    sinks: Vec<Box<dyn TelemetrySink>>,
}

impl AuditLogger {
    pub fn new() -> Self {
        Self { sinks: Vec::new() }
    }

    pub fn add_sink(&mut self, sink: Box<dyn TelemetrySink>) {
        self.sinks.push(sink);
    }

    pub fn emit(&self, event: &AuditEvent) {
        for sink in &self.sinks {
            sink.emit(event);
        }
    }

    pub fn emit_all(&self, events: &[AuditEvent]) {
        for event in events {
            self.emit(event);
        }
    }

    pub fn flush(&self) -> Result<(), OpenIceError> {
        for sink in &self.sinks {
            sink.flush()?;
        }
        Ok(())
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}
