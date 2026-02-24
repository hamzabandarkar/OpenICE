# OpenICE

OpenICE is a deterministic AI agent containment and execution control platform for Windows.

It provides precision enforcement over locally installed autonomous AI agents by controlling:

- Process execution
- Child process spawning
- Network egress
- Resource usage
- Persistence mechanisms


## Phase 1 (Current)

- Process detection (hash + path)
- Process tree termination
- Per-process network blocking
- Persistence monitoring
- Structured audit logging

## Architecture

OpenICE follows a policy-driven modular architecture:

- Policy Engine
- Identifier Engine
- Enforcement Backends
- Telemetry Layer

## Roadmap

- Containment Mode (resource throttling)
- Launch Denial via WDAC/AppLocker
- User-defined policy profiles
- Learn Mode

---

## How to Run

### Requirements

- Windows 10 or Windows 11
- Rust (stable toolchain)
- Administrator privileges (required for process control and firewall rules)

Install Rust:

https://www.rust-lang.org/tools/install

Verify installation:

```powershell
rustc --version
cargo --version

OpenICE treats AI agents as deterministic software systems that can be governed through precise execution control rather than heuristic malware detection.
