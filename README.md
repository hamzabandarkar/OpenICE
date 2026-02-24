# OpenICE

OpenICE is a deterministic AI agent containment and execution control platform for Windows.

It provides precision enforcement over locally installed autonomous AI agents by controlling:

- Process execution
- Child process spawning
- Network egress
- Resource usage
- Persistence mechanisms

## Project Goals

OpenICE is designed as:

- A learning-focused security systems project
- A modular containment framework
- A potential enterprise AI governance platform

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

OpenICE treats AI agents as deterministic software systems that can be governed through precise execution control rather than heuristic malware detection.
