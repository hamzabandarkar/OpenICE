Here is a **detailed Claude-ready project context file** for your project.

You can paste this directly into Claude Code.

---

````markdown
# OpenICE — Precision AI Agent Containment & Execution Control Platform

## Project Overview

OpenICE is a defensive security platform designed to precisely control, contain, or block locally installed AI agent software (e.g., autonomous coding agents like OpenClaw).

The initial implementation will target Windows, with architectural consideration for future Linux support.

OpenICE is NOT an antivirus.
OpenICE is NOT malware removal software.
OpenICE is NOT AI detection software.

OpenICE is a precision application-control and containment system focused on:

- Deterministic execution blocking
- Per-process network isolation
- Child-process containment
- Resource throttling
- Persistence prevention
- Transparent audit logging

The long-term vision is to evolve OpenICE into a modular endpoint security platform specifically tailored to AI agent containment.

---

# Core Philosophy

Computers do not understand "AI."
They execute code.

Therefore, OpenICE does NOT attempt to detect AI computation patterns.

Instead, OpenICE enforces control over:

- Specific binaries
- Signatures
- Process trees
- Network behavior
- File access
- Persistence mechanisms

This makes OpenICE technically sound and future-proof.

---

# Target Audience

Primary users:

- AI-aware developers
- Security-conscious power users
- Enterprises evaluating AI containment
- Researchers running agent experiments
- Privacy-focused technical users

Users are assumed to be technically literate.

---

# OS Target (Phase 1)

Primary: Windows 10/11  
Secondary (Future): Linux  

Windows is chosen for:
- Market reach
- Resume value
- Enterprise relevance
- Real-world applicability

---

# Threat Model

OpenICE assumes:

- Target AI agent (e.g., OpenClaw) is already installed.
- Target agent may have admin rights.
- User cannot manually delete or alter target agent.
- OpenICE must operate within legal OS boundaries.
- No kernel exploit assumptions.

OpenICE must:

- Survive restarts.
- Prevent respawn attempts.
- Block network-based LLM calls.
- Restrict command execution capabilities.
- Prevent persistence re-creation.

---

# OpenICE Operating Modes

OpenICE supports four enforcement tiers.

## 1. Observe Mode
- No blocking.
- Full telemetry collection.
- Process tree mapping.
- Network logging.
- File access logging.
- Persistence detection.

Used for:
- Learning agent behavior.
- Building containment profiles.

---

## 2. Containment Mode (Primary Mode)

The agent may execute, but:

- Outbound network is blocked.
- Child shell execution is blocked.
- Access to protected directories is denied.
- CPU/GPU usage can be limited.
- Memory usage can be limited.

This makes agents functionally inert without deleting them.

---

## 3. Quarantine Mode

- Target executable is immediately terminated.
- Launch attempts are intercepted.
- Firewall rules block outbound traffic.
- Persistence entries are removed.
- Process tree is killed recursively.

Reactive but aggressive.

---

## 4. Lockdown Mode (Policy-Based Hard Block)

- Execution is denied at launch via OS policy.
- WDAC/AppLocker policies generated dynamically.
- Binary hash or signer-based deny rules.
- Child process rules enforced.
- Survives reboot.

Strongest enforcement mode.

---

# System Architecture

OpenICE consists of the following components:

## 1. Policy Engine

Responsible for:

- Rule parsing
- Priority resolution
- Policy validation
- Rule conflict handling
- Persistence

Policy format (JSON example):

```json
{
  "profile_name": "OpenClaw",
  "identifiers": {
    "hash": "SHA256_VALUE",
    "signer": "Publisher Name",
    "path": "C:\\Program Files\\OpenClaw\\openclaw.exe"
  },
  "enforcement": {
    "block_launch": false,
    "block_network": true,
    "block_child_shell": true,
    "limit_cpu_percent": 10,
    "limit_memory_mb": 512
  }
}
````

---

## 2. Identifier Engine

Matches processes using:

* SHA-256 file hash
* Authenticode publisher signature
* Path-based rules
* Parent/child ancestry patterns
* Command-line signature
* Process behavior fingerprint (future)

Supports multiple matching strategies.

---

## 3. Enforcement Backends

### A. Process Control

* Monitor process creation
* Kill process tree
* Prevent respawn
* Block child shells (powershell, cmd, wsl, python)

### B. Network Isolation

* Windows Filtering Platform integration
* Per-process outbound block
* Domain-level blocking
* DNS sinkhole (optional)

### C. Resource Governance

* Job Objects for CPU throttling
* Memory caps
* Priority reduction

### D. Persistence Monitoring

* Scheduled task scanning
* Startup folder monitoring
* Registry run keys
* Service monitoring

### E. Policy-Based Launch Denial

* WDAC rule generation
* AppLocker deny rules
* Policy validation before deployment
* Safe rollback mechanism

---

## 4. Telemetry & Audit Layer

Every enforcement action is logged.

Example:

```
[14:23:05] Blocked outbound connection from openclaw.exe to api.llmprovider.com
[14:23:07] Prevented child process spawn: powershell.exe (parent: openclaw.exe)
[14:23:08] Terminated openclaw.exe (Quarantine Mode)
```

Logs must be:

* Transparent
* Exportable
* Reversible
* Human-readable

---

# OpenClaw-Specific Profile (Initial Target)

OpenICE v1 will include a built-in OpenClaw profile:

* Known executable hash
* Known signer (if signed)
* Known directories
* Known helper processes
* Known LLM API domains (if applicable)

Future versions allow user-created profiles.

---

# Future Generalization

Users can:

* Add arbitrary executables.
* Define containment rules.
* Use “Learn Mode” to record behavior.
* Export/import policy packs.

Long-term vision:

OpenICE becomes a modular AI containment firewall.

---

# Security & Self-Protection

OpenICE must:

* Run as a privileged service.
* Protect its own process.
* Validate policy integrity.
* Detect tampering attempts.
* Provide rollback if policy misconfiguration occurs.

---

# MVP Roadmap

Phase 1:

* Detect OpenClaw
* Kill process tree
* Block outbound traffic
* Remove persistence
* Log actions

Phase 2:

* Resource throttling
* Child process blocking
* Containment mode

Phase 3:

* WDAC/AppLocker integration
* Policy deployment UI
* Safe rollback

Phase 4:

* User-defined profiles
* Learn Mode
* Telemetry dashboard

---

# Non-Goals

OpenICE will NOT:

* Attempt kernel exploits
* Reverse engineer arbitrary apps
* Detect AI by mathematical pattern
* Operate outside OS permission model
* Act as generic antivirus replacement

---

# Long-Term Startup Potential

OpenICE could evolve into:

* Enterprise AI containment product
* Agent execution firewall
* Developer sandboxing platform
* AI governance enforcement layer
* Controlled experimentation environment

Differentiation:

Unlike antivirus, OpenICE provides deterministic user-controlled containment of specific AI systems.

---

# Core Design Principles

1. Deterministic > heuristic
2. Transparent > opaque
3. Reversible > destructive
4. Containment > deletion
5. Precision > broad blocking
6. Policy-driven architecture
7. Minimal performance overhead
8. Clean modular design

---

# Engineering Constraints

* Must operate within Windows APIs.
* Must not destabilize OS.
* Must avoid system-wide policy corruption.
* Must include fail-safe.
* Must include recovery instructions.

---

# Final Vision Statement

OpenICE is a next-generation AI agent containment system that gives technically sophisticated users full control over local autonomous AI execution — without relying on malware heuristics, vague detection models, or destructive removal tactics.

It treats AI agents as deterministic software systems that can be controlled, governed, or neutralized through precise policy enforcement.

```

---

If you want next, I can:

- Turn this into a technical system architecture diagram
- Write a concrete Windows implementation plan
- Help you decide language stack (Rust, C++, C#, etc.)
- Or design the OpenICE branding & positioning strategy
```
