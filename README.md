# in-memory-hunter-rules

Production-focused YARA rules and Sysmon XML configuration profiles for hunting in-memory tradecraft, Position-Independent Code (PIC), Reflective DLL Injection (RDI), and unbacked executable memory regions.

## Coverage

Modern offensive frameworks avoid writing artifacts to disk, operating directly in volatile process memory. This repository provides detection logic tailored for endpoint threat hunting and SIEM correlation.

### YARA Signatures (`yara/`)

- `reflective_loader_peb_walk.yar`:
  - Detects dynamic PEB resolution (`gs:[0x60]` on x64, `fs:[0x30]` on x86).
  - Flags module list traversal across `InLoadOrderModuleList` / `InMemoryOrderModuleList`.
  - Identifies runtime API hash resolution algorithms including ROR-13 and ROR-7.
- `wininet_implant_pipe.yar`:
  - Identifies implants coupling WinINet HTTP/S beaconing with anonymous pipe redirection (`CreatePipe`, `SetHandleInformation`, `CreateProcessA`).

### Sysmon Profiles (`sysmon/`)

- `in_memory_injection.xml`:
  - Event ID 8 (`CreateRemoteThread`): Flags thread creation into critical system processes or threads initiating at unbacked memory addresses.
  - Event ID 10 (`ProcessAccess`): Catches memory manipulation flags (`PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) paired with anomalous call stacks.
  - Event ID 25 (`ProcessTampering`): Alerts on process hollowing and image replacement techniques.

## Usage

### Scanning with YARA
```bash
yara -r yara/reflective_loader_peb_walk.yar /path/to/memory_dump_or_binaries/
```

### Loading Sysmon Configuration
```powershell
sysmon.exe -c sysmon/in_memory_injection.xml
```

## Defensive Scope

These rules are engineered for defensive telemetry ingestion, SIEM alerting, and forensic memory analysis. They contain no offensive payloads or weaponized code.

## License

MIT - Copyright (c) Shinabaze Ajiya.
