# SentinelFIM

<p align="center">
  <strong>A desktop File Integrity Monitor for Windows</strong><br>
  Establish a trusted file baseline, detect changes, and investigate the evidence.
</p>

<p align="center">
  <img alt="Platform: Windows" src="https://img.shields.io/badge/platform-Windows-0078D4?logo=windows&logoColor=white">
  <img alt="Language: Python" src="https://img.shields.io/badge/language-Python-3776AB?logo=python&logoColor=white">
  <img alt="Security: Defensive tool" src="https://img.shields.io/badge/use-defensive%20security-1F6FEB">
  <img alt="License not specified" src="https://img.shields.io/badge/license-not%20specified-lightgrey">
</p>

SentinelFIM is a local desktop application for monitoring selected files and folders. It fingerprints files, compares later scans with a saved baseline, and presents changes for review through alerts, an inventory, and forensic details.

> **Scope:** SentinelFIM detects and reports differences. It does not prevent file changes or determine whether an event is malicious. It is an educational defensive security project, not a certified enterprise security platform.

## Features

- **File integrity checks:** SHA-256 and SHA-512 fingerprints, calculated in 1 MiB chunks.
- **Change classification:** created, tampered, deleted, verified rename, and unchanged files.
- **Safer scan reporting:** scan errors are kept separate from deletions, so inaccessible paths are not automatically reported as removed.
- **Local baseline history:** HMAC-SHA-256 authentication with a key derived from the user's password using scrypt.
- **Investigation views:** desktop dashboard, alert details, nested file inventory, baseline management, and forensic review.
- **Optional AI assistance:** user-triggered Gemini or local Ollama analysis. Results are advisory and separate from observed scan evidence.
- **Responsive monitoring:** Watchdog notifications can wake scans early; periodic hash scans determine integrity findings.

Monitoring is active only while SentinelFIM is running. Watchdog notifications do not block writes.

## Screenshots and demo

Add genuine screenshots captured from the current application to [`screenshots/`](screenshots/README.md). The repository's screenshot guide lists the recommended captures. Avoid publishing personal paths, file contents, credentials, or baseline data.

## Requirements

- Windows (the tested platform)
- Python 3 with `venv` and `pip`
- Internet access for the initial dependency installation

The repository also includes `run.command` for macOS/Linux, but those platforms have not been validated.

## Quick start

### Windows launcher

Download or clone the repository, then double-click `run.bat`. It creates a virtual environment if needed, installs dependencies, and launches the application.

### Manual setup (PowerShell)

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

On first launch, create a baseline database password of at least 12 characters. SentinelFIM does not save this password. If it is forgotten, the database cannot be unlocked; the reset workflow starts a new database and preserves the old database as a locked backup.

## First scan

1. Select a file or folder in **Dashboard** or **Baseline Manager**.
2. Review recursion, exclusions, file-size limits, and other options in **Settings**.
3. Start monitoring and wait for a successful scan. The first successful scan creates a baseline when none exists for the target.
4. Review changes in **Alerts**, **System Inventory**, or **Forensic Analysis**.
5. Save a new baseline only after reviewing and explicitly accepting the changed state.

For a safe demonstration, create a disposable folder and edit or remove a test file. Do not use important files as test data or commit personal monitoring targets, baseline databases, preferences, or logs.

## How it works

1. SentinelFIM walks the selected target using normalized relative paths, subject to configured exclusions and limits.
2. Regular files are read in 1 MiB chunks while SHA-256 and SHA-512 fingerprints are calculated.
3. The resulting inventory is compared with the selected baseline. Matching files remain unchanged; new, modified, missing, and verified moved files are classified separately.
4. Findings and scan diagnostics are available for review. Optional AI interpretation uses selected incident evidence and does not replace the recorded scan results.

Coverage is bounded by configured exclusions, a 5,000-file cap, a configurable maximum file size, and text-diff limits. Review scan diagnostics for skipped or inaccessible content.

## Optional AI analysis

AI analysis is disabled unless you configure and explicitly use it. Gemini requires an API key and network access; Ollama requires a local service and model. For Gemini, selected incident evidence is sent to Google; file contents and unrelated alert history are not included. Store credentials through the OS credential vault when available, and treat all AI output as advisory.

## Security and limitations

- HMAC authentication can reveal database edits when the password remains secret. The baseline database is **not encrypted**; a copy on the same machine is not an independent trust anchor.
- Inaccessible files cannot be verified. A scan warning is not proof that a file was deleted.
- SentinelFIM does not provide write prevention, file recovery, antivirus scanning, network monitoring, or user/process attribution.
- It is a local desktop monitor, not a centralized fleet-management service. No PCI DSS, NIST, or other compliance certification is claimed.
- Review documented coverage limits and testing scope in the [project documentation](PROJECT_DOCUMENTATION.md).

## Documentation

- [Detailed project documentation](PROJECT_DOCUMENTATION.md)
- [Project guide (PDF)](docs/SentinelFIM_Project_Guide_Improved.pdf)
- [Documentation index](docs/README.md)
- [Screenshot capture guide](screenshots/README.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## Development and tests

Dependencies are listed in [`requirements.txt`](requirements.txt). Run the standard-library test suite with:

```powershell
python -m unittest discover -s tests -v
```

The documented test run covered 34 tests: 33 passed and one Windows symbolic-link integration test was skipped because the account lacked the required privilege. Live Gemini requests and actual ACL-denial integration were not tested; see the project documentation for full scope.

## Author

**Abhishek UM**

