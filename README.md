# SentinelFIM

**A local-first desktop file integrity monitor for Windows.** SentinelFIM creates a trusted file baseline, checks later scans against it, and helps you review unexpected changes with alerts, an inventory, and forensic details.

> SentinelFIM is an educational defensive security project. It detects and reports file differences; it does not prevent changes or determine whether they are malicious.

## What it does

- Fingerprints regular files with SHA-256 and SHA-512 while reading in 1 MiB chunks.
- Detects created, tampered, deleted, and byte-identical renamed files.
- Keeps scan errors distinct from deletions so inaccessible paths are not silently treated as removed.
- Stores local baseline history in an HMAC-authenticated database using a key derived from a password with scrypt.
- Provides a desktop dashboard, alert details, a nested file inventory, baseline management, and forensic review.
- Optionally offers incident summaries through Gemini or a local Ollama service. AI analysis is user-triggered and advisory.
- Uses Watchdog notifications to wake scans early; periodic scans recalculate hashes and determine findings.

Monitoring runs only while the application is open. Watchdog notifications do not block file writes.

## Screenshots and demo

Current screenshots and a demo video are not included in this checkout. The `screenshots/` directory explains how to capture and add genuine screenshots from the running application. No mock images are presented as product captures.

## Requirements

- Windows (the tested platform)
- Python 3 with `venv` and `pip`
- Internet access for the first dependency installation

`run.bat` sets up a local virtual environment, installs dependencies when needed, and starts the application. macOS/Linux users can try `run.command`; those platforms have not been validated.

## Quick start

1. Download or clone this repository.
2. On Windows, double-click `run.bat`, or use PowerShell:

   ```powershell
   py -3 -m venv .venv
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   .\.venv\Scripts\python.exe app.py
   ```

3. On first launch, create a baseline database password of at least 12 characters. The password is not saved. If you forget it, the existing database cannot be unlocked; reset starts a new database and preserves the old one as a locked backup.
4. Select a file or folder, review monitoring settings, and start monitoring. The first successful scan creates a baseline if one does not already exist for that target.

For a safe demonstration, monitor a disposable folder and edit a test file. Review the resulting alert and inventory entry before accepting any changed state into a new baseline. Do not commit personal monitoring targets, baseline databases, preferences, or logs.

## How findings are produced

1. SentinelFIM walks the selected target using normalized relative paths, subject to exclusions and configured limits.
2. It calculates SHA-256 and SHA-512 hashes and compares the resulting inventory with the selected baseline.
3. Matching files remain unchanged; new, changed, missing, and verified moved files receive separate classifications.
4. Review findings in Alerts, System Inventory, or Forensic Analysis. Optional AI interpretation is separate from the recorded scan evidence.

Coverage is bounded by configured exclusions, a 5,000-file cap, maximum file size, and text-diff limits. Review scan diagnostics for skipped or inaccessible content.

## Security notes

- HMAC authentication can reveal database edits when the password remains secret. The database is not encrypted, and a same-machine copy is not an independent trust anchor.
- Inaccessible content cannot be verified. A scan warning is not proof that a file was deleted.
- Gemini analysis is opt-in. When requested, selected incident evidence is sent to Google; file contents and unrelated alert history are not included. The response may be wrong. Gemini requires an API key and network access; Ollama requires a configured local service and model.
- SentinelFIM is not antivirus, write protection, file recovery, network monitoring, or a centralized fleet-management service. No compliance certification is claimed.

## Documentation

- [Project guide (current)](docs/SentinelFIM_Project_Guide_Improved.pdf)
- [Detailed project documentation](PROJECT_DOCUMENTATION.md)
- [Documentation index and historical reports](docs/README.md)
- [Screenshot capture guidance](screenshots/README.md)

## Development

Dependencies are listed in `requirements.txt`. The automated suite uses Python's standard-library `unittest`:

```powershell
python -m unittest discover -s tests -v
```

The documented test run covered 34 tests: 33 passed and one Windows symbolic-link integration test was skipped because the account lacked the required privilege. Live Gemini requests and actual ACL-denial integration were not tested. See the project documentation for test scope and limitations.

## Author

**Abhishek UM**
