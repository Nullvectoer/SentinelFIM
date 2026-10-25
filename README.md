# SentinelFIM HEAD

A Python desktop File Integrity Monitor (FIM) that records a trusted file baseline and compares later scans to identify file changes for review.

## Overview

SentinelFIM helps a user notice unexpected changes to selected files and folders. It calculates file fingerprints, compares them with a saved baseline, and presents findings in a desktop dashboard, alert list, inventory, and forensic review. It is an educational defensive cybersecurity project for local, small-scope monitoring. It detects and reports differences; it does not prevent changes or determine whether they are malicious.

## Features

- Select a file or folder, scan nested directories, and exclude configured folder names.
- Calculate SHA-256 and SHA-512 while reading regular files in 1 MiB chunks.
- Save and manage baseline history; authenticate the local baseline database with HMAC-SHA-256 using a key derived from a user password with scrypt.
- Classify created, tampered, deleted, and verified rename events. Scan errors are distinct from deletions.
- Browse nested file inventory, sizes, hashes, status filters, and recent alert history.
- View alert details and open a separate forensic investigation view.
- Use optional Gemini analysis or local Ollama analysis when explicitly enabled. Gemini analysis receives selected incident evidence, not file contents; its output is advisory.
- Use Watchdog file-system notifications to wake scans early, plus periodic scans that recalculate hashes and compare against the baseline.

## Application Screenshots

Current, readable screenshots from the working application are not included yet. No mock or outdated captures are presented as current. See [screenshots/README.md](screenshots/README.md) for the specific captures to add before publication.

## Technology Stack

| Area | Implementation |
| --- | --- |
| Language / desktop UI | Python, PyQt6 |
| File-system notifications | Watchdog |
| File fingerprinting | Python `hashlib`: SHA-256 and SHA-512 |
| Baseline database authentication | `hmac` with an scrypt-derived key |
| Optional AI | Google Gen AI SDK (`google-genai`) or local Ollama endpoint |
| Credential storage | `keyring` for an optional Gemini API key |
| Automated tests | Python standard-library `unittest` |

## How It Works

1. **Select a target.** Choose a file or folder, or paste its path. Folder scans can include nested subfolders; exclusions and file-size limits apply.
2. **Create or load a baseline.** If no baseline exists for the target, the first successful scan saves an initial snapshot. A user can also explicitly save a new baseline after reviewing and accepting changes.
3. **Scan and calculate fingerprints.** The scanner walks the target using normalized relative paths and reads files in 1 MiB chunks while calculating SHA-256 and SHA-512.
4. **Compare to the selected baseline.** Matching digests are unchanged. Different digests, new paths, missing paths, and byte-identical moves are classified separately. Uncertain paths with scan errors are not treated as deleted.
5. **Review the evidence.** Use Alerts for a plain-language summary and details, System Inventory to browse path/status/hash information, and Forensic Analysis for technical evidence. Optional AI interpretation is separate from observed scan evidence.

Watchdog notifications are a wake-up aid; they do not block file writes. Periodic hash scans determine the integrity findings. SentinelFIM must remain running to monitor.

## Project Structure

```text
.
├── app.py
├── requirements.txt
├── run.bat
├── run.command
├── PROJECT_DOCUMENTATION.md
├── tests/
│   ├── test_app.py
│   ├── test_forensics.py
│   ├── test_inventory.py
│   └── test_long_monitoring.py
├── docs/                             # Published PDFs and documentation index
├── screenshots/                      # Genuine app screenshots when available
├── output/                           # Local/generated PDFs; ignored by Git
├── tmp/                              # Local test logs and temporary renders; ignored
└── watch_folder/                     # Local monitoring target; ignored
```

No sample monitoring target is bundled. For demonstrations, create a disposable folder with files you can safely edit or remove. Do not commit your personal `watch_folder/`, local baseline database, preferences, or scan logs.

## Prerequisites

- Windows is the tested desktop platform. The repository also includes a `run.command` launcher for macOS/Linux, but those platforms have not been validated here.
- Python 3 with `venv` and `pip`. The current project test environment used Python 3.12.14. The repository does not pin a minimum Python version.
- Internet access for the first dependency installation. It is not required for local file monitoring after dependencies are installed. Gemini requires an API key and network access; Ollama requires a local Ollama service and model.

## Installation

### Windows

The simplest setup is to run `run.bat` from the project folder. The launcher selects `py -3` or `python`, creates `.venv` when missing, installs `requirements.txt` when required packages are unavailable, then launches `app.py`.

Manual setup:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

The dependency list was checked against the application imports, and `pip install --dry-run -r requirements.txt` resolved successfully in the existing Python 3.12.14 environment. A clean-machine installation was not performed. This host has no system Python registered with `py -3`, so the fresh-environment creation step could not be verified here.

## Running the Application

On Windows, double-click `run.bat`, or launch the installed environment directly:

```powershell
.\.venv\Scripts\python.exe app.py
```

On macOS/Linux, `run.command` provides a corresponding `python3`/`python` and `.venv/bin/python` setup flow. This launcher is present in the repository but has not been tested on those operating systems.

At first launch, create a baseline database password of at least 12 characters. The application does not save the password. A forgotten password cannot be recovered; the reset workflow starts a new baseline database and preserves the old database as a locked backup.

## Usage

1. Open **Dashboard** or **Baseline Manager** and select a file or folder.
2. Review recursion, exclusions, file-size limit, and other monitoring options in **Settings**.
3. Select **Start monitoring** and wait for a successful scan. If this target has no existing baseline, the first successful scan creates one automatically.
4. Create or edit a file in a disposable test folder. Avoid experimenting on important files.
5. Open **Alerts** for Details or Investigate, or use **System Inventory** to locate the relative path and review its current status and hashes.
6. Save a new baseline only after you have reviewed and explicitly accepted the changed state.

Use a disposable folder to exercise TAMPERED, CREATED, and DELETED events. Do not use a personal `watch_folder/` as a public sample directory.


## Security Considerations

- A baseline is only as trustworthy as the process and storage that created and protect it. HMAC authentication detects database edits when the password remains secret; the database is not encrypted and a same-machine copy is not an independent trust anchor.
- Inaccessible files and directories cannot be verified. Scan warnings must be resolved or investigated; absence during an uncertain scan is not treated as proof of deletion.
- Monitoring stops when the application stops. Watchdog notifications improve scan responsiveness but do not prevent writes or replace periodic hash comparison.
- Exclusions, the 5,000-file cap, the configurable maximum file size, and text-diff cache limits bound coverage and resource use. Review scan diagnostics for skipped or inaccessible content.
- Gemini analysis is opt-in and user-triggered. The selected incident's recorded evidence is sent to Google for analysis; file contents and unrelated alert history are not included. API keys are not written to preferences; the app can store them in the OS credential vault. AI output may be wrong and is not a substitute for evidence review.

## Known Limitations

- No write prevention, file recovery, antivirus scanning, network monitoring, or user/process attribution.
- The app is a local desktop monitor, not a centralized enterprise fleet-management service.
- No live Gemini service request, real ACL-denial integration test, or privileged symlink integration test is included in the reported test run.
- Empty-folder history is session-local; file baselines and scan errors have different persistence behavior.
- Text diffs are bounded. Binary and large files can show size/hash evidence without a text diff.
- No PCI DSS, NIST, or other certification/compliance claim is made.

## Documentation

- [Current SentinelFIM Project Guide](docs/SentinelFIM_Project_DOC.pdf)

## Disclaimer

SentinelFIM is an educational defensive cybersecurity application for learning and local file-integrity review. It is not a certified enterprise security platform, and it does not guarantee that monitored files or systems are safe. Validate findings and use organizational change-management and incident-response processes.

## Author

**Author:** Abhishek UM



A Python-based File Integrity Monitoring (FIM) application for detecting file changes, monitoring filesystem activity, and supporting security investigations.
>>>>>>> 03647cfbd3233c7a11d50d93b61d6417cf557e4b
