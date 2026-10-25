# 🛡️ SentinelFIM

<p align="center">
  <strong>See what changed. Review the evidence. Protect file integrity.</strong><br>
  A Python desktop File Integrity Monitor for local, small-scope defensive security.
</p>

<p align="center">
  <img alt="Windows" src="https://img.shields.io/badge/platform-Windows-0078D4?logo=windows&logoColor=white">
  <img alt="Python" src="https://img.shields.io/badge/built%20with-Python-3776AB?logo=python&logoColor=white">
  <img alt="Defensive security" src="https://img.shields.io/badge/cybersecurity-defensive-1F6FEB">
</p>

SentinelFIM creates a trusted baseline of selected files and folders, then compares later scans to help you spot unexpected changes. Review findings through the desktop dashboard, alerts, file inventory, and forensic analysis.

> **Project scope:** SentinelFIM detects and reports file differences. It does not block changes or decide whether they are malicious. This is an educational defensive security tool, not a certified enterprise platform.

## 🎬 Project Demo

<p align="center">
  <a href="screenshots/Video%20Project%207.mp4">
    <img src="screenshots/Analysis%20output%201.png" alt="Open the SentinelFIM demonstration video" width="850">
  </a><br>
  <a href="screenshots/Video%20Project%207.mp4"><strong>▶ Watch the full SentinelFIM demo</strong></a>
</p>

## 🖥️ Application Screenshots

The numbered images below are the analysis captures in `screenshots/`. Screenshot 1 shows the starting dashboard; select any image to open the full-size capture.

<table>
  <tr>
    <td align="center"><strong>01 · Dashboard</strong><br><a href="screenshots/Analysis%20output%201.png"><img src="screenshots/Analysis%20output%201.png" alt="SentinelFIM starting dashboard" width="420"></a></td>
    <td align="center"><strong>03 · Analysis</strong><br><a href="screenshots/Analysis%20output%203.png"><img src="screenshots/Analysis%20output%203.png" alt="SentinelFIM analysis screen 3" width="420"></a></td>
    <td align="center"><strong>05 · Investigation</strong><br><a href="screenshots/Analysis%20output%205.png"><img src="screenshots/Analysis%20output%205.png" alt="SentinelFIM analysis screen 5" width="420"></a></td>
  </tr>
</table>

## ✨ What it can do

- Calculate **SHA-256** and **SHA-512** fingerprints while reading files in 1 MiB chunks.
- Detect and classify **created, modified, deleted, unchanged, and verified renamed** files.
- Keep scan errors distinct from deletions, so inaccessible paths are not silently treated as removed.
- Save baseline history in a local database authenticated with **HMAC-SHA-256** and a password-derived **scrypt** key.
- Review findings in a dashboard, alert list, nested inventory, and forensic investigation view.
- Optionally request incident analysis with **Google Gemini** or a local **Ollama** service.
- Use Watchdog notifications to wake scans early; periodic hash scans determine integrity findings.

Monitoring runs only while the application is open. Watchdog notifications do not block writes.

## 🚀 Quick start

### Windows launcher

1. Download or clone this repository.
2. Double-click `run.bat` and allow it to install the required packages and start the app.

### Manual setup with PowerShell

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Python 3 with `venv` and `pip` is required. Internet access is needed for the initial package installation. Windows is the tested platform; `run.command` is included for macOS/Linux, which have not been validated.

On first launch, create a baseline database password of at least 12 characters. SentinelFIM does not save it. If forgotten, the database cannot be unlocked; the reset workflow starts a new database and preserves the old one as a locked backup.

## 🔍 Use SentinelFIM

1. Select a file or folder from **Dashboard** or **Baseline Manager**.
2. Review recursion, exclusions, file-size limits, and other options in **Settings**.
3. Start monitoring and wait for the first successful scan. A baseline is created automatically if one does not already exist for the target.
4. Make a safe change in a disposable test folder and review the result in **Alerts**, **System Inventory**, or **Forensic Analysis**.
5. Save a new baseline only after reviewing and accepting the changed state.

## 🔐 Security notes and limits

- HMAC authentication can reveal database edits when your password remains secret. The database is **not encrypted**; a copy stored on the same machine is not an independent trust anchor.
- Inaccessible files cannot be verified. A scan warning is not proof that a file was deleted.
- Coverage is limited by exclusions, a 5,000-file cap, the configured maximum file size, and text-diff limits. Check scan diagnostics for skipped or inaccessible content.
- Gemini analysis is opt-in and user-triggered. Selected incident evidence is sent to Google; file contents and unrelated alert history are not included. AI results can be wrong and are advisory. Gemini needs an API key and network access; Ollama needs a configured local service and model.
- SentinelFIM does not provide write prevention, file recovery, antivirus scanning, network monitoring, or user/process attribution. No compliance certification is claimed.

## 📘 Project Documentation

- [Open the SentinelFIM project document (PDF)](docs/SentinelFIM_Project_DOC.pdf)

## 🧪 Tests

Run the test suite from the project directory:

```powershell
python -m unittest discover -s tests -v
```

The documented run covered 34 tests: 33 passed and one Windows symbolic-link integration test was skipped because the account lacked the required privilege. Live Gemini requests and actual ACL-denial integration were not tested.

## 👤 Author

**Abhishek UM**
 integration were not tested; see the project documentation for full scope.

## Author

**Abhishek UM**

