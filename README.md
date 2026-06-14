# Window Registry Examination

Offline Windows Registry forensic analysis tool with hash-verified
chain-of-custody, automatic decoding of encoded values, real-time
examiner action logging, and exportable PDF / CSV / JSON reports.



---

## Features

- **Pre & post analysis SHA-256 verification.** The examiner enters the
  reference hash recorded at acquisition. The tool computes the SHA-256
  of each imported hive file before any analysis begins, and re-verifies
  before generating any report. Mismatches are a hard stop — evidence
  whose integrity cannot be verified is never analysed.
- **Strict read-only operation.** Hive files are opened through
  `python-registry` in read-only mode; the source folder is never written
  to.
- **36 hard-coded forensic artifacts** across 9 categories (System
  Timeline, User Activity, USB, Persistence, Software Installation, User
  Accounts, Network Activity, Windows Logs) - covering every artifact in
  the project specification.
- **Automatic decoding.** FILETIME, Unix epoch, SYSTEMTIME, ROT-13 (for
  UserAssist), Base64, hexadecimal, UTF-16LE strings and `REG_MULTI_SZ`
  blobs are decoded and presented in plain English.
- **Severity highlighting.** Findings are flagged `WARNING`,
  `SUSPICIOUS`, or `HIGH RISK` (e.g. firewall disabled, non-system
  startup paths, encoded PowerShell, brute-force logon patterns) and
  color-coded in both the GUI and the PDF.
- **Real-time action log.** Every click, selection, view, note, hash
  check and export is recorded with a UTC timestamp into both an
  in-memory log and a persistent JSONL file in
  `~/.reghive_analyzer/logs/`.
- **Three export formats.** PDF (formatted, color-coded, signature
  block), CSV (flat, spreadsheet-friendly with chain-of-custody header),
  and JSON (full structured dump).

---

## Installation

```bash
# (Windows / macOS / Linux)
python -m pip install -r requirements.txt
```

`tkinter` ships with the standard Python distribution on Windows. On
Debian/Ubuntu install it via `sudo apt install python3-tk`.

## Running

```bash
python main.py
```

The splash dialog appears first and asks for:

1. **Examiner name**
2. **Case name / number**
3. **Reference SHA-256 hash** (64 hex characters, recorded at
   acquisition)
4. **Path to the evidence folder** containing the exported hive files
   (`SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `NTUSER.DAT`, `DEFAULT`)
   and, optionally, exported `.evtx` event-log files.

When you click **Begin Analysis**, the tool:

- Computes the SHA-256 of every file in the folder.
- Builds a deterministic composite hash (sorted by relative path).
- Compares it to your reference hash.
- Opens the main analysis window only on a match. **Mismatches are a
  hard stop** — the tool will not proceed.

## Computing Reference Hashes

Reference SHA-256 hashes must be computed with an **external tool at
acquisition time**, before the evidence is handed off for analysis.

### Single file

```bash
# Linux / macOS
sha256sum SYSTEM

# Windows PowerShell
Get-FileHash -Algorithm SHA256 .\SYSTEM
```

### All hive files in a folder

```bash
# Linux / macOS
for f in SYSTEM SOFTWARE SAM SECURITY NTUSER.DAT DEFAULT; do
  [ -f "$f" ] && sha256sum "$f"
done

# Windows PowerShell
@('SYSTEM','SOFTWARE','SAM','SECURITY','NTUSER.DAT','DEFAULT') |
  ForEach-Object { if (Test-Path $_) { Get-FileHash -Algorithm SHA256 $_ } }
```

Record the hash for each file and enter it when prompted during upload.

## Project Layout

```
RegHiveForensicAnalyzer/
  main.py                          # entry point
  requirements.txt
  core/
    __init__.py
    hash_verifier.py               # SHA-256 streaming + folder hash + checks
    decoder.py                     # FILETIME, Base64, ROT-13, UTF-16, hex...
    registry_parser.py             # python-registry wrapper, hive detection
    artifact_definitions.py        # all 36 artifacts + EVTX parsers
    action_logger.py               # thread-safe append-only audit log
    report_generator.py            # PDF / CSV / JSON exporters
  gui/
    __init__.py
    splash_window.py               # case intake + pre-analysis hash check
    artifact_view.py               # color-coded result table + notes
    main_window.py                 # toolbar, sidebar, action log, exports
```

## Forensic Workflow Implemented

```
   Examiner enters case info + reference hash + evidence folder
                              |
                              v
        Pre-analysis SHA-256 over the folder (composite)
                              |
            +-----------------+-----------------+
             | match                             | mismatch
             v                                   v
    Open main analysis window         HARD STOP — evidence
             |                       cannot be analysed.
             v                       Examiner must fix the
    Read-only artifact extraction    hash or re-acquire.
   (every action -> action log,
    every encoded value -> decoded)
            |
            v
   Examiner clicks Export PDF/CSV/JSON
            |
            v
   Post-analysis SHA-256 (mandatory revalidation)
            |
            v
   Generate report including:
   - chain-of-custody header
   - pre & post integrity stamps
   - all viewed artifacts with rows + flags
   - examiner notes per artifact
   - full action log
```

## Artifacts Implemented (matches specification tables 1-9)

1. **System Timeline & State Reconstruction** - Last shutdown, boot
   configuration, hardware profile, timezone, docking profile.
2. **User Activity & Behavior Analysis** - RecentDocs, UserAssist
   (ROT-13 decoded), RunMRU, WordWheelQuery, Open/Save dialogs.
3. **USB & External Device Usage** - USBSTOR, USB connection
   timestamps, MountedDevices, per-user MountPoints2.
4. **Program Execution & Persistence** - System & user Run keys,
   ShimCache, file-association `\shell\open\command`, COM `CLSID` 
   InprocServer32 paths.
5. **Software Installation & Unauthorized Apps** - Uninstall
   (incl. Wow6432Node), OS install date, RegisteredApplications.
6. **User Accounts & Authentication** - SAM `V`/`F` records (decoded
   in pure Python: usernames, full names, last logon, password
   policies, account flags, login & failed-login counts), 
   LSA Secrets enumeration.
7. **Network Activity & Connectivity** - Tcpip interfaces (DHCP IP &
   gateway), adapter GUIDs, network profiles (SSID + first/last
   connect), wireless profiles, VPN, mapped drives, firewall.
8. **(intentionally not assigned in the spec)**
9. **Windows Log Analysis** - System.evtx (6005/6006/6008),
   Security.evtx (4624/4625/4648/4672 + brute-force detection),
   Application.evtx, PowerShell %4Operational (with `-enc` base64
   detection), Windows Defender %4Operational.

## Notes for Examiners

- The tool detects hive type from the hive's *root key children*, not
  the filename, so renaming a hive cannot mislead it.
- Encoded PowerShell command-line arguments (`-enc`) are flagged
  `HIGH RISK` and the base64 payload is decoded inline.
- Three or more consecutive failed Security-log logons (4625) raise a
  brute-force `HIGH RISK` flag.
- Real-time-protection-disabled events (Defender 5001) raise a
  `HIGH RISK` flag.
- Suspicious autorun paths in `\Temp\`, `\AppData\Local\Temp\`,
  `\Users\Public\`, `\Windows\Debug\`, `\ProgramData\`, or
  `\$Recycle.Bin\` raise a `SUSPICIOUS` flag.

## Limitations (in scope per the FYP proposal)

- Offline analysis only - the tool never reads the live registry of
  the host it runs on.
- LSA Secrets are *enumerated* but not decrypted (the SYSTEM boot key
  & cryptographic chain are out of scope per the proposal).
- `.evtx` parsing requires `python-evtx`; PDF export requires
  `reportlab`. Both are listed in `requirements.txt`.


