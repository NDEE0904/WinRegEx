"""
Artifact Definitions
====================
All 36 forensic artifacts hard-coded as ArtifactDefinition objects.

Every artifact is described by:
    * name             - human label shown in the sidebar
    * category         - sidebar group
    * required_hive    - HiveType this artifact requires
    * key_path         - registry path RELATIVE to that hive's root
    * forensic_value   - what it tells an investigator
    * forensic_question- the question it answers
    * extractor        - callable(hive: LoadedHive) -> ArtifactResult

Each extractor returns an ArtifactResult containing rows of structured,
human-readable findings. Extractors must NEVER raise; they wrap their
own errors and return them in the ArtifactResult.error field so the
GUI can render the error inline rather than crashing.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .decoder import (
    auto_decode,
    decode_filetime,
    decode_systemtime,
    decode_unix_epoch,
    decode_yyyymmdd,
    decode_rot13,
    format_bias,
    hex_dump,
    interpret_boolean_dword,
    utf16le_multi_sz,
    utf16le_to_str,
)
from .registry_parser import (
    HiveType,
    LoadedHive,
    active_controlset_path,
    get_value_raw,
    key_last_write_utc,
    list_subkeys,
    list_values,
    open_key,
)


# ---------------------------------------------------------------------------
# Result containers
# ---------------------------------------------------------------------------

@dataclass
class ArtifactRow:
    """A single row of findings inside an artifact result table."""
    fields: Dict[str, str] = field(default_factory=dict)
    interpretation: str = ""
    flag: str = ""  # "" / "WARNING" / "SUSPICIOUS" / "HIGH RISK"


@dataclass
class ArtifactResult:
    artifact_name: str
    columns: List[str]
    rows: List[ArtifactRow] = field(default_factory=list)
    summary: str = ""
    error: Optional[str] = None
    raw_key_last_write: str = ""

    @property
    def row_count(self) -> int:
        return len(self.rows)


@dataclass
class ArtifactDefinition:
    name: str
    category: str
    required_hive: HiveType
    key_path: str
    forensic_value: str
    forensic_question: str
    extractor: Callable[[LoadedHive], ArtifactResult]


# ---------------------------------------------------------------------------
# Helper that wraps every extractor with consistent error handling
# ---------------------------------------------------------------------------

def _safe(extractor):
    def wrapper(hive: LoadedHive) -> ArtifactResult:
        try:
            result = extractor(hive)
            if result is None:
                return ArtifactResult(
                    artifact_name=extractor.__name__,
                    columns=[],
                    error="Extractor returned no result.",
                )
            return result
        except Exception as exc:  # noqa: BLE001
            return ArtifactResult(
                artifact_name=extractor.__name__,
                columns=[],
                error=f"Unhandled error during extraction: {exc.__class__.__name__}: {exc}",
            )
    wrapper.__name__ = extractor.__name__
    return wrapper


def _hive_missing_result(name: str, hive_type: HiveType) -> ArtifactResult:
    return ArtifactResult(
        artifact_name=name,
        columns=[],
        error=(f"Required hive '{hive_type.value}' has not been imported. "
               "Please use Import Hive to load it."),
    )


def _key_not_found_result(name: str, path: str) -> ArtifactResult:
    return ArtifactResult(
        artifact_name=name,
        columns=[],
        error=f"Key not found in imported hive. Expected path: {path}",
    )


# ===========================================================================
# DFIR Network Activity formatting helpers
# ===========================================================================
# These helpers enforce the standardized presentation contract for the
# Network Activity section: missing values are rendered as the em-dash
# placeholder "—" so evidentiary gaps are visible rather than silently
# omitted, and timestamps are normalized to "YYYY-MM-DD HH:MM UTC"
# (24-hour). Empty result sets are still rendered with one placeholder
# row to evidence that the artifact was examined.

DFIR_MISSING = "—"  # U+2014 em dash


def _dfir(value: Any) -> str:
    """Coerce a value to its display string, replacing empty / None
    with the em-dash placeholder."""
    if value is None:
        return DFIR_MISSING
    s = str(value).strip()
    return s if s else DFIR_MISSING


def _dfir_time(decoded: Any) -> str:
    """Normalise a decoded timestamp string to 'YYYY-MM-DD HH:MM UTC'.

    Accepts the verbose UTC strings produced by decode_filetime,
    decode_unix_epoch, decode_systemtime, key_last_write_utc, etc., or
    returns the em-dash placeholder when the input is empty.
    """
    if not decoded:
        return DFIR_MISSING
    s = str(decoded).strip()
    if not s:
        return DFIR_MISSING
    parts = s.split(" ")
    if len(parts) >= 2 and len(parts[0]) == 10 and parts[0][4] == "-":
        date = parts[0]
        time = parts[1][:5]
        suffix = parts[2] if len(parts) >= 3 else "UTC"
        return f"{date} {time} {suffix}"
    return s


def _dfir_finalize(result: ArtifactResult) -> ArtifactResult:
    """Per the spec, an examined-but-empty artifact must still render a
    single placeholder row of '—' across every column."""
    if not result.error and not result.rows and result.columns:
        result.rows.append(ArtifactRow(
            fields={c: DFIR_MISSING for c in result.columns}))
    return result


def _executable_from_command(command: str) -> str:
    """Best-effort extraction of the executable path from a command line.

    Handles three common forms:
      "C:\\Program Files\\App\\app.exe" /silent  ->  C:\\Program Files\\App\\app.exe
      C:\\Tools\\thing.exe arg1 arg2             ->  C:\\Tools\\thing.exe
      rundll32 C:\\dll.dll,EntryPoint            ->  rundll32

    The function never raises - any unexpected input falls back to the
    leading whitespace-delimited token.
    """
    s = (command or "").strip()
    if not s:
        return ""
    # Quoted form: "exe path" trailing args
    if s.startswith('"'):
        end = s.find('"', 1)
        if end > 0:
            return s[1:end]
    # Heuristic: scan for an extension boundary so unquoted paths with
    # spaces (e.g. "C:\Program Files\App\app.exe /flag") don't get
    # truncated at the first space.
    lower = s.lower()
    for ext in (".exe", ".dll", ".bat", ".cmd", ".com", ".scr",
                ".vbs", ".ps1", ".jse", ".wsf", ".hta"):
        idx = lower.find(ext)
        if idx > 0:
            cut = idx + len(ext)
            if cut == len(s) or s[cut] in (" ", "\t", '"', ","):
                return s[:cut]
    # Fallback: whitespace tokenize
    return s.split()[0] if s.split() else s


def _basename_win(path: str) -> str:
    """Windows-style basename: split on either separator, ignore trailing."""
    p = (path or "").strip().replace("/", "\\").rstrip("\\")
    return p.rsplit("\\", 1)[-1] if "\\" in p else p


def _user_from_hive(hive: LoadedHive) -> str:
    """Best-effort: pull the username from an NTUSER.DAT hive's path/name.

    Looks for 'Users\\<name>\\NTUSER.DAT' or
    'Documents and Settings\\<name>\\...' patterns, with
    'NTUSER_<name>.DAT' as the fallback. Returns '' when the user
    cannot be determined - the caller should render that as '—'.
    """
    if not hive:
        return ""
    fp = (hive.file_path or "").replace("/", "\\")
    parts = fp.split("\\")
    for i, p in enumerate(parts[:-1]):
        if p.lower() in ("users", "documents and settings"):
            if i + 1 < len(parts):
                cand = parts[i + 1]
                if cand and cand.lower() not in (
                        "default", "default user", "public",
                        "all users", "defaultappuser"):
                    return cand
    fn = (hive.file_name or "").lower()
    if fn.startswith("ntuser_") and fn.endswith(".dat"):
        return (hive.file_name or "")[7:-4]
    return ""


# ===========================================================================
# CATEGORY 1 - SYSTEM TIMELINE & STATE RECONSTRUCTION
# ===========================================================================

@_safe
def extract_last_shutdown_time(hive: LoadedHive) -> ArtifactResult:
    name = "Last Shutdown Time"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.SYSTEM)

    cs = active_controlset_path(hive)
    key = open_key(hive, rf"{cs}\Control\Windows")
    if key is None:
        return _key_not_found_result(name, rf"{cs}\Control\Windows")

    raw, _vt = get_value_raw(key, "ShutdownTime")
    result = ArtifactResult(
        artifact_name=name,
        columns=["Value Name", "Decoded Value", "Encoding"],
        raw_key_last_write=key_last_write_utc(key),
    )
    if raw is None:
        result.error = "ShutdownTime value not present in this hive."
        return result

    decoded = decode_filetime(raw if isinstance(raw, int) else bytes(raw))
    if decoded is None:
        result.error = "ShutdownTime present but could not be decoded as FILETIME."
        return result

    result.rows.append(ArtifactRow(
        fields={
            "Value Name": "ShutdownTime",
            "Decoded Value": decoded,
            "Encoding": "FILETIME (8-byte little-endian, 100-ns intervals since 1601-01-01 UTC)",
        },
        interpretation=f"The system was last powered off on {decoded}. This timestamp "
                       "establishes the upper bound of system activity for the "
                       "investigation timeline.",
    ))
    result.summary = f"Last shutdown: {decoded}"
    return result


@_safe
def extract_boot_configuration(hive: LoadedHive) -> ArtifactResult:
    name = "Boot Configuration"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.SYSTEM)

    key = open_key(hive, "Select")
    if key is None:
        return _key_not_found_result(name, "Select")

    result = ArtifactResult(
        artifact_name=name,
        columns=["Value Name", "Numeric Value", "Interpretation"],
        raw_key_last_write=key_last_write_utc(key),
    )

    for vname in ("Current", "Default", "Failed", "LastKnownGood"):
        raw, _ = get_value_raw(key, vname)
        if raw is None:
            continue
        try:
            num = int(raw)
            interpretation = f"ControlSet{num:03d}" if num else "(none)"
            row = ArtifactRow(
                fields={
                    "Value Name": vname,
                    "Numeric Value": str(num),
                    "Interpretation": interpretation,
                },
            )
            if vname == "Failed" and num != 0:
                row.flag = "WARNING"
                row.interpretation = (f"A failed boot was recorded against "
                                      f"ControlSet{num:03d}. Investigate.")
            result.rows.append(row)
        except (TypeError, ValueError):
            continue

    if not result.rows:
        result.error = "Select key exists but no recognized values found."
    else:
        current = next((r.fields.get("Interpretation", "") for r in result.rows
                        if r.fields.get("Value Name") == "Current"), "")
        result.summary = f"Active control set: {current}"
    return result


@_safe
def extract_hardware_profile(hive: LoadedHive) -> ArtifactResult:
    name = "Current Hardware Profile"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.SYSTEM)

    cs = active_controlset_path(hive)
    key = (open_key(hive, rf"{cs}\Control\IDConfigDB\Hardware Profiles")
           or open_key(hive, r"Control\IDConfigDB\Hardware Profiles"))
    if key is None:
        return _key_not_found_result(name, rf"{cs}\Control\IDConfigDB\Hardware Profiles")

    result = ArtifactResult(
        artifact_name=name,
        columns=["Profile ID", "Friendly Name", "Last Modified (UTC)"],
        raw_key_last_write=key_last_write_utc(key),
    )

    for sub in list_subkeys(key):
        try:
            friendly_raw, vt = get_value_raw(sub, "FriendlyName")
            friendly = auto_decode(friendly_raw, vt, "FriendlyName").display if friendly_raw else "(none)"
            result.rows.append(ArtifactRow(
                fields={
                    "Profile ID": sub.name(),
                    "Friendly Name": friendly,
                    "Last Modified (UTC)": key_last_write_utc(sub),
                },
            ))
        except Exception:  # noqa: BLE001
            continue

    if not result.rows:
        result.summary = "No hardware profiles defined."
    else:
        result.summary = f"{len(result.rows)} hardware profile(s) found."
    return result


@_safe
def extract_timezone_settings(hive: LoadedHive) -> ArtifactResult:
    name = "Timezone Settings"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.SYSTEM)

    cs = active_controlset_path(hive)
    key = open_key(hive, rf"{cs}\Control\TimeZoneInformation")
    if key is None:
        return _key_not_found_result(name, rf"{cs}\Control\TimeZoneInformation")

    result = ArtifactResult(
        artifact_name=name,
        columns=["Setting", "Value", "Interpretation"],
        raw_key_last_write=key_last_write_utc(key),
    )

    tz_name_raw, vt = get_value_raw(key, "TimeZoneKeyName")
    tz_name = auto_decode(tz_name_raw, vt, "TimeZoneKeyName").display if tz_name_raw else "(unknown)"
    result.rows.append(ArtifactRow(
        fields={"Setting": "TimeZoneKeyName", "Value": tz_name,
                "Interpretation": "The system's configured timezone identifier."}))

    bias_raw, _ = get_value_raw(key, "Bias")
    if bias_raw is not None:
        try:
            bias = int(bias_raw)
            # Windows stores Bias as a signed 32-bit integer; reinterpret if needed
            if bias > 2_000_000_000:
                bias -= 1 << 32
            offset = format_bias(bias)
            result.rows.append(ArtifactRow(
                fields={"Setting": "Bias", "Value": str(bias),
                        "Interpretation": f"Standard-time offset from UTC: {offset}"}))
        except (TypeError, ValueError):
            pass

    active_bias_raw, _ = get_value_raw(key, "ActiveTimeBias")
    if active_bias_raw is not None:
        try:
            ab = int(active_bias_raw)
            if ab > 2_000_000_000:
                ab -= 1 << 32
            offset = format_bias(ab)
            result.rows.append(ArtifactRow(
                fields={"Setting": "ActiveTimeBias", "Value": str(ab),
                        "Interpretation": f"Currently-active offset from UTC: {offset}"}))
        except (TypeError, ValueError):
            pass

    result.summary = f"Timezone: {tz_name}"
    return result


# Docking Profile extractor removed per Change 7 — artifact retired
# from the System Timeline category.


# ===========================================================================
# CATEGORY 2 - USER ACTIVITY & BEHAVIOR ANALYSIS
# ===========================================================================

@_safe
def extract_recent_docs(hive: LoadedHive) -> ArtifactResult:
    """User Activity / Artifact 1 - RecentDocs.

    Columns: MRU Order | File Name | File Type | Source Key

    Walks the RecentDocs root and every per-extension subkey. For each
    (sub)key the MRU order comes from MRUListEx (a stream of int32
    slot indices terminated by 0xFFFFFFFF, where index 0 in the
    stream is the most recent). File names are UTF-16LE strings
    embedded at the start of each binary value.
    """
    name = "Recently Opened Files (RecentDocs)"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.NTUSER)

    key = open_key(
        hive, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs")
    if key is None:
        return _key_not_found_result(
            name, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs")

    result = ArtifactResult(
        artifact_name=name,
        columns=["MRU Order", "File Name", "File Type", "Source Key"],
        raw_key_last_write=key_last_write_utc(key),
    )

    def _decode_filename(raw: bytes) -> str:
        """First UTF-16LE NUL-terminated string in a RecentDocs value."""
        if not isinstance(raw, (bytes, bytearray)) or len(raw) < 2:
            return ""
        b = bytes(raw)
        for i in range(0, len(b) - 1, 2):
            if b[i] == 0 and b[i + 1] == 0:
                return b[:i].decode("utf-16-le", errors="replace")
        return b.decode("utf-16-le", errors="replace").split("\x00")[0]

    def _parse_mru_listex(mru_raw: Any) -> List[int]:
        if not isinstance(mru_raw, (bytes, bytearray)):
            return []
        b = bytes(mru_raw)
        out: List[int] = []
        for i in range(0, len(b) - 3, 4):
            n = struct.unpack_from("<i", b, i)[0]
            if n == -1:  # terminator
                break
            out.append(n)
        return out

    def _process_key(source_label: str, k: Any,
                     ext_for_subkey: Optional[str]) -> None:
        """Walk one RecentDocs (sub)key.

        ext_for_subkey is the file-type derived from the subkey name
        for per-extension subkeys (e.g. '.pdf'). For the root RecentDocs
        key, this is None and the file type is inferred from each
        filename's own extension instead.
        """
        mru_raw, _ = get_value_raw(k, "MRUListEx")
        order = _parse_mru_listex(mru_raw)
        values_by_slot = {
            v.name: v for v in list_values(k)
            if v.name.lower() != "mrulistex"
        }

        if order:
            iterable = enumerate(order)
        else:
            # Fall back: stable order of slot numbers
            slot_keys = sorted(values_by_slot.keys(),
                               key=lambda s: int(s) if s.isdigit() else 1 << 30)
            iterable = enumerate(slot_keys)

        for mru_pos, slot in iterable:
            slot_str = str(slot)
            v = values_by_slot.get(slot_str)
            if v is None:
                continue
            filename = _decode_filename(v.raw)
            if not filename:
                continue
            if ext_for_subkey is not None:
                file_type = ext_for_subkey
            elif "." in filename:
                file_type = "." + filename.rsplit(".", 1)[-1].lower()
            else:
                file_type = ""

            result.rows.append(ArtifactRow(fields={
                "MRU Order": str(mru_pos),
                "File Name": _dfir(filename),
                "File Type": _dfir(file_type),
                "Source Key": _dfir(source_label),
            }))

    # Top-level RecentDocs (mixed extensions, mirrors all subkeys)
    _process_key("(root)", key, None)
    # Per-extension subkeys
    for sub in list_subkeys(key):
        ext = sub.name()
        _process_key(ext, sub, ext)

    result.summary = (f"{len(result.rows)} recent-document entry(ies) "
                      f"recovered, ordered by MRU position.")
    return _dfir_finalize(result)


@_safe
def extract_userassist(hive: LoadedHive) -> ArtifactResult:
    """User Activity / Artifact 2 - UserAssist.

    Columns: Program Name | Path | Run Count | Last Executed | Source GUID

    Each value name is ROT-13 encoded. After decoding, the entry is
    typically one of:
      - A full path: 'C:\\Program Files\\App\\app.exe'
      - A KNOWNFOLDERID-rooted path:
        '{F38BF404-1D43-42F2-9305-67DE0B28FC23}\\notepad.exe'
      - A modern app entity: 'Microsoft.Notepad_8wekyb3d8bbwe!App'
      - An internal counter:  'UEME_CTLSESSION', 'UEME_RUNPATH', ...
        (filtered out - these are not program executions).
    """
    name = "Program Execution (UserAssist)"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.NTUSER)

    base_key = open_key(
        hive, r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")
    if base_key is None:
        return _key_not_found_result(
            name, r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")

    result = ArtifactResult(
        artifact_name=name,
        columns=["Program Name", "Path", "Run Count",
                 "Last Executed", "Source GUID"],
        raw_key_last_write=key_last_write_utc(base_key),
    )

    # Common KNOWNFOLDERID GUIDs that prefix UserAssist entries. Lower-cased,
    # braces stripped. Mapping reflects the public GUIDs used by Windows so
    # the analyst sees a friendly path root in the Path column.
    KFID = {
        "0762d272-c50a-4bb0-a382-697dcd729b80": "C:\\Users\\Public",
        "1ac14e77-02e7-4e5d-b744-2eb1ae5198b7": "C:\\Windows\\System32",
        "6d809377-6af0-444b-8957-a3773f02200e": "C:\\Program Files",
        "7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e": "C:\\Program Files (x86)",
        "905e63b6-c1bf-494e-b29c-65b732d3d21a": "C:\\Program Files",
        "b4bfcc3a-db2c-424c-b029-7fe99a87c641": "%USERPROFILE%\\Desktop",
        "f38bf404-1d43-42f2-9305-67de0b28fc23": "C:\\Windows",
        "f7f1ed05-9f6d-47a2-aaae-29d317c6f066": "C:\\Program Files\\Common Files",
        "fdd39ad0-238f-46af-adb4-6c85480369c7": "%USERPROFILE%\\Documents",
        "ae50c081-ebd2-438a-8655-8a092e34987a": "%APPDATA%",
        "374de290-123f-4565-9164-39c4925e467b": "%USERPROFILE%\\Downloads",
    }

    def _resolve_path(decoded_name: str) -> Tuple[str, str]:
        """Return (display_path, program_name) from a decoded value name."""
        s = decoded_name.strip()
        if not s:
            return "", ""
        # KNOWNFOLDERID GUID prefix: '{guid}\rest...'
        if s.startswith("{"):
            close = s.find("}")
            if close > 0:
                guid = s[1:close].lower()
                rest = s[close + 1:].lstrip("\\")
                root = KFID.get(guid)
                if root:
                    full = f"{root}\\{rest}" if rest else root
                    program = rest.rsplit("\\", 1)[-1] if rest else root
                    return full, program
                # Unknown GUID - keep the GUID in the path so the analyst
                # can still see something
                return s, rest.rsplit("\\", 1)[-1] if rest else s
        # Modern app activation ID: 'Microsoft.X_pub!App'
        if "!" in s and "\\" not in s and "/" not in s:
            return s, s.split("!", 1)[0]
        # Plain path
        if "\\" in s or s[1:3] == ":\\":
            return s, s.rsplit("\\", 1)[-1]
        return s, s

    for guid_key in list_subkeys(base_key):
        count_key = open_key_by_subkey(guid_key, "Count")
        if count_key is None:
            continue
        for v in list_values(count_key):
            decoded_name = decode_rot13(v.name)
            # Filter internal session counters - they are not program
            # execution events.
            if decoded_name.startswith("UEME_"):
                continue
            run_count = ""
            last_exec = ""
            if isinstance(v.raw, (bytes, bytearray)):
                b = bytes(v.raw)
                # Win 7+ UserAssist record (72 bytes typical):
                #   +0  DWORD session id
                #   +4  DWORD run count
                #   +8  DWORD focus count
                #   +60 FILETIME last executed
                try:
                    if len(b) >= 16:
                        rc = struct.unpack_from("<I", b, 4)[0]
                        run_count = str(rc) if rc > 0 else ""
                    if len(b) >= 68:
                        ft_value = struct.unpack_from("<Q", b, 60)[0]
                        decoded_ts = decode_filetime(ft_value)
                        if decoded_ts:
                            last_exec = decoded_ts
                except struct.error:
                    pass

            full_path, program_name = _resolve_path(decoded_name)

            result.rows.append(ArtifactRow(fields={
                "Program Name": _dfir(program_name),
                "Path": _dfir(full_path),
                "Run Count": _dfir(run_count),
                "Last Executed": _dfir_time(last_exec),
                "Source GUID": _dfir(guid_key.name()),
            }))

    # Sort: most-recently-executed first; entries with no timestamp last
    def _sort_key(row: ArtifactRow) -> Tuple[int, str]:
        ts = row.fields.get("Last Executed", "")
        if ts == DFIR_MISSING or not ts:
            return (1, row.fields.get("Program Name", ""))
        return (0, "_" * 64 + str(ts))  # ts ascending → invert below

    timed = [r for r in result.rows
             if r.fields.get("Last Executed") not in (DFIR_MISSING, "", None)]
    untimed = [r for r in result.rows
               if r.fields.get("Last Executed") in (DFIR_MISSING, "", None)]
    timed.sort(key=lambda r: r.fields.get("Last Executed", ""), reverse=True)
    untimed.sort(key=lambda r: r.fields.get("Program Name", "").lower())
    result.rows = timed + untimed

    result.summary = (f"{len(result.rows)} program-execution record(s) "
                      f"recovered. Internal session counters (UEME_*) "
                      f"have been filtered.")
    return _dfir_finalize(result)


def open_key_by_subkey(parent: Any, name: str) -> Optional[Any]:
    """Open a named subkey directly under `parent`, returning None if missing."""
    if parent is None:
        return None
    try:
        return parent.subkey(name)
    except Exception:
        return None


@_safe
def extract_run_mru(hive: LoadedHive) -> ArtifactResult:
    name = "Run Dialog Commands (RunMRU)"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.NTUSER)

    key = open_key(hive, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU")
    if key is None:
        return _key_not_found_result(name, r"Software\...\Explorer\RunMRU")

    result = ArtifactResult(
        artifact_name=name,
        columns=["Order", "Slot", "Command"],
        raw_key_last_write=key_last_write_utc(key),
    )

    mru_list_raw, _ = get_value_raw(key, "MRUList")
    order = list(mru_list_raw) if isinstance(mru_list_raw, str) else []
    values_by_name = {v.name: v for v in list_values(key) if v.name != "MRUList"}

    if order:
        for idx, slot in enumerate(order, start=1):
            v = values_by_name.get(slot)
            if not v:
                continue
            cmd = auto_decode(v.raw, v.value_type_name, v.name).display
            # The trailing '\1' is a separator marker - strip it for display
            cmd = cmd.rstrip("\\1").rstrip("\x01")
            result.rows.append(ArtifactRow(
                fields={"Order": str(idx), "Slot": slot, "Command": cmd},
            ))
    else:
        for slot, v in sorted(values_by_name.items()):
            cmd = auto_decode(v.raw, v.value_type_name, v.name).display.rstrip("\\1").rstrip("\x01")
            result.rows.append(ArtifactRow(
                fields={"Order": "(no MRUList)", "Slot": slot, "Command": cmd},
            ))

    result.summary = f"{len(result.rows)} command(s) recorded in the Run dialog."
    return result


@_safe
def extract_word_wheel_query(hive: LoadedHive) -> ArtifactResult:
    """User Activity / Artifact 3 - WordWheelQuery.

    Columns: MRU Order | Search Term | Approx Time | Source

    The MRUListEx value is a stream of int32 slot indices terminated
    by 0xFFFFFFFF. Index 0 in the stream = most recent. Each numeric
    value is a UTF-16LE NUL-terminated search term entered into the
    Explorer search bar. Per spec, the registry key's LastWriteTime
    is used as the approximate activity time (it bumps on every new
    search), so the freshest term is anchored to that timestamp.
    """
    name = "Search History (WordWheelQuery)"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.NTUSER)

    key = open_key(
        hive, r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery")
    if key is None:
        return _key_not_found_result(
            name, r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery")

    last_write = key_last_write_utc(key)
    approx_time = _dfir_time(last_write)

    result = ArtifactResult(
        artifact_name=name,
        columns=["MRU Order", "Search Term", "Approx Time", "Source"],
        raw_key_last_write=last_write,
    )

    # MRUListEx: int32 slot indices, terminator 0xFFFFFFFF
    mru_raw, _ = get_value_raw(key, "MRUListEx")
    order_indices: List[int] = []
    if isinstance(mru_raw, (bytes, bytearray)):
        b = bytes(mru_raw)
        for i in range(0, len(b) - 3, 4):
            n = struct.unpack_from("<i", b, i)[0]
            if n == -1:
                break
            order_indices.append(n)

    values_by_name = {v.name: v
                      for v in list_values(key) if v.name != "MRUListEx"}

    if order_indices:
        for mru_pos, idx in enumerate(order_indices):
            v = values_by_name.get(str(idx))
            if v is None:
                continue
            term = (utf16le_to_str(v.raw)
                    if isinstance(v.raw, (bytes, bytearray)) else str(v.raw))
            # Only the most-recent term gets the precise key timestamp;
            # older terms only have the same ceiling, so we publish the
            # same value but the analyst should treat it as an upper bound.
            result.rows.append(ArtifactRow(fields={
                "MRU Order": str(mru_pos),
                "Search Term": _dfir(term),
                "Approx Time": approx_time if mru_pos == 0 else DFIR_MISSING,
                "Source": "WordWheelQuery",
            }))
    else:
        # No MRUListEx - emit slots in insertion order with no time
        for slot, v in sorted(values_by_name.items(),
                              key=lambda x: int(x[0])
                              if x[0].isdigit() else 1 << 30):
            term = (utf16le_to_str(v.raw)
                    if isinstance(v.raw, (bytes, bytearray)) else str(v.raw))
            result.rows.append(ArtifactRow(fields={
                "MRU Order": DFIR_MISSING,
                "Search Term": _dfir(term),
                "Approx Time": DFIR_MISSING,
                "Source": "WordWheelQuery",
            }))

    result.summary = (f"{len(result.rows)} Explorer search term(s) "
                      f"recovered. Approx Time on MRU 0 reflects the key's "
                      f"LastWriteTime; older entries have no precise "
                      f"timestamp.")
    return _dfir_finalize(result)


@_safe
def extract_open_save_dialog(hive: LoadedHive) -> ArtifactResult:
    """Open/Save Dialog History combining three ComDlg32 subkeys.

    Sources (NTUSER.DAT):
      Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\
        OpenSavePidlMRU\\<ext>\\<slot>   - PRIMARY: full paths via PIDL
        LastVisitedPidlMRU\\<slot>        - application context
        CIDSizeMRU\\<slot>                - file-name hint only

    Each row in the output table represents one MRU entry, columns:
      MRU Slot | File Name | Full Path | Application |
      Directory | File Type | User Action

    Rules per spec:
      * OpenSavePidlMRU is the primary source for full paths.
      * CIDSizeMRU is used only for file-name hints when an
        OpenSavePidlMRU row had no recoverable file name.
      * LastVisitedPidlMRU supplies the Application column.
      * No Interpretation / Flag columns.
    """
    name = "Open/Save Dialog History (ComDlg32)"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.NTUSER)

    base_path = (r"Software\Microsoft\Windows\CurrentVersion"
                 r"\Explorer\ComDlg32")
    base = open_key(hive, base_path)
    if base is None:
        return _key_not_found_result(name, base_path)

    result = ArtifactResult(
        artifact_name=name,
        columns=["MRU Slot", "File Name", "Full Path", "Application",
                 "Directory", "File Type", "User Action"],
        raw_key_last_write=key_last_write_utc(base),
    )

    # ----- 1. CIDSizeMRU -> exe-name hint per slot ---------------------
    cid_hints: Dict[int, str] = {}
    cid_key = open_key_by_subkey(base, "CIDSizeMRU")
    if cid_key is not None:
        for v in list_values(cid_key):
            if v.name == "MRUListEx":
                continue
            try:
                slot = int(v.name)
            except ValueError:
                continue
            blob = bytes(v.raw) if isinstance(v.raw, (bytes, bytearray)) else b""
            exe = _read_utf16_zstring(blob, 0)
            if exe:
                cid_hints[slot] = exe

    # ----- 2. LastVisitedPidlMRU -> (app, last directory) per slot ----
    last_visited: Dict[int, Tuple[str, str]] = {}
    lv_key = open_key_by_subkey(base, "LastVisitedPidlMRU")
    if lv_key is not None:
        for v in list_values(lv_key):
            if v.name == "MRUListEx":
                continue
            try:
                slot = int(v.name)
            except ValueError:
                continue
            blob = bytes(v.raw) if isinstance(v.raw, (bytes, bytearray)) else b""
            app = _read_utf16_zstring(blob, 0)
            # PIDL begins after the app name + UTF-16 NUL terminator.
            pidl_start = (len(app) + 1) * 2
            # 4-byte align
            if pidl_start & 1:
                pidl_start += 1
            directory = ""
            if 0 < pidl_start < len(blob):
                directory = _pidl_to_path(blob[pidl_start:])
            last_visited[slot] = (app, directory)

    # ----- 3. OpenSavePidlMRU -> primary rows --------------------------
    seen_slots: set = set()
    osp_key = open_key_by_subkey(base, "OpenSavePidlMRU")
    if osp_key is not None:
        for ext_key in list_subkeys(osp_key):
            ext_name = ext_key.name() or ""
            for v in list_values(ext_key):
                if v.name == "MRUListEx":
                    continue
                try:
                    slot = int(v.name)
                except ValueError:
                    continue
                blob = bytes(v.raw) if isinstance(v.raw, (bytes, bytearray)) else b""
                full_path = _pidl_to_path(blob)
                if not full_path:
                    continue
                file_name, directory = _split_path(full_path)
                # If PIDL gave us a folder-only path (no filename portion),
                # try the CIDSizeMRU hint as the file name.
                if not file_name and slot in cid_hints:
                    file_name = cid_hints[slot]
                # File type: prefer extension from file name; fall back to
                # the subkey name (".exe", ".pdf", ...) when meaningful.
                file_type = ""
                if file_name and "." in file_name:
                    file_type = "." + file_name.rsplit(".", 1)[-1].lower()
                elif ext_name and ext_name != "*":
                    file_type = ext_name if ext_name.startswith(".") \
                        else "." + ext_name
                # Application: from LastVisitedPidlMRU when slots align,
                # otherwise default to explorer.exe (the host of the
                # common Open/Save dialog).
                app = ""
                if slot in last_visited and last_visited[slot][0]:
                    app = last_visited[slot][0]
                if not app:
                    app = "explorer.exe"

                result.rows.append(ArtifactRow(fields={
                    "MRU Slot": str(slot),
                    "File Name": file_name,
                    "Full Path": full_path,
                    "Application": app,
                    "Directory": directory,
                    "File Type": file_type,
                    "User Action": "Opened/Saved via dialog",
                }))
                seen_slots.add(slot)

    # ----- 4. LastVisitedPidlMRU rows that don't overlap ---------------
    for slot, (app, directory) in last_visited.items():
        if slot in seen_slots:
            continue
        if not app and not directory:
            continue
        result.rows.append(ArtifactRow(fields={
            "MRU Slot": str(slot),
            "File Name": app or "",
            "Full Path": directory or "",
            "Application": app or "explorer.exe",
            "Directory": directory or "",
            "File Type": (".exe" if app.lower().endswith(".exe") else ""),
            "User Action": "Last directory accessed by application",
        }))
        seen_slots.add(slot)

    if not result.rows:
        return _key_not_found_result(name, base_path + " (no decodable entries)")

    # MRU slots typically run 0..N - sort numerically for readability
    try:
        result.rows.sort(key=lambda r: int(r.fields.get("MRU Slot", 0)))
    except (TypeError, ValueError):
        pass

    result.summary = (f"{len(result.rows)} dialog history entry(ies) "
                      f"reconstructed from OpenSavePidlMRU PIDLs, with "
                      f"application context from LastVisitedPidlMRU and "
                      f"file-name hints from CIDSizeMRU.")
    return result


# ---------------------------------------------------------------------------
# Helpers for ComDlg32 PIDL parsing (used only by extract_open_save_dialog)
# ---------------------------------------------------------------------------

def _read_utf16_zstring(data: bytes, offset: int) -> str:
    """Read a UTF-16-LE NUL-terminated string starting at offset."""
    chars = []
    pos = offset
    while pos + 1 < len(data):
        ch = struct.unpack_from("<H", data, pos)[0]
        if ch == 0:
            break
        chars.append(chr(ch))
        pos += 2
    return "".join(chars)


def _split_path(path: str) -> Tuple[str, str]:
    """Split 'C:\\a\\b\\c.txt' -> ('c.txt', 'C:\\a\\b'). For folder-only
    paths returns ('', folder)."""
    if not path:
        return "", ""
    # If the trailing segment looks like a file (has '.' AND isn't a
    # bare drive like 'C:.') treat it as a file.
    if "\\" not in path:
        return ("", path) if path.endswith(":") else (path, "")
    head, _, tail = path.rpartition("\\")
    if "." in tail and not tail.endswith(":"):
        return tail, head
    # Folder-only: tail is the deepest folder name
    return "", path


def _pidl_to_path(data: bytes) -> str:
    """Walk a PIDL (sequence of SHITEMIDs) and reconstruct the path.

    Tolerant of malformed items - we skip a damaged item rather than
    abandon the whole walk.
    """
    drive = ""
    folders: List[str] = []
    pos = 0
    while pos + 2 <= len(data):
        cb = struct.unpack_from("<H", data, pos)[0]
        if cb == 0:
            break  # PIDL terminator
        if cb < 3 or pos + cb > len(data):
            break  # malformed - stop here
        item = data[pos + 2:pos + cb]
        type_byte = item[0]

        # Drive items: 0x20-0x2F (and historically 0x23/0x25/0x29/0x2A/0x2E/0x2F)
        if 0x20 <= type_byte < 0x30:
            d = _scan_ascii_run(item, 1, 8)
            if d and d[1:2] == ":":
                drive = d[:2].upper()
        # File-system items: 0x30-0x3F (regular) and 0xB0-0xBF (extended)
        elif (0x30 <= type_byte < 0x40) or (0xB0 <= type_byte < 0xC0):
            long_name = _pidl_long_name_from_extblock(item)
            if not long_name:
                long_name = _pidl_short_name(item)
            if long_name:
                folders.append(long_name)
        # 0x1F (root folder, CLSID) and others: silently skip
        pos += cb

    if not drive and not folders:
        return ""
    if drive and folders:
        return drive + "\\" + "\\".join(folders)
    if drive:
        return drive + "\\"
    return "\\".join(folders)


def _scan_ascii_run(item: bytes, start: int, max_len: int) -> str:
    chars = []
    end = min(len(item), start + max_len)
    for i in range(start, end):
        c = item[i]
        if c == 0 or c < 0x20 or c > 0x7E:
            break
        chars.append(chr(c))
    return "".join(chars)


def _pidl_short_name(item: bytes) -> str:
    """ASCII short (8.3) name in a file-system SHITEMID payload.

    Layout for type 0x31 / 0x32:
        0x00 type, 0x01 flags, 0x02 size(4), 0x06 date(2), 0x08 time(2),
        0x0A attrs(2), 0x0C name(ASCII NUL-terminated)
    """
    if len(item) < 14:
        return ""
    chars = []
    for i in range(12, min(len(item), 280)):
        c = item[i]
        if c == 0:
            break
        if 0x20 <= c <= 0x7E:
            chars.append(chr(c))
        else:
            break
    return "".join(chars)


# The Shell PIDL extension block always ends with the magic dword
# 0xBEEF0004 (little-endian bytes b"\x04\x00\xEF\xBE") followed by the
# extension body; the long file name is the trailing UTF-16-LE string.
_PIDL_EXT_SIG = b"\x04\x00\xEF\xBE"


def _pidl_long_name_from_extblock(item: bytes) -> str:
    """Extract the long file name from the BEEF0004 extension block.

    On Win 7+ the long name lives in the extension block at the tail
    of every modern file-system SHITEMID. We anchor on the
    well-known signature and scan backwards from the end of the item
    for the trailing UTF-16-LE NUL-terminated string.
    """
    if _PIDL_EXT_SIG not in item:
        return ""
    # The trailing long name is the last printable UTF-16-LE string in
    # the item. Scan backwards from end-of-item.
    end = len(item)
    while end >= 2 and item[end - 1] == 0 and item[end - 2] == 0:
        end -= 2  # strip trailing UTF-16 NULs
    if end < 4:
        return ""
    chars: List[str] = []
    pos = end - 2
    while pos >= 0:
        ch = struct.unpack_from("<H", item, pos)[0]
        if ch == 0:
            break
        # Accept printable Unicode (BMP, no controls, no surrogate halves)
        if 0x20 <= ch <= 0xD7FF or 0xE000 <= ch <= 0xFFFD:
            chars.append(chr(ch))
            pos -= 2
        else:
            break
    if len(chars) < 2:
        return ""
    return "".join(reversed(chars))


@_safe
def extract_typed_urls(hive: LoadedHive) -> ArtifactResult:
    """User Activity / Typed URLs (TypedURLs).

    Columns: MRU Order | URL | Visit Time | Source

    Recovers URLs explicitly typed into the Internet Explorer / Edge
    Legacy address bar.  Visit timestamps are correlated from the
    companion TypedURLsTime key when present (Windows 8+); each value
    there is an 8-byte FILETIME matching the url<N> index.
    """
    name = "Typed URLs (TypedURLs)"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.NTUSER)

    key = open_key(hive, r"Software\Microsoft\Internet Explorer\TypedURLs")
    if key is None:
        return _key_not_found_result(
            name, r"Software\Microsoft\Internet Explorer\TypedURLs")

    # Optional: companion time key (Windows 8+)
    time_key = open_key(
        hive, r"Software\Microsoft\Internet Explorer\TypedURLsTime")

    result = ArtifactResult(
        artifact_name=name,
        columns=["MRU Order", "URL", "Visit Time", "Source"],
        raw_key_last_write=key_last_write_utc(key),
    )

    for v in list_values(key):
        vname = v.name or ""
        if not vname.lower().startswith("url"):
            continue

        url = auto_decode(v.raw, v.value_type_name, vname).display
        if not url:
            continue

        # Extract MRU order from value name (url1 -> 1, url2 -> 2, ...)
        order_str = vname[3:]  # strip "url" prefix
        try:
            order = int(order_str)
        except (TypeError, ValueError):
            order = 0

        # Correlate timestamp from TypedURLsTime if available
        visit_time = DFIR_MISSING
        if time_key is not None:
            time_raw, _ = get_value_raw(time_key, vname)
            if isinstance(time_raw, (bytes, bytearray)) and len(time_raw) >= 8:
                decoded_time = decode_filetime(time_raw)
                if decoded_time:
                    visit_time = _dfir_time(decoded_time)

        result.rows.append(ArtifactRow(fields={
            "MRU Order": str(order),
            "URL": _dfir(url),
            "Visit Time": visit_time,
            "Source": "TypedURLs",
        }))

    # Sort by MRU order ascending
    try:
        result.rows.sort(key=lambda r: int(r.fields.get("MRU Order", "0")))
    except (TypeError, ValueError):
        pass

    result.summary = (
        f"{len(result.rows)} typed URL(s) recovered from "
        f"Internet Explorer / Edge Legacy address bar.")
    return _dfir_finalize(result)


# ===========================================================================
# CATEGORY 3 - USB & EXTERNAL DEVICE USAGE
# ===========================================================================

@_safe
def extract_usbstor(hive: LoadedHive) -> ArtifactResult:
    name = "USB Device Identifiers (USBSTOR)"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.SYSTEM)

    cs = active_controlset_path(hive)
    key = open_key(hive, rf"{cs}\Enum\USBSTOR")
    if key is None:
        return _key_not_found_result(name, rf"{cs}\Enum\USBSTOR")

    result = ArtifactResult(
        artifact_name=name,
        columns=["Device Type", "Serial Number", "FriendlyName",
                 "DeviceDesc", "Manufacturer", "First Seen (UTC)"],
        raw_key_last_write=key_last_write_utc(key),
    )

    for device_type_key in list_subkeys(key):
        for instance_key in list_subkeys(device_type_key):
            friendly_raw, vt1 = get_value_raw(instance_key, "FriendlyName")
            desc_raw, vt2 = get_value_raw(instance_key, "DeviceDesc")
            mfg_raw, vt3 = get_value_raw(instance_key, "Mfg")
            friendly = auto_decode(friendly_raw, vt1, "FriendlyName").display if friendly_raw else "(none)"
            desc = auto_decode(desc_raw, vt2, "DeviceDesc").display if desc_raw else "(none)"
            mfg = auto_decode(mfg_raw, vt3, "Mfg").display if mfg_raw else "(none)"
            result.rows.append(ArtifactRow(
                fields={
                    "Device Type": device_type_key.name(),
                    "Serial Number": instance_key.name(),
                    "FriendlyName": friendly,
                    "DeviceDesc": desc,
                    "Manufacturer": mfg,
                    "First Seen (UTC)": key_last_write_utc(instance_key),
                },
            ))

    result.summary = f"{len(result.rows)} USB storage device(s) recorded."
    return result


@_safe
def extract_usb_timestamps(hive: LoadedHive) -> ArtifactResult:
    """USB connection history with FriendlyName resolution.

    Walks both ControlSet001\\Enum\\USB (host controllers / hubs) and
    ControlSet001\\Enum\\USBSTOR (mass-storage devices). For each
    detected device we resolve a human-readable Device Name from
    FriendlyName, falling back to DeviceDesc, then to the parent
    USBSTOR key name. Last-connected timestamps come from the
    instance key's LastWrite time.

    Per spec: no Interpretation / no Flag columns.
    """
    name = "USB Connection Timestamps"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.SYSTEM)

    cs = active_controlset_path(hive)

    result = ArtifactResult(
        artifact_name=name,
        columns=["Device Name", "VID/PID", "Serial / Instance",
                 "Source", "Last Connected (UTC)"],
    )
    last_write_seen = ""

    # ---- USBSTOR (mass-storage devices) - have rich FriendlyName -----
    usbstor = open_key(hive, rf"{cs}\Enum\USBSTOR")
    if usbstor is not None:
        last_write_seen = key_last_write_utc(usbstor)
        for vendor_key in list_subkeys(usbstor):  # e.g. Disk&Ven_Kingston&...
            for instance_key in list_subkeys(vendor_key):
                friendly_raw, vt = get_value_raw(instance_key, "FriendlyName")
                desc_raw, vt2 = get_value_raw(instance_key, "DeviceDesc")
                friendly = (auto_decode(friendly_raw, vt, "FriendlyName").display
                            if friendly_raw else "")
                desc = (auto_decode(desc_raw, vt2, "DeviceDesc").display
                        if desc_raw else "")
                # DeviceDesc looks like  @disk.inf,%disk_devdesc%;Disk drive
                # - take the human-readable suffix after the last ';'
                if desc and ";" in desc:
                    desc = desc.split(";")[-1].strip()
                device_name = friendly or desc or vendor_key.name()
                result.rows.append(ArtifactRow(fields={
                    "Device Name": device_name[:120],
                    "VID/PID": vendor_key.name(),
                    "Serial / Instance": instance_key.name(),
                    "Source": "USBSTOR",
                    "Last Connected (UTC)": key_last_write_utc(instance_key),
                }))

    # ---- USB (hubs / controllers / non-storage USB) -----------------
    usb = open_key(hive, rf"{cs}\Enum\USB")
    if usb is not None:
        if not last_write_seen:
            last_write_seen = key_last_write_utc(usb)
        for vid_pid_key in list_subkeys(usb):
            for instance_key in list_subkeys(vid_pid_key):
                friendly_raw, vt = get_value_raw(instance_key, "FriendlyName")
                desc_raw, vt2 = get_value_raw(instance_key, "DeviceDesc")
                friendly = (auto_decode(friendly_raw, vt, "FriendlyName").display
                            if friendly_raw else "")
                desc = (auto_decode(desc_raw, vt2, "DeviceDesc").display
                        if desc_raw else "")
                if desc and ";" in desc:
                    desc = desc.split(";")[-1].strip()
                device_name = friendly or desc or vid_pid_key.name()
                result.rows.append(ArtifactRow(fields={
                    "Device Name": device_name[:120],
                    "VID/PID": vid_pid_key.name(),
                    "Serial / Instance": instance_key.name(),
                    "Source": "USB",
                    "Last Connected (UTC)": key_last_write_utc(instance_key),
                }))

    if not result.rows:
        return _key_not_found_result(name,
                                     rf"{cs}\Enum\{{USB,USBSTOR}}")

    result.raw_key_last_write = last_write_seen
    result.summary = (f"{len(result.rows)} USB connection record(s) recovered, "
                      f"with device names resolved from FriendlyName / DeviceDesc.")
    return result


@_safe
def extract_mounted_devices(hive: LoadedHive) -> ArtifactResult:
    """USB & Devices / Mounted Volumes — analyst-ready table.

    Columns: Volume GUID | Drive Letter | Device Type | Disk Signature | First Seen (Approx)

    Correlates volume GUIDs with assigned drive letters and disk
    signatures by matching the raw data blobs in MountedDevices.
    Device Type is classified as Internal or External (USB) by
    inspecting the device path for USBSTOR markers.
    """
    name = "Mounted Volumes"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.SYSTEM)

    key = open_key(hive, "MountedDevices")
    if key is None:
        return _key_not_found_result(name, "MountedDevices")

    first_seen = _dfir_time(key_last_write_utc(key))

    result = ArtifactResult(
        artifact_name=name,
        columns=["Volume GUID", "Drive Letter", "Device Type",
                 "Disk Signature", "First Seen (Approx)"],
        raw_key_last_write=key_last_write_utc(key),
    )

    # First pass: collect raw blobs keyed by value name so we can
    # correlate GUIDs with drive letters (they share the same blob).
    guid_entries: Dict[str, bytes] = {}   # GUID string -> raw blob
    letter_entries: Dict[str, bytes] = {}  # "X:" -> raw blob

    for v in list_values(key):
        raw = bytes(v.raw) if isinstance(v.raw, (bytes, bytearray)) else b""
        vn = v.name or ""
        if vn.startswith(r"\??\Volume{") or vn.startswith(r"\\?\\Volume{"):
            guid_entries[vn] = raw
        elif vn.startswith(r"\DosDevices\\") or vn.startswith(r"\DosDevices\\"):
            letter = vn.rsplit("\\", 1)[-1] if "\\" in vn else ""
            if letter:
                letter_entries[letter] = raw

    # Build a blob -> drive-letter reverse index for correlation
    blob_to_letter: Dict[bytes, str] = {}
    for letter, blob in letter_entries.items():
        blob_to_letter[blob] = letter

    # Emit one row per volume GUID entry
    for vn, raw in guid_entries.items():
        # Extract GUID from the value name
        guid = DFIR_MISSING
        start = vn.find("{")
        end = vn.find("}")
        if start >= 0 and end > start:
            guid = vn[start:end + 1]

        # Correlate with drive letter
        drive_letter = _dfir(blob_to_letter.get(raw, ""))

        # Classify device type + extract disk signature
        disk_sig = DFIR_MISSING
        device_type = "Internal"

        if len(raw) == 12:
            # MBR partition descriptor: 4-byte disk sig + 8-byte offset
            try:
                sig_val = struct.unpack_from("<I", raw, 0)[0]
                disk_sig = f"0x{sig_val:08X}"
            except struct.error:
                pass
        elif len(raw) > 12:
            # Longer blobs are UTF-16LE device paths
            try:
                path_str = raw.decode("utf-16-le", errors="replace")
            except Exception:
                path_str = ""
            if "USBSTOR" in path_str.upper() or "USB#" in path_str.upper():
                device_type = "External (USB)"
            # Try to extract GPT disk GUID from the path
            gpt_start = path_str.find("#")
            if gpt_start >= 0:
                disk_sig = DFIR_MISSING  # GPT doesn't have a simple 4-byte sig

        result.rows.append(ArtifactRow(fields={
            "Volume GUID": _dfir(guid),
            "Drive Letter": drive_letter,
            "Device Type": _dfir(device_type),
            "Disk Signature": disk_sig,
            "First Seen (Approx)": first_seen,
        }))

    result.summary = (
        f"{len(result.rows)} mounted volume(s) correlated with drive letters "
        f"and device types.")
    return _dfir_finalize(result)


@_safe
def extract_user_usb_usage(hive: LoadedHive) -> ArtifactResult:
    """USB & Devices / MountPoints2 — user-attributed table.

    Columns: User | Volume/Name | Drive Letter | Device Type | Remote Path | Last Access (Approx)

    Attributes removable media and network-share mounts to specific
    user accounts.  Network entries encoded as ##server#share are
    decoded into readable \\\\server\\share form for the Remote Path
    column.
    """
    name = "User-Level USB Usage (MountPoints2)"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.NTUSER)

    key = open_key(hive, r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2")
    if key is None:
        return _key_not_found_result(name, r"Software\...\Explorer\MountPoints2")

    user = _dfir(_user_from_hive(hive))

    result = ArtifactResult(
        artifact_name=name,
        columns=["User", "Volume/Name", "Drive Letter", "Device Type",
                 "Remote Path", "Last Access (Approx)"],
        raw_key_last_write=key_last_write_utc(key),
    )

    for sub in list_subkeys(key):
        nm = sub.name()
        last_access = _dfir_time(key_last_write_utc(sub))
        volume_name = DFIR_MISSING
        drive_letter = DFIR_MISSING
        device_type = DFIR_MISSING
        remote_path = DFIR_MISSING

        if nm.startswith("{"):
            # Volume GUID — likely USB volume
            volume_name = nm
            device_type = "USB"
        elif len(nm) == 1 and nm.isalpha():
            # Single drive letter
            drive_letter = f"{nm.upper()}:"
            volume_name = drive_letter
            device_type = "Local"
        elif nm.startswith("##"):
            # Network share: ##server#share  ->  \\server\share
            decoded = nm.replace("#", "\\")
            # Clean up: leading \\\\ is correct for UNC
            if not decoded.startswith("\\\\"):
                decoded = "\\" + decoded.lstrip("\\")
            remote_path = decoded
            volume_name = nm
            device_type = "Network"
        else:
            # Other / unknown
            volume_name = nm
            device_type = "Local"

        result.rows.append(ArtifactRow(fields={
            "User": user,
            "Volume/Name": _dfir(volume_name),
            "Drive Letter": drive_letter,
            "Device Type": device_type,
            "Remote Path": remote_path,
            "Last Access (Approx)": last_access,
        }))

    result.summary = (
        f"{len(result.rows)} user-level mount point(s) attributed to "
        f"{user if user != DFIR_MISSING else '(unknown user)'}.")
    return _dfir_finalize(result)


# ===========================================================================
# CATEGORY 4 - PROGRAM EXECUTION & PERSISTENCE
# ===========================================================================

_SUSPICIOUS_PATH_FRAGMENTS = (
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp", "\\users\\public\\",
    "\\windows\\debug\\", "\\programdata\\", "\\$recycle.bin\\",
)


def _flag_suspicious_path(path: str) -> str:
    p = path.lower()
    for frag in _SUSPICIOUS_PATH_FRAGMENTS:
        if frag in p:
            return "SUSPICIOUS"
    return ""


def _walk_run_keys(hive: LoadedHive,
                   sources: List[Tuple[str, str, str, str]]
                   ) -> Tuple[List[ArtifactRow], str]:
    """Walk a list of Run/RunOnce-style keys.

    `sources` is a list of (subkey_path, type_label, mode_label,
    source_label) tuples. Returns (rows, last_write_utc).
    """
    rows: List[ArtifactRow] = []
    last_write = ""
    for path, type_label, mode_label, source_label in sources:
        key = open_key(hive, path)
        if key is None:
            continue
        if not last_write:
            last_write = key_last_write_utc(key)
        for v in list_values(key):
            cmd_text = auto_decode(v.raw, v.value_type_name, v.name).display
            exe_path = _executable_from_command(cmd_text)
            program = _basename_win(exe_path) or v.name
            flag = _flag_suspicious_path(exe_path)
            rows.append(ArtifactRow(
                fields={
                    "Program Name": _dfir(program),
                    "Path": _dfir(exe_path or cmd_text),
                    "Type": _dfir(type_label),
                    "Startup Mode": _dfir(mode_label),
                    "Source": _dfir(source_label),
                },
                flag=flag,
            ))
    return rows, last_write


@_safe
def extract_startup_programs_system(hive: LoadedHive) -> ArtifactResult:
    """Program Execution / Artifact 1 - System-Wide Startup Programs.

    Columns: Program Name | Path | Type | Startup Mode | Source

    Walks every machine-context Run / RunOnce key in HKLM\\Software,
    including the 32-bit-on-64-bit redirected Wow6432Node hierarchy.
    Auto-start services (HKLM\\SYSTEM\\CurrentControlSet\\Services with
    Start=2) are out of scope here because they live in the SYSTEM
    hive, not SOFTWARE.
    """
    name = "Startup Programs (System-Wide)"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.SOFTWARE)

    sources = [
        (r"Microsoft\Windows\CurrentVersion\Run",
         "Run", "Auto", "HKLM"),
        (r"Microsoft\Windows\CurrentVersion\RunOnce",
         "RunOnce", "Once", "HKLM"),
        (r"Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
         "Wow6432Node Run", "Auto", "HKLM (Wow64)"),
        (r"Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
         "Wow6432Node RunOnce", "Once", "HKLM (Wow64)"),
    ]

    rows, last_write = _walk_run_keys(hive, sources)
    result = ArtifactResult(
        artifact_name=name,
        columns=["Program Name", "Path", "Type", "Startup Mode", "Source"],
        raw_key_last_write=last_write,
    )
    result.rows = rows
    result.summary = (
        f"{len(result.rows)} system-wide startup entry(ies) recovered "
        f"from Run / RunOnce / Wow6432Node keys.")
    return _dfir_finalize(result)


@_safe
def extract_startup_programs_user(hive: LoadedHive) -> ArtifactResult:
    """Program Execution / Artifact 2 - User-Specific Startup Programs.

    Columns: User | Program Name | Path | Type | Startup Mode | Source

    Walks the user-context Run / RunOnce keys in NTUSER.DAT. The User
    column is derived from the NTUSER hive's file path (e.g.
    `C:\\Users\\jdoe\\NTUSER.DAT` -> `jdoe`) so multi-user evidence
    sets remain attributable.
    """
    name = "User Startup Programs"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.NTUSER)

    user = _user_from_hive(hive)
    sources = [
        (r"Software\Microsoft\Windows\CurrentVersion\Run",
         "Run", "Auto", "HKCU"),
        (r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
         "RunOnce", "Once", "HKCU"),
    ]

    rows, last_write = _walk_run_keys(hive, sources)
    # Splice the User column to the front of every row
    final_rows: List[ArtifactRow] = []
    for r in rows:
        new_fields = {"User": _dfir(user)}
        new_fields.update(r.fields)
        final_rows.append(ArtifactRow(fields=new_fields, flag=r.flag,
                                      interpretation=r.interpretation))

    result = ArtifactResult(
        artifact_name=name,
        columns=["User", "Program Name", "Path", "Type",
                 "Startup Mode", "Source"],
        raw_key_last_write=last_write,
    )
    result.rows = final_rows
    result.summary = (
        f"{len(result.rows)} per-user startup entry(ies) recovered "
        f"for {user or '(user not identifiable from hive path)'}.")
    return _dfir_finalize(result)


@_safe
def extract_shimcache(hive: LoadedHive) -> ArtifactResult:
    """Program Execution / Artifact 3 - Shimcache (AppCompatCache).

    Columns: Entry Order | File Name | File Path | Last Modified | Source

    Surfaces every binary the Application Compatibility subsystem has
    seen on this host. The Last Modified value is the file's
    $STANDARD_INFORMATION timestamp at the time the cache entry was
    recorded. Per spec we treat entries as evidence of presence and
    shim processing - this view does NOT assert confirmed execution.
    """
    name = "Executed Programs (AppCompatCache / Shimcache)"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.SYSTEM)

    cs = active_controlset_path(hive)
    key = open_key(hive, rf"{cs}\Control\Session Manager\AppCompatCache")
    if key is None:
        return _key_not_found_result(
            name, rf"{cs}\Control\Session Manager\AppCompatCache")

    raw, _ = get_value_raw(key, "AppCompatCache")
    result = ArtifactResult(
        artifact_name=name,
        columns=["Entry Order", "File Name", "File Path",
                 "Last Modified", "Source"],
        raw_key_last_write=key_last_write_utc(key),
    )
    if not isinstance(raw, (bytes, bytearray)):
        result.error = "AppCompatCache value not present or unreadable."
        return result

    entries = _parse_shimcache_w10(bytes(raw))
    for idx, (path, ft_str) in enumerate(entries):
        flag = _flag_suspicious_path(path)
        result.rows.append(ArtifactRow(
            fields={
                "Entry Order": str(idx),
                "File Name": _dfir(_basename_win(path)),
                "File Path": _dfir(path),
                "Last Modified": _dfir_time(ft_str),
                "Source": "AppCompatCache (Shimcache)",
            },
            flag=flag,
        ))
    result.summary = (f"{len(result.rows)} Shimcache entry(ies) recovered. "
                      f"Note: Win10/11 Shimcache evidences presence and "
                      f"shim processing - it does not on its own confirm "
                      f"execution.")
    return _dfir_finalize(result)


def _parse_shimcache_w10(raw: bytes) -> List[tuple]:
    """Best-effort parser for the Windows 10/11 AppCompatCache layout.

    Header: '10ts' magic at offset 0x30; entries follow with 4-byte 'sig',
    4-byte length, then per-entry: 4-byte path-length-bytes, UTF-16LE path,
    8-byte FILETIME, plus padding/flags. Failures are tolerated silently.
    """
    out: List[tuple] = []
    if len(raw) < 0x34:
        return out
    # Win10 cache magic is "10ts" at offset 0x30
    if raw[0x30:0x34] != b"10ts":
        # Try alternative offsets for older builds
        magic_pos = raw.find(b"10ts", 0, 0x100)
        if magic_pos < 0:
            return out
        offset = magic_pos
    else:
        offset = 0x30

    while offset < len(raw) - 12:
        sig = raw[offset:offset + 4]
        if sig != b"10ts":
            offset += 1
            continue
        try:
            entry_len = struct.unpack_from("<I", raw, offset + 4)[0]
            path_size = struct.unpack_from("<H", raw, offset + 8)[0]
            if path_size == 0 or path_size > 1024:
                offset += 1
                continue
            path_bytes = raw[offset + 10:offset + 10 + path_size]
            path = path_bytes.decode("utf-16-le", errors="replace")
            ft_pos = offset + 10 + path_size
            if ft_pos + 8 > len(raw):
                break
            ft_value = struct.unpack_from("<Q", raw, ft_pos)[0]
            ft_str = decode_filetime(ft_value) or "(unknown)"
            out.append((path, ft_str))
            offset += 12 + entry_len
        except struct.error:
            offset += 1
            continue
        if len(out) > 5000:  # safety guard against runaway loops
            break
    return out


@_safe
def extract_file_associations(hive: LoadedHive) -> ArtifactResult:
    """Program Execution / Artifact 4 - File Association Commands.

    Columns: File Extension | ProgID | Command | Application Path | Scope

    Maps each file extension to its ProgID, then to the
    `<ProgID>\\shell\\open\\command` registration. Resolves the
    underlying executable from the command line. Scope is determined
    by the hive type:
      - SOFTWARE hive  -> 'System'  (HKLM\\Software\\Classes)
      - NTUSER.DAT     -> 'User'    (HKCU\\Software\\Classes)
    """
    name = "File Association Commands"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.SOFTWARE)

    if hive.hive_type == HiveType.NTUSER:
        classes_root = r"Software\Classes"
        scope_label = "User"
    else:
        classes_root = "Classes"
        scope_label = "System"

    classes = open_key(hive, classes_root)
    if classes is None:
        return _key_not_found_result(name, classes_root)

    result = ArtifactResult(
        artifact_name=name,
        columns=["File Extension", "ProgID", "Command",
                 "Application Path", "Scope"],
        raw_key_last_write=key_last_write_utc(classes),
    )

    # Wildcard handler (* applies to every file)
    star_cmd = open_key(hive, f"{classes_root}\\*\\shell\\open\\command")
    if star_cmd is not None:
        raw, vt = get_value_raw(star_cmd, "")
        if raw:
            cmd_text = auto_decode(raw, vt, "(default)").display
            exe = _executable_from_command(cmd_text)
            result.rows.append(ArtifactRow(
                fields={
                    "File Extension": "* (wildcard)",
                    "ProgID": DFIR_MISSING,
                    "Command": _dfir(cmd_text),
                    "Application Path": _dfir(exe),
                    "Scope": scope_label,
                },
                flag=_flag_suspicious_path(exe),
            ))

    # High-signal extensions: anything that can host code on user
    # double-click, plus common document types whose handler hijacks
    # have been seen in the wild.
    target_extensions = (
        ".exe", ".bat", ".cmd", ".com", ".scr", ".ps1", ".vbs", ".vbe",
        ".js", ".jse", ".wsh", ".wsf", ".hta", ".lnk",
        ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".html",
        ".reg", ".msi",
    )

    for ext in target_extensions:
        # Step 1: read default value of the .ext key -> ProgID
        ext_key = open_key(hive, f"{classes_root}\\{ext}")
        progid = ""
        if ext_key is not None:
            progid_raw, _ = get_value_raw(ext_key, "")
            if isinstance(progid_raw, str):
                progid = progid_raw
            elif isinstance(progid_raw, (bytes, bytearray)):
                progid = utf16le_to_str(progid_raw)
        progid = progid.strip()

        # Step 2: look up the command via ProgID, then fall back to the
        # extension key's own shell\open\command if no ProgID was set.
        cmd_text = ""
        if progid:
            cmd_key = open_key(
                hive, f"{classes_root}\\{progid}\\shell\\open\\command")
            if cmd_key is not None:
                raw, vt = get_value_raw(cmd_key, "")
                if raw:
                    cmd_text = auto_decode(raw, vt, "(default)").display
        if not cmd_text:
            cmd_key = open_key(
                hive, f"{classes_root}\\{ext}\\shell\\open\\command")
            if cmd_key is not None:
                raw, vt = get_value_raw(cmd_key, "")
                if raw:
                    cmd_text = auto_decode(raw, vt, "(default)").display

        if not cmd_text:
            continue  # extension not registered as openable

        exe = _executable_from_command(cmd_text)
        result.rows.append(ArtifactRow(
            fields={
                "File Extension": ext,
                "ProgID": _dfir(progid),
                "Command": _dfir(cmd_text),
                "Application Path": _dfir(exe),
                "Scope": scope_label,
            },
            flag=_flag_suspicious_path(exe),
        ))

    result.summary = (f"{len(result.rows)} file-association handler(s) "
                      f"resolved at scope '{scope_label}'.")
    return _dfir_finalize(result)


@_safe
def extract_com_objects(hive: LoadedHive) -> ArtifactResult:
    """Program Execution / Artifact 5 - COM Objects (CLSID).

    Columns: CLSID | Name | Server Type | Path | ProgID | Scope

    Enumerates registered COM objects and the binaries that
    implement them (InprocServer32 = in-process DLL,
    LocalServer32 = out-of-process EXE). One row per (CLSID, server
    type) pairing - a CLSID with both server types produces two
    rows so each implementation is independently visible.

    Scope is determined by the hive type:
      SOFTWARE hive  -> 'System'  (HKLM\\Software\\Classes\\CLSID)
      NTUSER.DAT     -> 'User'    (HKCU\\Software\\Classes\\CLSID)
    """
    name = "COM Objects (CLSID)"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.SOFTWARE)

    if hive.hive_type == HiveType.NTUSER:
        clsid_path = r"Software\Classes\CLSID"
        scope_label = "User"
    else:
        clsid_path = r"Classes\CLSID"
        scope_label = "System"

    key = open_key(hive, clsid_path)
    if key is None:
        return _key_not_found_result(name, clsid_path)

    result = ArtifactResult(
        artifact_name=name,
        columns=["CLSID", "Name", "Server Type", "Path", "ProgID", "Scope"],
        raw_key_last_write=key_last_write_utc(key),
    )

    # Cap the walk so a SOFTWARE hive with 30k+ CLSIDs doesn't lock the
    # GUI. The cap is generous enough to capture all CLSIDs that
    # actually point to a binary.
    SAMPLE_CAP = 1500
    inspected = 0
    truncated = False

    for clsid_key in list_subkeys(key):
        if inspected >= SAMPLE_CAP:
            truncated = True
            break
        inspected += 1

        # Friendly name = default value at the CLSID root
        default_raw, _ = get_value_raw(clsid_key, "")
        default = (utf16le_to_str(default_raw)
                   if isinstance(default_raw, (bytes, bytearray))
                   else (default_raw or ""))

        # ProgID lives at CLSID\<id>\ProgID (default value)
        progid_key = open_key_by_subkey(clsid_key, "ProgID")
        progid = ""
        if progid_key is not None:
            r, _ = get_value_raw(progid_key, "")
            if isinstance(r, str):
                progid = r
            elif isinstance(r, (bytes, bytearray)):
                progid = utf16le_to_str(r)

        # Emit a row per server type that's actually populated.
        for sub_name, server_type_label in (
                ("InprocServer32", "InProcServer32"),
                ("LocalServer32",  "LocalServer32")):
            server_key = open_key_by_subkey(clsid_key, sub_name)
            if server_key is None:
                continue
            r, vt = get_value_raw(server_key, "")
            if not r:
                continue
            server_path = auto_decode(r, vt, sub_name).display
            if not server_path:
                continue
            result.rows.append(ArtifactRow(
                fields={
                    "CLSID": _dfir(clsid_key.name()),
                    "Name": _dfir(str(default)[:200]),
                    "Server Type": server_type_label,
                    "Path": _dfir(server_path),
                    "ProgID": _dfir(progid),
                    "Scope": scope_label,
                },
                flag=_flag_suspicious_path(server_path),
            ))

    if truncated:
        result.summary = (f"{len(result.rows)} server bindings recovered "
                          f"after sampling {SAMPLE_CAP} CLSID(s); the full "
                          f"set may be larger. Scope: {scope_label}.")
    else:
        result.summary = (f"{len(result.rows)} server bindings recovered "
                          f"across {inspected} CLSID(s). Scope: "
                          f"{scope_label}.")
    return _dfir_finalize(result)


# ===========================================================================
# CATEGORY 5 - SOFTWARE INSTALLATION & UNAUTHORIZED APPS
# ===========================================================================

@_safe
def extract_installed_programs(hive: LoadedHive) -> ArtifactResult:
    name = "Installed Programs (Uninstall)"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.SOFTWARE)

    paths = [
        r"Microsoft\Windows\CurrentVersion\Uninstall",
        r"Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ]
    result = ArtifactResult(
        artifact_name=name,
        columns=["DisplayName", "Publisher", "Version", "Install Date",
                 "Install Location", "Source Key"],
    )
    found = False
    for path in paths:
        base = open_key(hive, path)
        if base is None:
            continue
        found = True
        result.raw_key_last_write = key_last_write_utc(base)
        for sub in list_subkeys(base):
            disp_raw, vt1 = get_value_raw(sub, "DisplayName")
            pub_raw, vt2 = get_value_raw(sub, "Publisher")
            ver_raw, vt3 = get_value_raw(sub, "DisplayVersion")
            loc_raw, vt4 = get_value_raw(sub, "InstallLocation")
            date_raw, _ = get_value_raw(sub, "InstallDate")

            disp = auto_decode(disp_raw, vt1, "DisplayName").display if disp_raw else sub.name()
            pub = auto_decode(pub_raw, vt2, "Publisher").display if pub_raw else "(unknown)"
            ver = auto_decode(ver_raw, vt3, "DisplayVersion").display if ver_raw else ""
            loc = auto_decode(loc_raw, vt4, "InstallLocation").display if loc_raw else ""
            inst_date = decode_yyyymmdd(date_raw) or (str(date_raw) if date_raw else "(unknown)")

            result.rows.append(ArtifactRow(
                fields={
                    "DisplayName": disp[:120],
                    "Publisher": pub[:80],
                    "Version": ver,
                    "Install Date": inst_date,
                    "Install Location": loc[:120],
                    "Source Key": path.split("\\")[0] + "..." if "Wow" in path else "x64",
                },
                # Per spec: no Interpretation, no Flag on this artifact
            ))

    if not found:
        return _key_not_found_result(name, " OR ".join(paths))

    result.summary = f"{len(result.rows)} installed program record(s)."
    return result


@_safe
def extract_os_identification(hive: LoadedHive) -> ArtifactResult:
    """Comprehensive OS identification.

    Surfaces ProductName, DisplayVersion (with ReleaseId fallback),
    CurrentBuild.UBR, InstallDate, RegisteredOwner, RegisteredOrganization,
    EditionID, ProductId, and ShutdownTime in a single key/value table.

    Note: ShutdownTime lives in the SYSTEM hive, not SOFTWARE. When this
    extractor is run against the SOFTWARE hive (its primary hive), the
    ShutdownTime field is omitted. The dedicated 'Last Shutdown Time'
    artifact in Category 1 covers it from SYSTEM.
    """
    name = "Operating System Identification"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.SOFTWARE)

    key = open_key(hive, r"Microsoft\Windows NT\CurrentVersion")
    if key is None:
        return _key_not_found_result(name,
                                     r"Microsoft\Windows NT\CurrentVersion")

    result = ArtifactResult(
        artifact_name=name,
        columns=["Field", "Value"],
        raw_key_last_write=key_last_write_utc(key),
    )

    def _read_str(value_name: str) -> str:
        raw, vt = get_value_raw(key, value_name)
        if raw is None or raw == "":
            return ""
        return auto_decode(raw, vt, value_name).display

    def _add(field_label: str, value: str) -> None:
        if value:
            result.rows.append(ArtifactRow(
                fields={"Field": field_label, "Value": value[:300]}))

    # ---- Derive the correct OS name ---------------------------------
    # Microsoft still writes "Windows 10" in ProductName even on
    # Windows 11 hives.  The canonical rule: CurrentBuildNumber >= 22000
    # means Windows 11.
    raw_product_name = _read_str("ProductName")
    edition_id = _read_str("EditionID")
    build_str = _read_str("CurrentBuild") or _read_str("CurrentBuildNumber")
    ubr_raw, _ = get_value_raw(key, "UBR")
    ubr_str = ""
    if ubr_raw is not None:
        try:
            ubr_str = str(int(ubr_raw))
        except (TypeError, ValueError):
            ubr_str = str(ubr_raw)

    # Determine the Windows generation from the build number
    os_generation = ""
    if build_str:
        try:
            build_num = int(build_str)
            if build_num >= 22000:
                os_generation = "11"
            elif build_num >= 10240:
                os_generation = "10"
            elif build_num >= 9600:
                os_generation = "8.1"
            elif build_num >= 9200:
                os_generation = "8"
            else:
                os_generation = ""  # fall back to ProductName
        except (TypeError, ValueError):
            pass

    # Build the canonical OS string:
    #   Windows <11|10|8.1|…> <Edition> (Build <CurrentBuild>.<UBR>)
    if os_generation:
        edition = edition_id or ""
        build_full = build_str
        if ubr_str:
            build_full = f"{build_str}.{ubr_str}"
        os_string = f"Windows {os_generation}"
        if edition:
            os_string += f" {edition}"
        if build_full:
            os_string += f" (Build {build_full})"
        _add("Operating System", os_string)
    elif raw_product_name:
        _add("Operating System", raw_product_name)

    # ---- Raw ProductName for transparency ---------------------------
    # Correct the displayed product name when the build number proves
    # Windows 11 but the registry still stores "Windows 10".
    display_product_name = raw_product_name
    if os_generation == "11" and raw_product_name:
        display_product_name = raw_product_name.replace(
            "Windows 10", "Windows 11")
    _add("Product Name (Raw)", display_product_name)

    # ---- Edition + ID -----------------------------------------------
    _add("Edition ID", edition_id)
    _add("Product ID", _read_str("ProductId"))

    # ---- Display version: prefer DisplayVersion, fall back to ReleaseId
    display_ver = _read_str("DisplayVersion") or _read_str("ReleaseId")
    if display_ver:
        _add("Display Version", display_ver)

    # ---- Build: CurrentBuild.UBR ------------------------------------
    if build_str:
        build_display = build_str
        if ubr_str:
            build_display = f"{build_str}.{ubr_str}"
        _add("Build Number", build_display)

    # ---- Install date - decoded from Unix epoch ---------------------
    inst_raw, _ = get_value_raw(key, "InstallDate")
    if inst_raw is not None:
        decoded = decode_unix_epoch(inst_raw)
        _add("Install Date", decoded or f"raw value: {inst_raw}")

    # ---- Install time - decoded from FILETIME (newer schema) -------
    inst_time_raw, _ = get_value_raw(key, "InstallTime")
    if inst_time_raw is not None:
        decoded = decode_filetime(inst_time_raw)
        if decoded:
            _add("Install Time (high precision)", decoded)

    # ---- Registered owner / organization ----------------------------
    _add("Registered Owner", _read_str("RegisteredOwner"))
    _add("Registered Organization", _read_str("RegisteredOrganization"))

    # ---- System root, path name, build branch -----------------------
    _add("System Root", _read_str("SystemRoot"))
    _add("Path Name", _read_str("PathName"))
    _add("Build Branch", _read_str("BuildBranch"))
    _add("Build Lab", _read_str("BuildLab"))

    if not result.rows:
        return _key_not_found_result(
            name, r"Microsoft\Windows NT\CurrentVersion (no values)")

    result.summary = f"{len(result.rows)} OS identification field(s) extracted."
    return result


# Back-compat alias for any older code paths that still import the old name
extract_os_install_date = extract_os_identification


@_safe
def extract_registered_apps(hive: LoadedHive) -> ArtifactResult:
    name = "Registered Applications"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.SOFTWARE)

    key = open_key(hive, "RegisteredApplications")
    if key is None:
        return _key_not_found_result(name, "RegisteredApplications")

    result = ArtifactResult(
        artifact_name=name,
        columns=["Application Name", "Capability Path", "Note"],
        raw_key_last_write=key_last_write_utc(key),
    )

    for v in list_values(key):
        path = auto_decode(v.raw, v.value_type_name, v.name).display
        flag = ""
        note = ""
        lower = path.lower()
        if "microsoft" not in lower and "windows" not in lower:
            flag = "WARNING"
            note = "Non-Microsoft registered application - verify legitimacy."
        result.rows.append(ArtifactRow(
            fields={"Application Name": v.name, "Capability Path": path[:200],
                    "Note": note},
            flag=flag,
        ))

    result.summary = f"{len(result.rows)} registered application(s)."
    return result


# ===========================================================================
# CATEGORY 6 - USER ACCOUNTS & AUTHENTICATION
# ===========================================================================

# Account flags from the SAM F structure (offset 0x38)
_ACCOUNT_FLAG_MAP = [
    (0x0001, "Account Disabled"),
    (0x0002, "Home Folder Required"),
    (0x0004, "Password Not Required"),
    (0x0008, "Temporary Duplicate Account"),
    (0x0010, "Normal Account"),
    (0x0020, "MNS Logon Account"),
    (0x0040, "Interdomain Trust Account"),
    (0x0080, "Workstation Trust Account"),
    (0x0100, "Server Trust Account"),
    (0x0200, "Password Doesn't Expire"),
    (0x0400, "Account Auto-Locked"),
]


def _decode_account_flags(flags: int) -> str:
    set_flags = [label for mask, label in _ACCOUNT_FLAG_MAP if flags & mask]
    return ", ".join(set_flags) or "(none)"


def _decode_sam_v(v_data: bytes, rid_int: int) -> Dict[str, str]:
    """Decode the SAM V record to recover username, full name, comment.

    The V record begins with a header of 17 (offset, length, unknown)
    triples - each 12 bytes. The header starts at offset 0x0C, NOT
    at 0x0C + 12. The first triple at 0x0C describes the USERNAME,
    the second at 0x18 the FULL NAME, the third at 0x24 the COMMENT.

    All offsets are relative to the start of the variable data section
    at 0xCC. Strings are stored as UTF-16-LE without a null terminator.

    Validation: a successfully decoded username should contain only
    printable characters; if it does not, we keep the raw decoded
    bytes anyway and let the caller see them - silent swallowing of
    parse failures is what hid the previous bug.
    """
    out = {"Username": "", "Full Name": "", "Comment": "",
           "User Comment": "", "Home Directory": ""}
    if not v_data or len(v_data) < 0xCC:
        return out

    HEADER_BASE = 0x0C   # first triple starts here
    DATA_BASE = 0xCC     # variable data section starts here
    # Index 0 = Username; 1 = Full Name; 2 = Comment;
    # 3 = User Comment; 5 = Home Directory.
    targets = {0: "Username", 1: "Full Name", 2: "Comment",
               3: "User Comment", 5: "Home Directory"}

    for record_idx, key in targets.items():
        try:
            triple_off = HEADER_BASE + record_idx * 12
            if triple_off + 8 > len(v_data):
                continue
            off = struct.unpack_from("<I", v_data, triple_off)[0]
            length = struct.unpack_from("<I", v_data, triple_off + 4)[0]
            if length == 0:
                continue
            start = DATA_BASE + off
            end = start + length
            if end > len(v_data):
                continue
            raw = v_data[start:end]
            text = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
            # Strip any embedded NULs (defensive)
            text = text.replace("\x00", "")
            out[key] = text
        except (struct.error, IndexError):
            continue

    return out


def _decode_sam_f(f_data: bytes) -> Dict[str, str]:
    """Decode the SAM F record (fixed-size, ~80 bytes) for account flags + dates."""
    out = {
        "Last Login (UTC)": "(never)",
        "Password Last Set (UTC)": "(never)",
        "Account Expires (UTC)": "(never)",
        "Last Failed Login (UTC)": "(never)",
        "Logon Count": "0",
        "Failed Logon Count": "0",
        "Account Flags": "(unknown)",
    }
    if not f_data or len(f_data) < 0x48:
        return out
    try:
        # Layout (little-endian):
        # +0x08  FILETIME LastLogon
        # +0x18  FILETIME PasswordLastSet
        # +0x20  FILETIME AccountExpires
        # +0x28  FILETIME LastFailedLogon (newer schema)
        # +0x30  DWORD    RID
        # +0x38  DWORD    AccountFlags
        # +0x40  WORD     LogonCount
        # +0x42  WORD     FailedLogonCount  (when present)
        last_logon = struct.unpack_from("<Q", f_data, 0x08)[0]
        pwd_last = struct.unpack_from("<Q", f_data, 0x18)[0]
        expires = struct.unpack_from("<Q", f_data, 0x20)[0]
        flags = struct.unpack_from("<I", f_data, 0x38)[0]
        logon_count = struct.unpack_from("<H", f_data, 0x42)[0]

        out["Last Login (UTC)"] = decode_filetime(last_logon) or "(never)"
        out["Password Last Set (UTC)"] = decode_filetime(pwd_last) or "(never)"
        out["Account Expires (UTC)"] = decode_filetime(expires) or "(never)"
        out["Logon Count"] = str(logon_count)
        out["Account Flags"] = f"0x{flags:04X} -> {_decode_account_flags(flags)}"
        if len(f_data) >= 0x4A:
            failed = struct.unpack_from("<H", f_data, 0x44)[0]
            out["Failed Logon Count"] = str(failed)
    except struct.error:
        pass
    return out


@_safe
def extract_user_accounts(hive: LoadedHive) -> ArtifactResult:
    name = "User Accounts & Account Status"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.SAM)

    key = open_key(hive, r"SAM\Domains\Account\Users")
    if key is None:
        return _key_not_found_result(name, r"SAM\Domains\Account\Users")

    result = ArtifactResult(
        artifact_name=name,
        columns=["RID", "Username", "Full Name", "Login Count",
                 "Last Login (UTC)", "Last Password Change (UTC)",
                 "Account Expires (UTC)", "Failed Logon Count",
                 "Account Disabled", "Account Locked",
                 "Password Required", "Account Flags"],
        raw_key_last_write=key_last_write_utc(key),
    )

    for sub in list_subkeys(key):
        rid_name = sub.name()
        if not rid_name.startswith("0000"):
            continue
        try:
            rid_int = int(rid_name, 16)
        except ValueError:
            rid_int = 0

        v_raw, _ = get_value_raw(sub, "V")
        f_raw, _ = get_value_raw(sub, "F")
        v_data = bytes(v_raw) if isinstance(v_raw, (bytes, bytearray)) else b""
        f_data = bytes(f_raw) if isinstance(f_raw, (bytes, bytearray)) else b""

        v_fields = _decode_sam_v(v_data, rid_int)
        f_fields = _decode_sam_f(f_data)

        # Decode boolean-ish flags from the F record. The numeric mask
        # is in the "Account Flags" string we already produced.
        flag_str = f_fields["Account Flags"]
        disabled = "Yes" if "Account Disabled" in flag_str else "No"
        locked = "Yes" if "Account Auto-Locked" in flag_str else "No"
        # "Password Not Required" -> Password Required = No
        pwd_required = "No" if "Password Not Required" in flag_str else "Yes"

        # Severity: failed-logon spike or auto-locked is suspicious;
        # disabled is informational only.
        sev_flag = ""
        try:
            failed_n = int(f_fields["Failed Logon Count"])
            if failed_n >= 5:
                sev_flag = "SUSPICIOUS"
        except (TypeError, ValueError):
            pass
        if locked == "Yes":
            sev_flag = "SUSPICIOUS"

        username = v_fields["Username"] or "(unknown)"
        full_name = v_fields["Full Name"]

        result.rows.append(ArtifactRow(
            fields={
                "RID": f"{rid_int} (0x{rid_int:04X})",
                "Username": username,
                "Full Name": full_name,
                "Login Count": f_fields["Logon Count"],
                "Last Login (UTC)": f_fields["Last Login (UTC)"],
                "Last Password Change (UTC)": f_fields["Password Last Set (UTC)"],
                "Account Expires (UTC)": f_fields["Account Expires (UTC)"],
                "Failed Logon Count": f_fields["Failed Logon Count"],
                "Account Disabled": disabled,
                "Account Locked": locked,
                "Password Required": pwd_required,
                "Account Flags": flag_str,
            },
            flag=sev_flag,
        ))

    result.summary = (f"{len(result.rows)} local user account(s) recovered "
                      f"from SAM\\Domains\\Account\\Users.")
    return result


@_safe
def extract_password_policy(hive: LoadedHive) -> ArtifactResult:
    name = "Password Policies & LSA Secrets"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.SECURITY)

    result = ArtifactResult(
        artifact_name=name,
        columns=["Setting / Secret", "Value", "Note"],
    )

    accounts = open_key(hive, r"Policy\Accounts")
    if accounts is not None:
        result.raw_key_last_write = key_last_write_utc(accounts)
        for v in list_values(accounts):
            decoded = auto_decode(v.raw, v.value_type_name, v.name)
            note = ""
            flag = ""
            if v.name.lower() == "minimumpasswordlength":
                try:
                    if int(decoded.display.split()[0]) < 8:
                        note = "Weak: minimum password length below 8."
                        flag = "WARNING"
                except (ValueError, IndexError):
                    pass
            result.rows.append(ArtifactRow(
                fields={"Setting / Secret": v.name, "Value": decoded.display[:120],
                        "Note": note}, flag=flag))

    pol_secrets = open_key(hive, r"Policy\Secrets")
    if pol_secrets is None:
        pol_secrets = open_key(hive, r"Policy\PolSecrets")
    if pol_secrets is not None:
        for sub in list_subkeys(pol_secrets):
            result.rows.append(ArtifactRow(
                fields={"Setting / Secret": f"PolSecret: {sub.name()}",
                        "Value": "(encrypted)",
                        "Note": "Decryption requires SYSTEM boot key - outside scope."}))

    if not result.rows:
        result.error = "Neither Policy\\Accounts nor Policy\\Secrets present."
    else:
        result.summary = f"{len(result.rows)} password policy / LSA secret entr(y/ies)."
    return result


# ===========================================================================
# CATEGORY 7 - NETWORK ACTIVITY & CONNECTIVITY
# ===========================================================================

@_safe
def extract_network_interfaces(hive: LoadedHive) -> ArtifactResult:
    """Artifact 1 - Network Interface & Adapter Configuration.

    Reconstructs the host's network identity by correlating each
    interface GUID with its IPv4 lease, DHCP authority, and DNS
    resolver. Connection name is cross-referenced from
    ControlSet001\\Control\\Network\\<class>\\<guid>\\Connection\\Name
    so every row is identified by its friendly interface name in
    addition to the raw GUID.
    """
    name = "Network Interfaces & Adapters"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.SYSTEM)

    cs = active_controlset_path(hive)
    iface_key = open_key(hive, rf"{cs}\Services\Tcpip\Parameters\Interfaces")
    if iface_key is None:
        return _key_not_found_result(
            name, rf"{cs}\Services\Tcpip\Parameters\Interfaces")

    # Build a GUID -> friendly-connection-name lookup from the Network
    # subtree so we can label rows with the user-facing interface name.
    name_lookup: Dict[str, str] = {}
    network_root = open_key(hive, rf"{cs}\Control\Network")
    if network_root is not None:
        for class_key in list_subkeys(network_root):
            for adapter_key in list_subkeys(class_key):
                conn = open_key_by_subkey(adapter_key, "Connection")
                if conn is None:
                    continue
                nraw, vt = get_value_raw(conn, "Name")
                if nraw:
                    name_lookup[adapter_key.name().lower()] = (
                        auto_decode(nraw, vt, "Name").display)

    result = ArtifactResult(
        artifact_name=name,
        columns=["Interface GUID", "Interface Name", "IP Address",
                 "DHCP IP", "DHCP Server", "DNS Server",
                 "Lease Obtained", "Lease Expiry"],
        raw_key_last_write=key_last_write_utc(iface_key),
    )

    def _multi(raw: Any) -> str:
        """Render a REG_MULTI_SZ / REG_SZ / list value as a comma list."""
        if raw is None:
            return ""
        if isinstance(raw, (bytes, bytearray)):
            parts = utf16le_multi_sz(raw)
            return ", ".join(p for p in parts if p)
        if isinstance(raw, list):
            return ", ".join(str(p) for p in raw if p)
        return str(raw).strip()

    def _gv(k: Any, vname: str) -> str:
        raw, vt = get_value_raw(k, vname)
        if raw is None:
            return ""
        return auto_decode(raw, vt, vname).display

    for sub in list_subkeys(iface_key):
        guid = sub.name()
        # IP address - prefer static IPAddress, fall back to DhcpIPAddress
        static_ip_raw, _ = get_value_raw(sub, "IPAddress")
        static_ip = _multi(static_ip_raw)
        dhcp_ip = _gv(sub, "DhcpIPAddress")
        ip_addr = static_ip or dhcp_ip
        # Filter out the all-zero placeholder Windows leaves on inactive ifaces
        if ip_addr in ("0.0.0.0", ""):
            ip_addr = ""
            if dhcp_ip in ("0.0.0.0", ""):
                dhcp_ip = ""

        dhcp_server = _gv(sub, "DhcpServer")
        if dhcp_server == "255.255.255.255":
            dhcp_server = ""

        # DNS - prefer static NameServer, fall back to DhcpNameServer
        static_dns_raw, _ = get_value_raw(sub, "NameServer")
        static_dns = _multi(static_dns_raw)
        dhcp_dns = _gv(sub, "DhcpNameServer")
        dns = static_dns or dhcp_dns

        lease_obtained_raw, _ = get_value_raw(sub, "LeaseObtainedTime")
        lease_term_raw, _ = get_value_raw(sub, "LeaseTerminatesTime")
        lease_obtained = (decode_unix_epoch(lease_obtained_raw)
                          if lease_obtained_raw else "")
        lease_term = (decode_unix_epoch(lease_term_raw)
                      if lease_term_raw else "")

        # Skip pure placeholders that never had any configuration
        if (not ip_addr and not dhcp_ip and not dhcp_server
                and not dns and not lease_obtained and not lease_term):
            continue

        result.rows.append(ArtifactRow(fields={
            "Interface GUID": _dfir(guid),
            "Interface Name": _dfir(name_lookup.get(guid.lower(), "")),
            "IP Address": _dfir(ip_addr),
            "DHCP IP": _dfir(dhcp_ip),
            "DHCP Server": _dfir(dhcp_server),
            "DNS Server": _dfir(dns),
            "Lease Obtained": _dfir_time(lease_obtained),
            "Lease Expiry": _dfir_time(lease_term),
        }))

    result.summary = (
        f"{len(result.rows)} active interface(s) recovered. Connection "
        f"names cross-referenced from {cs}\\Control\\Network."
        if result.rows else
        "No configured network interfaces were recovered.")
    return _dfir_finalize(result)


@_safe
def extract_network_adapter_guids(hive: LoadedHive) -> ArtifactResult:
    """Artifact 2 - Network Adapter Enumeration.

    Binds each adapter's hardware identity (NIC class entry: DriverDesc,
    NetworkAddress / MAC, ProviderName + DriverVersion) to its logical
    interface (Connection\\Name) and to its IP-stack configuration
    (Tcpip\\Parameters\\Interfaces\\<guid>: IP, DHCP server, DNS).

    The join is keyed on the adapter's NetCfgInstanceId GUID, which
    appears in three places:
      Control\\Network\\<class>\\<guid>            - logical interface
      Control\\Class\\<NIC class>\\<index>          - hardware/driver
      Services\\Tcpip\\Parameters\\Interfaces\\<guid> - IP stack
    """
    name = "Network Adapter GUIDs"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.SYSTEM)

    cs = active_controlset_path(hive)
    network_root = open_key(hive, rf"{cs}\Control\Network")
    if network_root is None:
        return _key_not_found_result(name, rf"{cs}\Control\Network")

    # ---- Hardware-side index from Control\Class\<NIC class GUID> -----
    # Only walk the standard NIC class so we pick up Ethernet / Wi-Fi /
    # virtual NICs but skip everything else.
    NIC_CLASS = "{4d36e972-e325-11ce-bfc1-08002be10318}"
    hw_by_guid: Dict[str, Dict[str, str]] = {}
    class_root = open_key(hive, rf"{cs}\Control\Class\{NIC_CLASS}")
    if class_root is not None:
        for hw_key in list_subkeys(class_root):
            netcfg_raw, vt = get_value_raw(hw_key, "NetCfgInstanceId")
            if not netcfg_raw:
                continue
            guid = auto_decode(netcfg_raw, vt, "NetCfgInstanceId").display.lower()

            def _g(name_: str) -> str:
                r, t = get_value_raw(hw_key, name_)
                return auto_decode(r, t, name_).display if r else ""

            mac = _g("NetworkAddress")  # MAC override (if user set one)
            if not mac:
                # Permanent MAC isn't in the registry on most systems;
                # surface "—" rather than fabricating a value.
                mac = ""
            else:
                mac = ":".join(mac[i:i+2].upper()
                               for i in range(0, min(12, len(mac)), 2)) \
                    if len(mac) == 12 and all(c in "0123456789abcdefABCDEF"
                                              for c in mac) else mac

            driver_desc = _g("DriverDesc")
            provider = _g("ProviderName")
            driver_ver = _g("DriverVersion")
            driver = " / ".join([d for d in (provider, driver_ver) if d])

            hw_by_guid[guid] = {
                "DriverDesc": driver_desc,
                "MAC": mac,
                "Driver": driver,
            }

    # ---- IP-stack index from Tcpip\Parameters\Interfaces\<guid> ------
    ip_by_guid: Dict[str, Dict[str, str]] = {}
    iface_root = open_key(hive, rf"{cs}\Services\Tcpip\Parameters\Interfaces")
    if iface_root is not None:
        for if_sub in list_subkeys(iface_root):
            guid = if_sub.name().lower()

            def _gv(k_: Any, n_: str) -> str:
                r, t = get_value_raw(k_, n_)
                if r is None:
                    return ""
                return auto_decode(r, t, n_).display

            def _multi(raw: Any) -> str:
                if raw is None:
                    return ""
                if isinstance(raw, (bytes, bytearray)):
                    return ", ".join(p for p in utf16le_multi_sz(raw) if p)
                if isinstance(raw, list):
                    return ", ".join(str(p) for p in raw if p)
                return str(raw).strip()

            static_ip, _ = get_value_raw(if_sub, "IPAddress")
            dhcp_ip = _gv(if_sub, "DhcpIPAddress")
            ip_addr = _multi(static_ip) or dhcp_ip
            if ip_addr == "0.0.0.0":
                ip_addr = ""

            dhcp_server = _gv(if_sub, "DhcpServer")
            if dhcp_server == "255.255.255.255":
                dhcp_server = ""

            ns_raw, _ = get_value_raw(if_sub, "NameServer")
            dns = _multi(ns_raw) or _gv(if_sub, "DhcpNameServer")

            ip_by_guid[guid] = {
                "IP": ip_addr,
                "DHCP Server": dhcp_server,
                "DNS Server": dns,
            }

    # ---- Walk Control\Network\<class>\<guid> for logical interfaces -
    result = ArtifactResult(
        artifact_name=name,
        columns=["Adapter ID", "Adapter Name", "Interface Name",
                 "MAC Address", "IP Address", "DHCP Server",
                 "DNS Server", "Driver"],
        raw_key_last_write=key_last_write_utc(network_root),
    )

    for class_key in list_subkeys(network_root):
        for adapter_key in list_subkeys(class_key):
            guid = adapter_key.name()
            guid_low = guid.lower()
            conn = open_key_by_subkey(adapter_key, "Connection")
            interface_name = ""
            if conn is not None:
                nraw, vt = get_value_raw(conn, "Name")
                if nraw:
                    interface_name = auto_decode(nraw, vt, "Name").display

            hw = hw_by_guid.get(guid_low, {})
            ip = ip_by_guid.get(guid_low, {})

            result.rows.append(ArtifactRow(fields={
                "Adapter ID": _dfir(guid),
                "Adapter Name": _dfir(hw.get("DriverDesc", "")),
                "Interface Name": _dfir(interface_name),
                "MAC Address": _dfir(hw.get("MAC", "")),
                "IP Address": _dfir(ip.get("IP", "")),
                "DHCP Server": _dfir(ip.get("DHCP Server", "")),
                "DNS Server": _dfir(ip.get("DNS Server", "")),
                "Driver": _dfir(hw.get("Driver", "")),
            }))

    result.summary = (f"{len(result.rows)} adapter(s) enumerated; "
                      f"hardware identity joined to interface configuration.")
    return _dfir_finalize(result)


@_safe
def extract_network_profiles(hive: LoadedHive) -> ArtifactResult:
    name = "Network Profile"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.SOFTWARE)

    key = open_key(hive, r"Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles")
    if key is None:
        return _key_not_found_result(name, r"Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles")

    cat_map = {0: "Public", 1: "Private", 2: "Domain"}

    result = ArtifactResult(
        artifact_name=name,
        columns=["Profile GUID", "ProfileName", "Description",
                 "Date Created (UTC)", "Date Last Connected (UTC)",
                 "Category"],
        raw_key_last_write=key_last_write_utc(key),
    )

    for sub in list_subkeys(key):
        pname_raw, vt1 = get_value_raw(sub, "ProfileName")
        desc_raw, vt2 = get_value_raw(sub, "Description")
        created_raw, _ = get_value_raw(sub, "DateCreated")
        last_raw, _ = get_value_raw(sub, "DateLastConnected")
        cat_raw, _ = get_value_raw(sub, "Category")

        try:
            cat_int = int(cat_raw) if cat_raw is not None else None
            cat_text = cat_map.get(cat_int, str(cat_int)) if cat_int is not None else ""
        except (TypeError, ValueError):
            cat_text = str(cat_raw) if cat_raw is not None else ""

        result.rows.append(ArtifactRow(
            fields={
                "Profile GUID": sub.name(),
                "ProfileName": auto_decode(pname_raw, vt1, "ProfileName").display if pname_raw else "",
                "Description": auto_decode(desc_raw, vt2, "Description").display if desc_raw else "",
                "Date Created (UTC)": decode_systemtime(bytes(created_raw)) if isinstance(created_raw, (bytes, bytearray)) else "",
                "Date Last Connected (UTC)": decode_systemtime(bytes(last_raw)) if isinstance(last_raw, (bytes, bytearray)) else "",
                "Category": cat_text,
            },
        ))

    result.summary = f"{len(result.rows)} network profile(s)."
    return result


@_safe
def extract_wireless_profiles(hive: LoadedHive) -> ArtifactResult:
    """Artifact 3 - Wireless SSID Connection History.

    Reconstructs every wireless network the host has associated with
    by joining NetworkList\\Profiles (timestamps, NameType) with
    NetworkList\\Signatures\\Unmanaged (gateway MAC, DNS suffix).
    Wired profiles are excluded (NameType=6 wireless,
    NameType=23 wired, NameType=71 mobile broadband). The WlanSvc
    profile XMLs are scanned as a secondary source so SSIDs that have
    been *configured* but never connected (and thus have no
    NetworkList timestamp) are still reported.
    """
    name = "Network Signature"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.SOFTWARE)

    profiles_root = open_key(
        hive, r"Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles")
    sigs_root = open_key(
        hive,
        r"Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged")

    if profiles_root is None and sigs_root is None and (
            open_key(hive, r"Microsoft\WlanSvc\Interfaces") is None):
        return _key_not_found_result(
            name, r"Microsoft\Windows NT\CurrentVersion\NetworkList")

    # ---- Build a Signatures\Unmanaged index keyed on ProfileGuid ----
    sig_by_profile: Dict[str, Dict[str, str]] = {}
    if sigs_root is not None:
        for sig in list_subkeys(sigs_root):
            def _g(name_: str) -> str:
                r, t = get_value_raw(sig, name_)
                return auto_decode(r, t, name_).display if r else ""
            profile_guid = _g("ProfileGuid").strip("{}").lower()
            if not profile_guid:
                continue
            mac_raw, _ = get_value_raw(sig, "DefaultGatewayMac")
            mac = ""
            if isinstance(mac_raw, (bytes, bytearray)) and len(mac_raw) >= 6:
                mac = ":".join(f"{b:02X}" for b in bytes(mac_raw[:6]))
            sig_by_profile[profile_guid] = {
                "GatewayMAC": mac,
                "DnsSuffix": _g("DnsSuffix"),
            }

    rows_by_ssid: Dict[str, ArtifactRow] = {}

    # ---- Primary: NetworkList\Profiles (wireless only) ---------------
    if profiles_root is not None:
        for prof in list_subkeys(profiles_root):
            def _g(name_: str) -> str:
                r, t = get_value_raw(prof, name_)
                return auto_decode(r, t, name_).display if r else ""

            nt_raw, _ = get_value_raw(prof, "NameType")
            try:
                ntype = int(nt_raw) if nt_raw is not None else 0
            except (TypeError, ValueError):
                ntype = 0
            # 6 = wireless 802.11; 71 = mobile broadband; 23 = wired
            if ntype not in (6, 71):
                continue

            profile_name = _g("ProfileName")  # equals SSID for wireless
            if not profile_name:
                continue

            created_raw, _ = get_value_raw(prof, "DateCreated")
            last_raw, _ = get_value_raw(prof, "DateLastConnected")
            first_connected = (decode_systemtime(bytes(created_raw))
                               if isinstance(created_raw, (bytes, bytearray))
                               else "")
            last_connected = (decode_systemtime(bytes(last_raw))
                              if isinstance(last_raw, (bytes, bytearray))
                              else "")

            net_type = ("Wireless 802.11" if ntype == 6
                        else "Mobile Broadband")

            # Match on this profile's GUID (the subkey name is the GUID
            # in some builds; on others ProfileGuid is a value)
            pguid_value = _g("ProfileGuid").strip("{}").lower()
            pguid = pguid_value or prof.name().strip("{}").lower()
            sig = sig_by_profile.get(pguid, {})

            rows_by_ssid[profile_name] = ArtifactRow(fields={
                "SSID": _dfir(profile_name),
                "First Connected": _dfir_time(first_connected),
                "Last Connected": _dfir_time(last_connected),
                "Network Type": _dfir(net_type),
                "Gateway MAC": _dfir(sig.get("GatewayMAC", "")),
                "DNS Suffix": _dfir(sig.get("DnsSuffix", "")),
            })

    # ---- Secondary: WlanSvc XML profiles -----------------------------
    # Adds SSIDs that were saved as profiles but never connected, so
    # they don't have a NetworkList\Profiles entry.
    import re as _re
    wlan_root = open_key(hive, r"Microsoft\WlanSvc\Interfaces")
    if wlan_root is not None:
        def _ssids_from_blob(raw: Any) -> List[str]:
            if isinstance(raw, (bytes, bytearray)):
                xml = utf16le_to_str(raw)
                if not xml:
                    try:
                        xml = bytes(raw).decode("utf-8", errors="replace")
                    except Exception:
                        return []
            elif isinstance(raw, str):
                xml = raw
            else:
                return []
            if "<" not in xml:
                return []
            return _re.findall(r"<name>([^<]+)</name>", xml)

        for iface_sub in list_subkeys(wlan_root):
            profiles_sub = open_key_by_subkey(iface_sub, "Profiles")
            walk = ([profiles_sub] if profiles_sub is not None
                    else [iface_sub])
            for parent in walk:
                # Walk one level of subkeys (per-profile keys carrying values)
                sub_iter = list_subkeys(parent) or [parent]
                for k_ in sub_iter:
                    for v in list_values(k_):
                        for ssid in _ssids_from_blob(v.raw):
                            if ssid and ssid not in rows_by_ssid:
                                rows_by_ssid[ssid] = ArtifactRow(fields={
                                    "SSID": _dfir(ssid),
                                    "First Connected": DFIR_MISSING,
                                    "Last Connected": DFIR_MISSING,
                                    "Network Type": "Wireless 802.11",
                                    "Gateway MAC": DFIR_MISSING,
                                    "DNS Suffix": DFIR_MISSING,
                                })

    result = ArtifactResult(
        artifact_name=name,
        columns=["SSID", "First Connected", "Last Connected",
                 "Network Type", "Gateway MAC", "DNS Suffix"],
        raw_key_last_write=(key_last_write_utc(profiles_root)
                            if profiles_root is not None else ""),
    )
    # Sort: rows that have a Last Connected timestamp come first, most
    # recent first. The remainder (SSIDs configured but never connected)
    # follow alphabetically.
    sortable = list(rows_by_ssid.values())
    sortable.sort(key=lambda r: (
        r.fields.get("Last Connected") in (DFIR_MISSING, ""),
        r.fields.get("Last Connected") or "",
        r.fields.get("SSID", "")),
    )
    # Reverse the connected-date direction so newest is first
    connected = [r for r in sortable
                 if r.fields.get("Last Connected") not in (DFIR_MISSING, "")]
    connected.sort(key=lambda r: r.fields.get("Last Connected", ""),
                   reverse=True)
    never = [r for r in sortable
             if r.fields.get("Last Connected") in (DFIR_MISSING, "")]
    never.sort(key=lambda r: r.fields.get("SSID", "").lower())
    result.rows = connected + never

    result.summary = (
        f"{len(result.rows)} SSID(s) in wireless connection history. "
        f"Note: encrypted Wi-Fi credentials are protected by SYSTEM-account "
        f"DPAPI keys and remain out of scope.")
    return _dfir_finalize(result)


@_safe
def extract_vpn_profiles(hive: LoadedHive) -> ArtifactResult:
    """Artifact 4 - VPN Profile Artifacts.

    Surfaces every VPN/RAS connection name visible in the registry.
    The Connections value blobs are RAS phonebook serialisations whose
    server address / VPN type / username live encrypted in DPAPI -
    the registry exposes only the connection NAMES safely. Server
    address, type, username, and last-connected timestamp are
    therefore reported as '—' here unless a parallel rasphone.pbk
    artifact is loaded (out of scope for offline-registry analysis).
    """
    name = "VPN Profiles"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.NTUSER)

    key = open_key(
        hive,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections")
    if key is None:
        return _key_not_found_result(
            name,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections")

    result = ArtifactResult(
        artifact_name=name,
        columns=["VPN Name", "Server Address", "VPN Type",
                 "Username", "Last Connected", "Source"],
        raw_key_last_write=key_last_write_utc(key),
    )

    SKIP_NAMES = {
        "DefaultConnectionSettings",  # IE/Edge proxy settings, not a VPN
        "SavedLegacySettings",        # legacy proxy struct
    }

    for v in list_values(key):
        if v.name in SKIP_NAMES:
            continue
        # The phonebook blob is opaque without DPAPI keys; we publish
        # the connection name and let the rest fall to '—'.
        result.rows.append(ArtifactRow(fields={
            "VPN Name": _dfir(v.name),
            "Server Address": DFIR_MISSING,
            "VPN Type": DFIR_MISSING,
            "Username": DFIR_MISSING,
            "Last Connected": DFIR_MISSING,
            "Source": "Registry: Internet Settings\\Connections",
        }))

    result.summary = (
        f"{len(result.rows)} VPN/RAS connection name(s) recovered. "
        f"DPAPI-protected fields (server, type, username) require the "
        f"SYSTEM master key and are not present in offline registry data.")
    return _dfir_finalize(result)


@_safe
def extract_mapped_drives(hive: LoadedHive) -> ArtifactResult:
    name = "Mapped Network Drives"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.NTUSER)

    key = open_key(hive, "Network")
    if key is None:
        return _key_not_found_result(name, "Network")

    result = ArtifactResult(
        artifact_name=name,
        columns=["Drive Letter", "Remote Path", "Username", "Provider"],
        raw_key_last_write=key_last_write_utc(key),
    )

    for sub in list_subkeys(key):
        rp_raw, vt1 = get_value_raw(sub, "RemotePath")
        un_raw, vt2 = get_value_raw(sub, "UserName")
        pn_raw, vt3 = get_value_raw(sub, "ProviderName")
        result.rows.append(ArtifactRow(
            fields={
                "Drive Letter": sub.name(),
                "Remote Path": auto_decode(rp_raw, vt1, "RemotePath").display if rp_raw else "",
                "Username": auto_decode(un_raw, vt2, "UserName").display if un_raw else "",
                "Provider": auto_decode(pn_raw, vt3, "ProviderName").display if pn_raw else "",
            },
            flag="WARNING" if rp_raw else "",
            interpretation="Remote share access recorded by the user." if rp_raw else "",
        ))

    result.summary = f"{len(result.rows)} mapped drive(s) recorded."
    return result


def _firewall_open_base(hive: LoadedHive) -> Any:
    """Locate the FirewallPolicy key under the active ControlSet."""
    cs = active_controlset_path(hive)
    return open_key(hive, rf"{cs}\Services\SharedAccess\Parameters\FirewallPolicy")


_PROFILE_LABEL = {
    "DomainProfile":   "Domain",
    "StandardProfile": "Standard (Private)",
    "PublicProfile":   "Public",
}

_FW_ACTION_LABEL = {0: "Block", 1: "Allow"}


def _parse_firewall_rule(text: str) -> Dict[str, str]:
    """Split a Windows firewall rule value (pipe-separated key=value
    pairs) into a dict. Unrecognised tokens are ignored."""
    out: Dict[str, str] = {}
    for tok in text.split("|"):
        if "=" in tok:
            k, _, v = tok.partition("=")
            out[k.strip()] = v.strip()
    return out


def _firewall_protocol_label(num: str) -> str:
    """Map Windows firewall protocol numbers to IANA names."""
    if not num:
        return ""
    table = {"1": "ICMPv4", "6": "TCP", "17": "UDP", "47": "GRE",
             "50": "ESP", "51": "AH", "58": "ICMPv6", "112": "VRRP"}
    return table.get(num.strip(), num.strip())


@_safe
def extract_firewall_status(hive: LoadedHive) -> ArtifactResult:
    """Artifact 5 / Table 1 - Firewall Status (per profile).

    Profile | Status | Default Inbound | Default Outbound
    """
    name = "Firewall Status"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.SYSTEM)

    base = _firewall_open_base(hive)
    if base is None:
        cs = active_controlset_path(hive)
        return _key_not_found_result(
            name, rf"{cs}\Services\SharedAccess\Parameters\FirewallPolicy")

    result = ArtifactResult(
        artifact_name=name,
        columns=["Profile", "Status", "Default Inbound", "Default Outbound"],
        raw_key_last_write=key_last_write_utc(base),
    )

    for profile_subkey, label in _PROFILE_LABEL.items():
        prof = open_key_by_subkey(base, profile_subkey)
        if prof is None:
            continue

        def _get_int(name_: str) -> Any:
            r, _ = get_value_raw(prof, name_)
            try:
                return int(r) if r is not None else None
            except (TypeError, ValueError):
                return None

        enabled = _get_int("EnableFirewall")
        in_action = _get_int("DefaultInboundAction")
        out_action = _get_int("DefaultOutboundAction")

        status = ("Enabled" if enabled == 1 else
                  "Disabled" if enabled == 0 else "")
        in_label = _FW_ACTION_LABEL.get(in_action, "")
        out_label = _FW_ACTION_LABEL.get(out_action, "")

        flag = "HIGH RISK" if enabled == 0 else ""

        result.rows.append(ArtifactRow(
            fields={
                "Profile": _dfir(label),
                "Status": _dfir(status),
                "Default Inbound": _dfir(in_label),
                "Default Outbound": _dfir(out_label),
            },
            flag=flag,
        ))

    result.summary = (f"{len(result.rows)} firewall profile(s) inspected. "
                      f"Disabled profiles are marked HIGH RISK.")
    return _dfir_finalize(result)


@_safe
def extract_firewall_rules(hive: LoadedHive) -> ArtifactResult:
    """Artifact 5 / Table 2 - Firewall Rules.

    Rule Name | Direction | Action | Protocol | Port | Application
    """
    name = "Firewall Rules"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.SYSTEM)

    base = _firewall_open_base(hive)
    if base is None:
        cs = active_controlset_path(hive)
        return _key_not_found_result(
            name, rf"{cs}\Services\SharedAccess\Parameters\FirewallPolicy")

    rules_key = open_key_by_subkey(base, "FirewallRules")
    if rules_key is None:
        result = ArtifactResult(
            artifact_name=name,
            columns=["Rule Name", "Direction", "Action",
                     "Protocol", "Port", "Application"],
            summary="No FirewallRules subkey present.",
        )
        return _dfir_finalize(result)

    result = ArtifactResult(
        artifact_name=name,
        columns=["Rule Name", "Direction", "Action",
                 "Protocol", "Port", "Application"],
        raw_key_last_write=key_last_write_utc(rules_key),
    )

    cap = 0
    for v in list_values(rules_key):
        cap += 1
        if cap > 500:
            break
        text = auto_decode(v.raw, v.value_type_name, v.name).display
        parts = _parse_firewall_rule(text)

        rule_name = parts.get("Name", v.name)
        direction = parts.get("Dir", "")
        direction = ("Inbound" if direction == "In"
                     else "Outbound" if direction == "Out"
                     else direction)
        action = parts.get("Action", "")
        protocol = _firewall_protocol_label(parts.get("Protocol", ""))
        # Port: prefer LocalPort (LPort) for inbound, RemotePort (RPort)
        # for outbound; concatenate when both present.
        lport = parts.get("LPort", "")
        rport = parts.get("RPort", "")
        port = lport or rport or ""
        if lport and rport:
            port = f"L:{lport} R:{rport}"
        application = parts.get("App", "") or parts.get("Svc", "")

        # Severity: Allow rules that expose an application or a port
        # are noteworthy, especially inbound.
        flag = ""
        if action.lower() == "allow":
            if direction == "Inbound" and (port or application):
                flag = "WARNING"

        result.rows.append(ArtifactRow(
            fields={
                "Rule Name": _dfir(rule_name)[:120],
                "Direction": _dfir(direction),
                "Action": _dfir(action),
                "Protocol": _dfir(protocol),
                "Port": _dfir(port),
                "Application": _dfir(application)[:120],
            },
            flag=flag,
        ))

    truncated = " (capped at first 500)" if cap > 500 else ""
    result.summary = (f"{len(result.rows)} firewall rule(s){truncated}. "
                      f"Inbound 'Allow' rules with an application or "
                      f"port set are flagged WARNING.")
    return _dfir_finalize(result)


@_safe
def extract_firewall_open_ports(hive: LoadedHive) -> ArtifactResult:
    """Artifact 5 / Table 3 - Open Ports.

    Port | Protocol | Application | Direction | Rule Name

    A filtered view of FirewallRules: every Allow rule that names an
    explicit local port (LPort) is reported here as an exposed
    listener.
    """
    name = "Open Ports"
    if not hive or not hive.loaded_ok:
        return _hive_missing_result(name, HiveType.SYSTEM)

    base = _firewall_open_base(hive)
    if base is None:
        cs = active_controlset_path(hive)
        return _key_not_found_result(
            name, rf"{cs}\Services\SharedAccess\Parameters\FirewallPolicy")

    rules_key = open_key_by_subkey(base, "FirewallRules")
    result = ArtifactResult(
        artifact_name=name,
        columns=["Port", "Protocol", "Application", "Direction", "Rule Name"],
        raw_key_last_write=(key_last_write_utc(rules_key)
                            if rules_key is not None else ""),
    )
    if rules_key is None:
        result.summary = "No FirewallRules subkey present."
        return _dfir_finalize(result)

    for v in list_values(rules_key):
        text = auto_decode(v.raw, v.value_type_name, v.name).display
        parts = _parse_firewall_rule(text)
        # Open port = Allow + an explicit LPort (inbound listener) or
        # an explicit RPort (outbound channel).
        if parts.get("Action", "").lower() != "allow":
            continue
        if parts.get("Active", "TRUE").upper() == "FALSE":
            continue
        lport = parts.get("LPort", "")
        rport = parts.get("RPort", "")
        if not lport and not rport:
            continue

        direction = parts.get("Dir", "")
        direction = ("Inbound" if direction == "In"
                     else "Outbound" if direction == "Out"
                     else direction)
        port = lport or rport
        flag = "WARNING" if direction == "Inbound" else ""

        result.rows.append(ArtifactRow(
            fields={
                "Port": _dfir(port),
                "Protocol": _dfir(_firewall_protocol_label(
                    parts.get("Protocol", ""))),
                "Application": _dfir(parts.get("App", "")
                                     or parts.get("Svc", ""))[:120],
                "Direction": _dfir(direction),
                "Rule Name": _dfir(parts.get("Name", v.name))[:120],
            },
            flag=flag,
        ))

    result.summary = (f"{len(result.rows)} listening / exposed port "
                      f"rule(s) recovered (Allow + explicit port). "
                      f"Inbound entries flagged WARNING.")
    return _dfir_finalize(result)


# Back-compat alias - older code paths may still import this symbol
extract_firewall_profiles = extract_firewall_status


# ===========================================================================
# CATEGORY 9 - WINDOWS EVENT LOG ANALYSIS  (reads .evtx, not hives)
# ===========================================================================
# These extractors take a path to an .evtx file rather than a LoadedHive.
# They are called via separate helper functions in the GUI rather than the
# generic extract(hive) interface, but use the same ArtifactResult shape so
# the report generator and table view can render them uniformly.
#
# Two backends are supported, in priority order:
#   1. ``evtx`` (Rust-backed PyEvtxParser) — orders of magnitude faster.
#      Install with: pip install evtx
#   2. ``python-evtx`` (pure-Python Evtx) — much slower but works.
#      Install with: pip install python-evtx
#
# The tool prefers whichever is available and transparently falls back.

import re as _re

# --- Backend 1: Rust-backed evtx (PyEvtxParser) ---
try:
    from evtx import PyEvtxParser as _PyEvtxParser  # type: ignore
    _EVTX_FAST_AVAILABLE = True
except Exception:
    _PyEvtxParser = None  # type: ignore
    _EVTX_FAST_AVAILABLE = False

# --- Backend 2: Pure-Python python-evtx ---
try:
    from Evtx.Evtx import Evtx as _EvtxFile  # python-evtx
    from xml.etree import ElementTree as _ET
    _EVTX_SLOW_AVAILABLE = True
except Exception:
    _EvtxFile = None  # type: ignore
    _ET = None        # type: ignore
    _EVTX_SLOW_AVAILABLE = False

# At least one backend must be available for EVTX parsing to work.
_EVTX_AVAILABLE = _EVTX_FAST_AVAILABLE or _EVTX_SLOW_AVAILABLE

# Maximum matched events per file.  When the cap is reached the parser
# stops early and annotates the result summary with a truncation notice.
_EVTX_EVENT_CAP = 10_000

# Regex to extract EventID from an XML string without full DOM parsing.
# This runs only on the first ~500 chars of each record's XML (the System
# element is always near the top), making it dramatically faster than
# ElementTree.fromstring() for non-matching records.
_EVTX_EID_RE = _re.compile(r"<EventID[^>]*>(\d+)</EventID>")


def _evtx_unavailable_result(artifact_name: str) -> ArtifactResult:
    return ArtifactResult(
        artifact_name=artifact_name,
        columns=[],
        error=("The 'python-evtx' or 'evtx' package is required for "
               ".evtx parsing. Install with: pip install evtx  (fast, "
               "recommended) or pip install python-evtx"),
    )


def _strip_namespace(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag


def _parse_xml_record(xml_text: str) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Parse a single EVTX XML record into (system_dict, event_data_dict)."""
    system: Dict[str, str] = {}
    event_data: Dict[str, str] = {}
    try:
        root = _ET.fromstring(xml_text)
    except Exception:
        return system, event_data
    for child in root.iter():
        tag = _strip_namespace(child.tag)
        if tag == "EventID":
            system["EventID"] = (child.text or "").strip()
        elif tag == "TimeCreated":
            system["TimeCreated"] = child.attrib.get("SystemTime", "")
        elif tag == "Computer":
            system["Computer"] = (child.text or "").strip()
        elif tag == "Channel":
            system["Channel"] = (child.text or "").strip()
        elif tag == "Provider":
            system["Provider"] = child.attrib.get("Name", "")
        elif tag == "Level":
            system["Level"] = (child.text or "").strip()
        elif tag == "Data":
            nm = child.attrib.get("Name", "Data")
            event_data[nm] = (child.text or "").strip()
    return system, event_data


def _iter_evtx_filtered_fast(
    file_path: str,
    target_ids: set,
    cap: int = _EVTX_EVENT_CAP,
) -> Tuple[List[Tuple[Dict[str, str], Dict[str, str]]], bool]:
    """Parse an .evtx file using the fast Rust-backed PyEvtxParser.

    Returns ``(matched_records, was_truncated)``.
    """
    matched: List[Tuple[Dict[str, str], Dict[str, str]]] = []
    truncated = False

    parser = _PyEvtxParser(file_path)
    for record in parser.records():
        xml_text = record.get("data", "")
        if not xml_text:
            continue
        # Fast regex pre-filter: extract EventID without DOM parsing
        m = _EVTX_EID_RE.search(xml_text, 0, 500)
        if not m or m.group(1) not in target_ids:
            continue
        # Full parse only for matching records
        system, event_data = _parse_xml_record(xml_text)
        if not system.get("EventID"):
            system["EventID"] = m.group(1)
        matched.append((system, event_data))
        if len(matched) >= cap:
            truncated = True
            break

    return matched, truncated


def _iter_evtx_filtered_slow(
    file_path: str,
    target_ids: set,
    cap: int = _EVTX_EVENT_CAP,
) -> Tuple[List[Tuple[Dict[str, str], Dict[str, str]]], bool]:
    """Parse an .evtx file using the pure-Python python-evtx library.

    Optimised with regex pre-filtering: the EventID is extracted from
    the raw XML string via regex *before* calling ET.fromstring(), so
    non-matching records (typically 95-99% of the file) skip the
    expensive DOM parse entirely.

    Returns ``(matched_records, was_truncated)``.
    """
    matched: List[Tuple[Dict[str, str], Dict[str, str]]] = []
    truncated = False

    with _EvtxFile(file_path) as log:
        for record in log.records():
            try:
                xml_text = record.xml()
            except Exception:
                continue

            # Regex pre-filter: extract EventID from the first 500
            # chars of the XML string.  This avoids the very expensive
            # ET.fromstring() call for records that don't match.
            m = _EVTX_EID_RE.search(xml_text, 0, 500)
            if not m or m.group(1) not in target_ids:
                continue

            # Full DOM parse only for the ~2% of records that match
            system, event_data = _parse_xml_record(xml_text)
            if not system.get("EventID"):
                system["EventID"] = m.group(1)
            matched.append((system, event_data))

            if len(matched) >= cap:
                truncated = True
                break

    return matched, truncated


def _iter_evtx_filtered(
    file_path: str,
    target_ids: set,
    cap: int = _EVTX_EVENT_CAP,
) -> Tuple[List[Tuple[Dict[str, str], Dict[str, str]]], bool]:
    """Parse an .evtx file, yielding only records whose EventID is in
    *target_ids*.  Stops after *cap* matched events.

    Returns ``(matched_records, was_truncated)``.

    Automatically selects the fastest available backend:
      1. Rust-backed PyEvtxParser (``pip install evtx``) — preferred.
      2. Pure-Python python-evtx with regex pre-filtering — fallback.

    Filtering is performed **at parse time** (inside the iterator) so
    the tool never materialises the full event stream of multi-GB log
    files.  This is a hard requirement of the specification.
    """
    if not _EVTX_AVAILABLE:
        return [], False

    if _EVTX_FAST_AVAILABLE:
        return _iter_evtx_filtered_fast(file_path, target_ids, cap)
    return _iter_evtx_filtered_slow(file_path, target_ids, cap)


# ===================================================================
# Auditable Event-ID → English lookup dictionaries
# ===================================================================
# Each dictionary is the single authoritative map for its artifact.
# Raw numeric IDs alone are NOT acceptable output; every ID shown in
# the "Event Type" column must resolve through one of these dicts.

_SYSTEM_EVENT_TYPES: Dict[str, str] = {
    "6005": "Event Log Service Started (Boot)",
    "6006": "Event Log Service Stopped (Shutdown)",
    "6008": "Unexpected Shutdown",
    "6009": "OS Version Banner at Boot",
    "6013": "System Uptime (seconds)",
    "1074": "Shutdown/Restart Initiated",
    "41":   "Kernel-Power: Unclean Reboot",
    "109":  "Kernel-General: Shutdown Reason",
    "12":   "Kernel-General: OS Started",
    "13":   "Kernel-General: OS Shutting Down",
}

_SECURITY_EVENT_TYPES: Dict[str, str] = {
    "4624": "Successful Logon",
    "4625": "Failed Logon",
    "4634": "Logoff",
    "4647": "User Initiated Logoff",
    "4648": "Explicit Credential Logon",
    "4672": "Special Privileges Assigned",
    "4720": "User Account Created",
    "4722": "User Account Enabled",
    "4724": "Password Reset Attempted",
    "4725": "User Account Disabled",
    "4726": "User Account Deleted",
    "4728": "Member Added to Global Group",
    "4732": "Member Added to Local Group",
    "4740": "User Account Locked Out",
    "4756": "Member Added to Universal Group",
    "4768": "Kerberos TGT Requested",
    "4769": "Kerberos Service Ticket Requested",
    "4776": "NTLM Credential Validation",
    "1102": "Audit Log Cleared",
}

_APPLICATION_EVENT_TYPES: Dict[str, str] = {
    "1000": "Application Crash",
    "1001": "Windows Error Reporting",
    "1002": "Application Hang",
    "1026": ".NET Runtime Error",
    "1033": "MSI Install Completed",
    "1034": "MSI Removal Completed",
    "1035": "MSI Reconfiguration Completed",
    "11707": "Install Operation Successful",
    "11708": "Install Operation Failed",
    "11724": "Application Removal Completed",
}

# Logon Type → English label (label-first, code in parens per spec)
_LOGON_TYPE_LABELS: Dict[int, str] = {
    2:  "Interactive (2)",
    3:  "Network (3)",
    4:  "Batch (4)",
    5:  "Service (5)",
    7:  "Unlock (7)",
    8:  "NetworkCleartext (8)",
    9:  "NewCredentials (9)",
    10: "RemoteInteractive (10)",
    11: "CachedInteractive (11)",
}

# Security event IDs that always produce a "Failure" result
_SECURITY_FAILURE_IDS = {"4625"}

# Level code → Severity label (Application.evtx)
_LEVEL_LABELS: Dict[str, str] = {
    "1": "Critical",
    "2": "Error",
    "3": "Warning",
    "4": "Information",
    "5": "Verbose",
}


# ===================================================================
# ARTIFACT 1 — System Event Log
# ===================================================================

def parse_system_log(file_path: str) -> ArtifactResult:
    """Parse System.evtx for startup / shutdown / power-state events.

    Required output columns (fixed order):
        Event Time | Event ID | Event Type | Source | Computer | Details
    """
    name = "System Logs (Startup/Shutdown)"
    if not _EVTX_AVAILABLE:
        return _evtx_unavailable_result(name)

    columns = ["Event Time", "Event ID", "Event Type",
               "Source", "Computer", "Details"]
    result = ArtifactResult(artifact_name=name, columns=columns)

    try:
        records, truncated = _iter_evtx_filtered(
            file_path, set(_SYSTEM_EVENT_TYPES.keys()))
    except Exception as exc:  # noqa: BLE001
        result.error = f"{exc.__class__.__name__}: {exc}"
        return result

    for sysd, data in records:
        eid = sysd.get("EventID", "")
        event_type = _SYSTEM_EVENT_TYPES.get(eid, DFIR_MISSING)

        # Build a concise Details string from event data
        details_parts: List[str] = []
        if eid == "1074":
            user = data.get("param7", data.get("param6", ""))
            reason = data.get("param3", "")
            process = data.get("param1", "")
            if user:
                details_parts.append(f"User: {user}")
            if reason:
                details_parts.append(f"Reason: {reason}")
            if process:
                details_parts.append(f"Process: {process}")
        elif eid == "6008":
            prev_time = data.get("param1", "")
            prev_date = data.get("param2", "")
            if prev_time or prev_date:
                details_parts.append(
                    f"Previous shutdown: {prev_date} {prev_time}".strip())
        elif eid == "6009":
            # OS version fields are in param1..param4
            parts = [data.get(f"param{i}", "") for i in range(1, 5)]
            version = " ".join(p for p in parts if p)
            if version:
                details_parts.append(f"OS: {version}")
        elif eid == "6013":
            uptime = data.get("param1", data.get("Data", ""))
            if uptime:
                details_parts.append(f"Uptime: {uptime}s")
        else:
            # Generic: concatenate non-empty Data values
            generic = " ".join(v for v in data.values() if v)[:200]
            if generic:
                details_parts.append(generic)

        details = "; ".join(details_parts) if details_parts else DFIR_MISSING

        flag = ""
        if eid == "6008":
            flag = "WARNING"
        elif eid == "41":
            flag = "HIGH RISK"

        result.rows.append(ArtifactRow(
            fields={
                "Event Time": _dfir_time(sysd.get("TimeCreated", "")),
                "Event ID":   _dfir(eid),
                "Event Type": event_type,
                "Source":     _dfir(sysd.get("Provider", "")),
                "Computer":  _dfir(sysd.get("Computer", "")),
                "Details":   details,
            },
            flag=flag,
        ))

    # Sort: most-recent first
    result.rows.sort(
        key=lambda r: r.fields.get("Event Time", ""), reverse=True)

    count = len(result.rows)
    trunc_note = f"  Truncated at {count} events." if truncated else ""
    result.summary = (
        f"{count} startup/shutdown/power-state event(s) extracted.{trunc_note}")

    return _dfir_finalize(result)


# ===================================================================
# ARTIFACT 2 — Security Event Log
# ===================================================================

def parse_security_log(file_path: str) -> ArtifactResult:
    """Parse Security.evtx for logon / authentication / account events.

    Required output columns (fixed order):
        Event Time | Event ID | Event Type | User | Logon Type | Source IP | Result
    """
    name = "Security Logs (Logon/Authentication)"
    if not _EVTX_AVAILABLE:
        return _evtx_unavailable_result(name)

    columns = ["Event Time", "Event ID", "Event Type",
               "User", "Logon Type", "Source IP", "Result"]
    result = ArtifactResult(artifact_name=name, columns=columns)

    try:
        records, truncated = _iter_evtx_filtered(
            file_path, set(_SECURITY_EVENT_TYPES.keys()))
    except Exception as exc:  # noqa: BLE001
        result.error = f"{exc.__class__.__name__}: {exc}"
        return result

    failed_streak = 0  # consecutive failed logon counter

    for sysd, data in records:
        eid = sysd.get("EventID", "")
        event_type = _SECURITY_EVENT_TYPES.get(eid, DFIR_MISSING)

        # --- User ---
        user = (data.get("TargetUserName")
                or data.get("SubjectUserName")
                or "")

        # --- Logon Type (only meaningful for 4624/4625) ---
        logon_type_raw = data.get("LogonType", "")
        if logon_type_raw and logon_type_raw.isdigit():
            lt_code = int(logon_type_raw)
            logon_type = _LOGON_TYPE_LABELS.get(lt_code, f"Unknown ({lt_code})")
        elif logon_type_raw:
            logon_type = logon_type_raw
        else:
            logon_type = ""

        # --- Source IP ---
        ip = data.get("IpAddress", "")
        if not ip or ip == "-":
            ip = data.get("WorkstationName", "")

        # --- Result ---
        if eid in _SECURITY_FAILURE_IDS:
            result_val = "Failure"
        elif eid == "4776":
            status = data.get("Status", "0x0")
            result_val = "Failure" if status != "0x0" else "Success"
        else:
            result_val = "Success"

        # --- Flags ---
        flag = ""
        if eid == "4625":
            failed_streak += 1
            if failed_streak >= 5:
                flag = "HIGH RISK"
            elif failed_streak >= 3:
                flag = "SUSPICIOUS"
            else:
                flag = "WARNING"
        else:
            if eid == "4624":
                failed_streak = 0
            if eid == "1102":
                flag = "HIGH RISK"
            elif eid == "4740":
                flag = "SUSPICIOUS"
            elif eid in ("4624",) and logon_type_raw == "10":
                flag = "WARNING"
            elif eid in ("4648", "4720", "4726"):
                flag = "WARNING"

        result.rows.append(ArtifactRow(
            fields={
                "Event Time":  _dfir_time(sysd.get("TimeCreated", "")),
                "Event ID":    _dfir(eid),
                "Event Type":  event_type,
                "User":        _dfir(user),
                "Logon Type":  _dfir(logon_type),
                "Source IP":   _dfir(ip),
                "Result":      result_val,
            },
            flag=flag,
        ))

    # Sort: most-recent first
    result.rows.sort(
        key=lambda r: r.fields.get("Event Time", ""), reverse=True)

    count = len(result.rows)
    trunc_note = f"  Truncated at {count} events." if truncated else ""
    result.summary = (
        f"{count} authentication/account event(s) extracted.{trunc_note}")

    return _dfir_finalize(result)


# ===================================================================
# ARTIFACT 3 — Application Event Log
# ===================================================================

def parse_application_log(file_path: str) -> ArtifactResult:
    """Parse Application.evtx for crashes, hangs, and installer events.

    Required output columns (fixed order):
        Event Time | Event ID | Event Type | Source | Severity | Application | Details
    """
    name = "Application Logs"
    if not _EVTX_AVAILABLE:
        return _evtx_unavailable_result(name)

    columns = ["Event Time", "Event ID", "Event Type",
               "Source", "Severity", "Application", "Details"]
    result = ArtifactResult(artifact_name=name, columns=columns)

    try:
        records, truncated = _iter_evtx_filtered(
            file_path, set(_APPLICATION_EVENT_TYPES.keys()))
    except Exception as exc:  # noqa: BLE001
        result.error = f"{exc.__class__.__name__}: {exc}"
        return result

    for sysd, data in records:
        eid = sysd.get("EventID", "")
        event_type = _APPLICATION_EVENT_TYPES.get(eid, DFIR_MISSING)
        provider = sysd.get("Provider", "")

        # --- Severity ---
        level_code = sysd.get("Level", "4")
        severity = _LEVEL_LABELS.get(level_code, "Information")

        # --- Application name (best-effort) ---
        app_name = ""
        if eid in ("1000", "1002"):
            # Application Error / Hang: first Data element is the app name
            app_name = (data.get("param1", "")
                        or data.get("Data", "")
                        or "")
        elif eid == "1026":
            # .NET Runtime: often has the process name in Data
            app_name = data.get("param1", "")
        elif eid in ("1033", "1034", "1035", "11707", "11708", "11724"):
            # MsiInstaller events: product name is typically param1
            app_name = data.get("param1", "")
        if not app_name:
            # Fallback: check all data values for something filename-like
            for v in data.values():
                if v and (".exe" in v.lower() or ".msi" in v.lower()):
                    app_name = v[:120]
                    break

        # --- Details ---
        details_parts: List[str] = []
        if eid == "1000":
            ver = data.get("param2", "")
            module = data.get("param3", "")
            if ver:
                details_parts.append(f"Version: {ver}")
            if module:
                details_parts.append(f"Faulting module: {module}")
        elif eid == "1001":
            bucket = data.get("param1", data.get("Data", ""))
            if bucket:
                details_parts.append(f"Bucket: {bucket[:150]}")
        elif eid == "1002":
            details_parts.append("Application stopped responding")
        elif eid == "1026":
            exc_text = data.get("Data", data.get("param1", ""))
            if exc_text:
                details_parts.append(exc_text[:200])
        elif eid in ("11708",):
            details_parts.append("Installation failed")
            err = data.get("param2", "")
            if err:
                details_parts.append(f"Error: {err}")
        else:
            generic = " ".join(v for v in data.values() if v)[:200]
            if generic:
                details_parts.append(generic)

        details = "; ".join(details_parts) if details_parts else DFIR_MISSING

        # --- Flags ---
        flag = ""
        if eid in ("1000", "1002"):
            flag = "WARNING"
        elif eid == "11708":
            flag = "WARNING"
        elif severity == "Critical":
            flag = "HIGH RISK"

        result.rows.append(ArtifactRow(
            fields={
                "Event Time":   _dfir_time(sysd.get("TimeCreated", "")),
                "Event ID":     _dfir(eid),
                "Event Type":   event_type,
                "Source":       _dfir(provider),
                "Severity":    severity,
                "Application": _dfir(app_name),
                "Details":     details,
            },
            flag=flag,
        ))

    # Sort: most-recent first
    result.rows.sort(
        key=lambda r: r.fields.get("Event Time", ""), reverse=True)

    count = len(result.rows)
    trunc_note = f"  Truncated at {count} events." if truncated else ""
    result.summary = (
        f"{count} application event(s) extracted.{trunc_note}")

    return _dfir_finalize(result)





# ===========================================================================
# THE FULL ARTIFACT REGISTRY  (sidebar source of truth)
# ===========================================================================

ALL_ARTIFACTS: List[ArtifactDefinition] = [
    # 1 - System Timeline
    ArtifactDefinition(
        name="Last Shutdown Time", category="1. System Timeline",
        required_hive=HiveType.SYSTEM,
        key_path=r"CurrentControlSet\Control\Windows",
        forensic_value="Determines when the system was last powered off.",
        forensic_question="When was the system last shut down?",
        extractor=extract_last_shutdown_time),
    ArtifactDefinition(
        name="Boot Configuration", category="1. System Timeline",
        required_hive=HiveType.SYSTEM, key_path="Select",
        forensic_value="Identifies failed or successful boots.",
        forensic_question="Were abnormal reboots observed?",
        extractor=extract_boot_configuration),
    ArtifactDefinition(
        name="Current Hardware Profile", category="1. System Timeline",
        required_hive=HiveType.SYSTEM,
        key_path=r"CurrentControlSet\Control\IDConfigDB\Hardware Profiles",
        forensic_value="Shows active hardware state.",
        forensic_question="Was the system mobile or stationary?",
        extractor=extract_hardware_profile),
    ArtifactDefinition(
        name="Timezone Settings", category="1. System Timeline",
        required_hive=HiveType.SYSTEM,
        key_path=r"CurrentControlSet\Control\TimeZoneInformation",
        forensic_value="Corrects timestamp interpretation.",
        forensic_question="What is the correct timezone for timestamps?",
        extractor=extract_timezone_settings),

    # 2 - User Activity
    ArtifactDefinition(
        name="Recently Opened Files (RecentDocs)", category="2. User Activity",
        required_hive=HiveType.NTUSER,
        key_path=r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        forensic_value="User document activity.",
        forensic_question="What files did the user access?",
        extractor=extract_recent_docs),
    ArtifactDefinition(
        name="Program Execution (UserAssist)", category="2. User Activity",
        required_hive=HiveType.NTUSER,
        key_path=r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
        forensic_value="Records the count and time of applications launched by a user.",
        forensic_question="What programs were executed?",
        extractor=extract_userassist),
    ArtifactDefinition(
        name="Run Dialog Commands (RunMRU)", category="2. User Activity",
        required_hive=HiveType.NTUSER,
        key_path=r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        forensic_value="Commands manually executed.",
        forensic_question="Which commands were executed manually?",
        extractor=extract_run_mru),
    ArtifactDefinition(
        name="Search History (WordWheelQuery)", category="2. User Activity",
        required_hive=HiveType.NTUSER,
        key_path=r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery",
        forensic_value="Tracks user intent.",
        forensic_question="What did the user search for?",
        extractor=extract_word_wheel_query),
    ArtifactDefinition(
        name="Open/Save Dialog History (ComDlg32)", category="2. User Activity",
        required_hive=HiveType.NTUSER,
        key_path=r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32",
        forensic_value="File interaction tracking.",
        forensic_question="Which files were opened/saved via dialogs?",
        extractor=extract_open_save_dialog),
    ArtifactDefinition(
        name="Typed URLs (TypedURLs)", category="2. User Activity",
        required_hive=HiveType.NTUSER,
        key_path=r"Software\Microsoft\Internet Explorer\TypedURLs",
        forensic_value="URLs explicitly typed into browser address bar.",
        forensic_question="What URLs did the user deliberately navigate to?",
        extractor=extract_typed_urls),

    # 3 - USB & Devices
    ArtifactDefinition(
        name="USB Device Identifiers (USBSTOR)", category="3. USB & Devices",
        required_hive=HiveType.SYSTEM, key_path=r"CurrentControlSet\Enum\USBSTOR",
        forensic_value="VID, PID, serial numbers.", forensic_question="What USB devices were connected?",
        extractor=extract_usbstor),
    ArtifactDefinition(
        name="USB Connection Timestamps", category="3. USB & Devices",
        required_hive=HiveType.SYSTEM, key_path=r"CurrentControlSet\Enum\USB",
        forensic_value="Device connection history.", forensic_question="When were USB devices connected?",
        extractor=extract_usb_timestamps),
    ArtifactDefinition(
        name="Mounted Volumes", category="3. USB & Devices",
        required_hive=HiveType.SYSTEM, key_path="MountedDevices",
        forensic_value="Disk attachment info.", forensic_question="Which drives were mounted?",
        extractor=extract_mounted_devices),
    ArtifactDefinition(
        name="User-Level USB Usage (MountPoints2)", category="3. USB & Devices",
        required_hive=HiveType.NTUSER,
        key_path=r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2",
        forensic_value="Tracks user interaction with devices.",
        forensic_question="Which user accessed USB devices?",
        extractor=extract_user_usb_usage),

    # 4 - Program Execution
    ArtifactDefinition(
        name="Startup Programs (System-Wide)", category="4. Program Execution",
        required_hive=HiveType.SOFTWARE,
        key_path=r"Microsoft\Windows\CurrentVersion\Run",
        forensic_value="System-wide persistence.", forensic_question="What programs executed on startup?",
        extractor=extract_startup_programs_system),
    ArtifactDefinition(
        name="User Startup Programs", category="4. Program Execution",
        required_hive=HiveType.NTUSER,
        key_path=r"Software\Microsoft\Windows\CurrentVersion\Run",
        forensic_value="User-level persistence.", forensic_question="Was malware persistence configured at user level?",
        extractor=extract_startup_programs_user),
    ArtifactDefinition(
        name="Executed Programs (Shimcache)", category="4. Program Execution",
        required_hive=HiveType.SYSTEM,
        key_path=r"CurrentControlSet\Control\Session Manager\AppCompatCache",
        forensic_value="Execution traces.", forensic_question="Were programs executed successfully?",
        extractor=extract_shimcache),
    ArtifactDefinition(
        name="File Association Commands", category="4. Program Execution",
        required_hive=HiveType.SOFTWARE, key_path=r"Classes\*\shell\open\command",
        forensic_value="Execution hijacking.", forensic_question="Were file associations hijacked?",
        extractor=extract_file_associations),
    ArtifactDefinition(
        name="COM Objects (CLSID)", category="4. Program Execution",
        required_hive=HiveType.SOFTWARE, key_path=r"Classes\CLSID",
        forensic_value="Malware persistence.", forensic_question="Were COM objects used for persistence?",
        extractor=extract_com_objects),

    # 5 - Software Installation
    ArtifactDefinition(
        name="Installed Programs (Uninstall)", category="5. Software Install",
        required_hive=HiveType.SOFTWARE,
        key_path=r"Microsoft\Windows\CurrentVersion\Uninstall",
        forensic_value="Software inventory.", forensic_question="Was unauthorized software installed?",
        extractor=extract_installed_programs),
    ArtifactDefinition(
        name="Operating System Identification", category="5. Software Install",
        required_hive=HiveType.SOFTWARE,
        key_path=r"Microsoft\Windows NT\CurrentVersion",
        forensic_value="OS version, build, install date, and registered owner.",
        forensic_question="What Windows version was installed and when?",
        extractor=extract_os_identification),
    ArtifactDefinition(
        name="Registered Applications", category="5. Software Install",
        required_hive=HiveType.SOFTWARE, key_path="RegisteredApplications",
        forensic_value="Application legitimacy.", forensic_question="Were all applications legitimate?",
        extractor=extract_registered_apps),

    # 6 - User Accounts
    ArtifactDefinition(
        name="User Accounts & Account Status", category="6. User Accounts",
        required_hive=HiveType.SAM, key_path=r"SAM\Domains\Account\Users",
        forensic_value="Local users.", forensic_question="What user accounts exist?",
        extractor=extract_user_accounts),
    ArtifactDefinition(
        name="Password Policies & LSA Secrets", category="6. User Accounts",
        required_hive=HiveType.SECURITY, key_path=r"Policy\PolSecrets",
        forensic_value="Cached credentials & security strength.",
        forensic_question="Were security policies weakened?",
        extractor=extract_password_policy),

    # 7 - Network Activity
    ArtifactDefinition(
        name="Network Interfaces & Adapters", category="7. Network Activity",
        required_hive=HiveType.SYSTEM,
        key_path=r"CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
        forensic_value="IP addresses, DHCP/static config.",
        forensic_question="Which network adapters were present and active?",
        extractor=extract_network_interfaces),
    ArtifactDefinition(
        name="Network Adapter GUIDs", category="7. Network Activity",
        required_hive=HiveType.SYSTEM, key_path=r"CurrentControlSet\Control\Network",
        forensic_value="Maps adapters to connections.",
        forensic_question="Which adapter was used at a given time?",
        extractor=extract_network_adapter_guids),
    ArtifactDefinition(
        name="Network Profile", category="7. Network Activity",
        required_hive=HiveType.SOFTWARE,
        key_path=r"Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles",
        forensic_value="SSID, first/last connected.",
        forensic_question="Which networks were connected?",
        extractor=extract_network_profiles),
    ArtifactDefinition(
        name="Network Signature", category="7. Network Activity",
        required_hive=HiveType.SOFTWARE, key_path=r"Microsoft\WlanSvc\Interfaces",
        forensic_value="Saved Wi-Fi SSIDs.", forensic_question="Which Wi-Fi networks were used?",
        extractor=extract_wireless_profiles),
    ArtifactDefinition(
        name="VPN Profiles", category="7. Network Activity",
        required_hive=HiveType.NTUSER,
        key_path=r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections",
        forensic_value="VPN usage.", forensic_question="Were VPNs used to hide activity?",
        extractor=extract_vpn_profiles),
    ArtifactDefinition(
        name="Mapped Network Drives", category="7. Network Activity",
        required_hive=HiveType.NTUSER, key_path="Network",
        forensic_value="Access to remote systems.",
        forensic_question="Did the user access remote systems?",
        extractor=extract_mapped_drives),
    ArtifactDefinition(
        name="Firewall Status", category="7. Network Activity",
        required_hive=HiveType.SYSTEM,
        key_path=r"CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy",
        forensic_value="Profile-level firewall on/off and default actions.",
        forensic_question="Was the host firewall enabled per profile?",
        extractor=extract_firewall_status),
    ArtifactDefinition(
        name="Firewall Rules", category="7. Network Activity",
        required_hive=HiveType.SYSTEM,
        key_path=r"ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
        forensic_value="Allow / block rules and the applications they target.",
        forensic_question="What inbound or outbound rules are present?",
        extractor=extract_firewall_rules),
    ArtifactDefinition(
        name="Open Ports", category="7. Network Activity",
        required_hive=HiveType.SYSTEM,
        key_path=r"CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
        forensic_value="Listening services and exposed network ports.",
        forensic_question="Which ports are exposed to the network?",
        extractor=extract_firewall_open_ports),
]


# Category 9 (event log) artifacts are kept separate because they take a
# file path rather than a LoadedHive. The GUI maps them by display name.
EVTX_ARTIFACTS = [
    ("System Logs (Startup/Shutdown)", "8. Windows Logs",
     "System.evtx", parse_system_log,
     "System uptime, abnormal shutdowns.",
     "When did the system start/shutdown? Were there abnormal shutdowns?"),
    ("Security Logs (Logon/Authentication)", "8. Windows Logs",
     "Security.evtx", parse_security_log,
     "Login attempts, privilege escalations.",
     "Who logged in? Were there failed logins or privilege abuses?"),
    ("Application Logs", "8. Windows Logs",
     "Application.evtx", parse_application_log,
     "Application failures & suspicious installs.",
     "Which applications crashed or were installed?"),

]


def list_artifacts_by_category() -> Dict[str, List[ArtifactDefinition]]:
    out: Dict[str, List[ArtifactDefinition]] = {}
    for art in ALL_ARTIFACTS:
        out.setdefault(art.category, []).append(art)
    # Add the event-log "virtual" artifacts at the end
    evtx_defs = []
    for nm, cat, fn, fn_callable, fv, fq in EVTX_ARTIFACTS:
        evtx_defs.append(ArtifactDefinition(
            name=nm, category=cat,
            required_hive=HiveType.UNKNOWN,
            key_path=fn,
            forensic_value=fv,
            forensic_question=fq,
            extractor=lambda h, _f=fn_callable: ArtifactResult(
                artifact_name=nm, columns=[], error=(
                    "Event log artifact - import the corresponding .evtx file"
                    " using 'Import Hive' (the tool detects .evtx and routes"
                    " them to this category).")),
        ))
    out.setdefault("8. Windows Logs", []).extend(evtx_defs)
    return out
