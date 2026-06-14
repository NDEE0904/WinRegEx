"""
Registry Parser Module
======================
Defensive wrapper around the `python-registry` library.

Hive detection strategy (priority order):

  1. CONTENT-BASED PROBES (primary). For each candidate hive type we
     check for keys/structures that exist in *that* hive type and only
     in that hive type. Matching one is a strong positive signal, not
     a guess. The NTUSER vs DEFAULT pair is the most important to
     disambiguate, because both share Software/Environment/Console.

  2. FILENAME FALLBACK (secondary). If content probes are inconclusive
     we trust the filename. Variants are normalised: NTUSER.DAT.LOG1,
     ntuser.dat.bak, NTUSER_user1.DAT all map to NTUSER.

  3. EXPLICIT UNKNOWN. If both layers fail, the hive is left as
     UNKNOWN with a clear error string for the UI - we never guess.

Every load operation produces a ClassificationTrace recorded in the
action log so misclassifications are never silent.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from Registry import Registry  # type: ignore
    _REGISTRY_AVAILABLE = True
    _REGISTRY_IMPORT_ERROR: Optional[Exception] = None
except Exception as exc:  # noqa: BLE001
    Registry = None  # type: ignore
    _REGISTRY_AVAILABLE = False
    _REGISTRY_IMPORT_ERROR = exc


class RegistryUnavailable(RuntimeError):
    """Raised when the python-registry package isn't installed."""


def _ensure_registry() -> None:
    if not _REGISTRY_AVAILABLE:
        raise RegistryUnavailable(
            "The 'python-registry' package is required for hive parsing. "
            "Install with: pip install python-registry\n"
            f"Underlying import error: {_REGISTRY_IMPORT_ERROR}"
        )


# ---------------------------------------------------------------------------
# Hive type enum
# ---------------------------------------------------------------------------

class HiveType(str, Enum):
    SYSTEM = "SYSTEM"
    SOFTWARE = "SOFTWARE"
    SAM = "SAM"
    SECURITY = "SECURITY"
    DEFAULT = "DEFAULT"
    NTUSER = "NTUSER.DAT"
    USRCLASS = "USRCLASS.DAT"
    UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# Content probes
# ---------------------------------------------------------------------------
#
# Hitting any path is a positive signal for that hive type.

_NTUSER_PROBES = [
    "Volatile Environment",
    "SessionInformation",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
]

_USRCLASS_PROBES = [
    r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
    r"Local Settings\Software\Microsoft\Windows\Shell\Bags",
    r"Local Settings\MuiCache",
]

_SYSTEM_PROBES = [
    "Select",
    "ControlSet001",
    "ControlSet002",
    "MountedDevices",
    r"ControlSet001\Control\ComputerName\ComputerName",
]

_SOFTWARE_PROBES = [
    r"Microsoft\Windows NT\CurrentVersion",
    r"Microsoft\Windows\CurrentVersion\Uninstall",
    r"Microsoft\Cryptography",
    r"Microsoft\Windows NT\CurrentVersion\ProfileList",
]

_SAM_PROBES = [
    r"SAM\Domains\Account\Users",
    r"SAM\Domains\Account",
    r"SAM\Domains\Builtin",
]

_SECURITY_PROBES = [
    r"Policy\PolAdtEv",
    r"Policy\Secrets",
    r"Policy\Accounts",
    r"Policy\PolAcDmS",
]

# DEFAULT contains Software/Environment but NEVER NTUSER-only markers.
_DEFAULT_NEGATIVE_MARKERS = ["Volatile Environment", "SessionInformation"]
_DEFAULT_POSITIVE_MARKERS = [
    "AppEvents", "Console", "Control Panel", "Environment", "Software",
]


# ---------------------------------------------------------------------------
# Filename normalisation
# ---------------------------------------------------------------------------

_FILENAME_TRIM_SUFFIXES = (".log1", ".log2", ".log", ".bak", ".old", ".tmp")
_NTUSER_FILENAME_RE = re.compile(r"^ntuser(?:_[^.]*)?\.dat$", re.IGNORECASE)
_USRCLASS_FILENAME_RE = re.compile(r"^usrclass\.dat$", re.IGNORECASE)


def _normalise_filename(name: str) -> str:
    n = name.lower()
    changed = True
    while changed:
        changed = False
        for s in _FILENAME_TRIM_SUFFIXES:
            if n.endswith(s):
                n = n[: -len(s)]
                changed = True
                break
    return n


def _classify_by_filename(file_name: str) -> HiveType:
    base = _normalise_filename(file_name)
    if (_NTUSER_FILENAME_RE.match(file_name)
            or _NTUSER_FILENAME_RE.match(base + ".dat")
            or base.startswith("ntuser")):
        return HiveType.NTUSER
    if _USRCLASS_FILENAME_RE.match(file_name) or base == "usrclass":
        return HiveType.USRCLASS
    if base == "system":
        return HiveType.SYSTEM
    if base == "software":
        return HiveType.SOFTWARE
    if base == "sam":
        return HiveType.SAM
    if base == "security":
        return HiveType.SECURITY
    if base == "default":
        return HiveType.DEFAULT
    return HiveType.UNKNOWN


# ---------------------------------------------------------------------------
# Classification trace + helpers
# ---------------------------------------------------------------------------

@dataclass
class ClassificationTrace:
    method: str               # "content" | "filename" | "unknown"
    matched_signal: str = ""
    notes: str = ""

    def describe(self) -> str:
        if self.method == "content":
            return f"via content probe ({self.matched_signal})"
        if self.method == "filename":
            return f"via filename fallback ({self.matched_signal})"
        return "could not classify"


def _has_path(reg: "Registry.Registry", path: str) -> bool:
    try:
        reg.open(path)
        return True
    except Exception:
        return False


def _root_child_names(reg: "Registry.Registry") -> set:
    try:
        return {sk.name() for sk in reg.root().subkeys()}
    except Exception:
        return set()


def _classify_by_content(reg: "Registry.Registry") -> Tuple[HiveType, str]:
    children = _root_child_names(reg)

    # SAM has a unique top-level child name
    if "SAM" in children:
        for p in _SAM_PROBES:
            if _has_path(reg, p):
                return HiveType.SAM, p
        return HiveType.SAM, "root child 'SAM'"

    # SECURITY: top-level Policy is unique enough when combined with probes
    if "Policy" in children:
        for p in _SECURITY_PROBES:
            if _has_path(reg, p):
                return HiveType.SECURITY, p

    for p in _SYSTEM_PROBES:
        if _has_path(reg, p):
            return HiveType.SYSTEM, p

    for p in _SOFTWARE_PROBES:
        if _has_path(reg, p):
            return HiveType.SOFTWARE, p

    for p in _NTUSER_PROBES:
        if _has_path(reg, p):
            return HiveType.NTUSER, p

    for p in _USRCLASS_PROBES:
        if _has_path(reg, p):
            return HiveType.USRCLASS, p

    # DEFAULT: profile-shaped, but with no NTUSER markers
    has_negative = any(m in children for m in _DEFAULT_NEGATIVE_MARKERS)
    if not has_negative:
        positive = sum(1 for m in _DEFAULT_POSITIVE_MARKERS if m in children)
        if positive >= 3:
            return (HiveType.DEFAULT,
                    f"profile markers ({positive}/{len(_DEFAULT_POSITIVE_MARKERS)})")

    return HiveType.UNKNOWN, ""


def _detect_hive_type(reg: "Registry.Registry", file_name: str
                      ) -> Tuple[HiveType, ClassificationTrace]:
    t, signal = _classify_by_content(reg)
    if t != HiveType.UNKNOWN:
        return t, ClassificationTrace(method="content", matched_signal=signal)

    fn_type = _classify_by_filename(file_name)
    if fn_type != HiveType.UNKNOWN:
        return fn_type, ClassificationTrace(
            method="filename",
            matched_signal=_normalise_filename(file_name),
            notes="content probes inconclusive; trusted filename")

    return HiveType.UNKNOWN, ClassificationTrace(
        method="unknown",
        notes=f"Unable to identify hive type for '{file_name}'")


# ---------------------------------------------------------------------------
# LoadedHive container
# ---------------------------------------------------------------------------

@dataclass
class LoadedHive:
    file_path: str
    file_name: str
    hive_type: HiveType
    registry: Any = None
    root_subkey_count: int = 0
    error: Optional[str] = None
    classification: Optional[ClassificationTrace] = None

    @property
    def loaded_ok(self) -> bool:
        return self.error is None and self.registry is not None


@dataclass
class RegValue:
    name: str
    value_type_name: str
    raw: Any

    @property
    def is_binary(self) -> bool:
        return isinstance(self.raw, (bytes, bytearray))


# ---------------------------------------------------------------------------
# HiveRegistry
# ---------------------------------------------------------------------------

class HiveRegistry:
    """Tracks every hive loaded during the case session."""

    def __init__(self):
        self._hives: Dict[HiveType, LoadedHive] = {}
        self._all_loaded: List[LoadedHive] = []

    def load_hive_file(self, file_path: str | Path) -> LoadedHive:
        path = Path(file_path)
        loaded = LoadedHive(
            file_path=str(path), file_name=path.name,
            hive_type=HiveType.UNKNOWN,
        )

        if not path.is_file():
            loaded.error = f"File not found: {path}"
            self._all_loaded.append(loaded)
            return loaded

        if not _REGISTRY_AVAILABLE:
            loaded.error = ("python-registry not installed. Run "
                            "'pip install python-registry'.")
            self._all_loaded.append(loaded)
            return loaded

        try:
            reg = Registry.Registry(str(path))
        except Exception as exc:  # noqa: BLE001
            loaded.error = f"Failed to open hive: {exc}"
            self._all_loaded.append(loaded)
            return loaded

        try:
            hive_type, trace = _detect_hive_type(reg, path.name)
            child_count = sum(1 for _ in reg.root().subkeys())
        except Exception as exc:  # noqa: BLE001
            loaded.error = f"Failed to read root key: {exc}"
            self._all_loaded.append(loaded)
            return loaded

        if hive_type == HiveType.UNKNOWN:
            loaded.error = (trace.notes or
                            f"Unable to identify hive type for '{path.name}'")
            loaded.classification = trace
            self._all_loaded.append(loaded)
            return loaded

        loaded.registry = reg
        loaded.hive_type = hive_type
        loaded.root_subkey_count = child_count
        loaded.classification = trace
        # Don't overwrite a previous load of the same type
        if hive_type not in self._hives:
            self._hives[hive_type] = loaded
        self._all_loaded.append(loaded)
        return loaded

    def load_folder(self, folder_path: str | Path) -> List[LoadedHive]:
        folder = Path(folder_path)
        if not folder.is_dir():
            raise NotADirectoryError(folder_path)
        results: List[LoadedHive] = []
        for fpath in self._discover_hive_files(folder):
            results.append(self.load_hive_file(fpath))
        return results

    @staticmethod
    def _discover_hive_files(folder: Path) -> List[Path]:
        canonical = {"system", "software", "sam", "security",
                     "default", "ntuser", "usrclass"}
        hits: List[Path] = []
        for dirpath, _dirs, files in os.walk(folder):
            for fn in files:
                fp = Path(dirpath) / fn
                low = fn.lower()
                if low.endswith(".evtx"):
                    continue
                # Skip transactional logs - they aren't full hives
                if low.endswith((".log1", ".log2", ".log")):
                    continue
                norm = _normalise_filename(fn)
                if (norm in canonical
                        or norm.startswith("ntuser")
                        or _has_regf_magic(fp)):
                    hits.append(fp)
        return sorted(hits, key=lambda p: p.name.lower())

    def get(self, hive_type: HiveType) -> Optional[LoadedHive]:
        return self._hives.get(hive_type)

    def has(self, hive_type: HiveType) -> bool:
        h = self._hives.get(hive_type)
        return bool(h and h.loaded_ok)

    def all_loaded(self) -> List[LoadedHive]:
        return list(self._all_loaded)

    def loaded_types(self) -> List[HiveType]:
        return [t for t, h in self._hives.items() if h.loaded_ok]


def _has_regf_magic(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"regf"
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Safe key/value lookup helpers (interface unchanged)
# ---------------------------------------------------------------------------

def open_key(hive: LoadedHive, key_path: str) -> Optional[Any]:
    if not hive or not hive.loaded_ok:
        return None
    try:
        return hive.registry.open(key_path)
    except Exception:
        return None


def list_values(key: Any) -> List[RegValue]:
    out: List[RegValue] = []
    if key is None:
        return out
    try:
        for v in key.values():
            try:
                raw = v.value()
            except Exception:
                raw = b""
            out.append(RegValue(name=v.name(),
                                value_type_name=v.value_type_str(),
                                raw=raw))
    except Exception:
        return out
    return out


def list_subkeys(key: Any) -> List[Any]:
    if key is None:
        return []
    try:
        return list(key.subkeys())
    except Exception:
        return []


def key_last_write_utc(key: Any) -> str:
    if key is None:
        return ""
    try:
        return key.timestamp().strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return ""


def get_value_raw(key: Any, value_name: str) -> Tuple[Any, str]:
    if key is None:
        return None, ""
    try:
        v = key.value(value_name)
        return v.value(), v.value_type_str()
    except Exception:
        return None, ""


# ---------------------------------------------------------------------------
# Active ControlSet resolution
# ---------------------------------------------------------------------------

def active_controlset_path(hive: LoadedHive) -> str:
    """Read Select\\Current (DWORD) and return the active ControlSet
    name, e.g. 'ControlSet001'.  Falls back to 'ControlSet001' if
    Select\\Current is unreadable but records the fallback in the
    hive's ClassificationTrace.notes."""
    fallback = "ControlSet001"
    if not hive or not hive.loaded_ok:
        return fallback
    try:
        select_key = hive.registry.open("Select")
        current_val = select_key.value("Current").value()
        cs_num = int(current_val)
        if cs_num < 1 or cs_num > 999:
            raise ValueError(f"Select\\Current out of range: {cs_num}")
        return f"ControlSet{cs_num:03d}"
    except Exception:  # noqa: BLE001
        # Record that we fell back so the classification trace is honest
        if hive.classification and hasattr(hive.classification, "notes"):
            existing = hive.classification.notes or ""
            fb_msg = ("Select\\Current unreadable; fell back to "
                      "ControlSet001 for all SYSTEM-hive lookups.")
            if fb_msg not in existing:
                hive.classification.notes = (
                    (existing + " " + fb_msg).strip())
        return fallback
