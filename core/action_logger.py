"""
Action Logger Module
====================
Records every examiner action (clicks, selections, viewed entries,
hash checks, exports) with high-resolution local timestamps. The log is
the audit trail required for the final forensic report.

Thread-safe via a single lock; safe to call from any GUI callback.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Hardcoded UTC+3 timezone per v1.5.0 spec
TZ_UTC3 = timezone(timedelta(hours=3))


@dataclass
class LogEntry:
    sequence: int
    timestamp_local: str
    action: str          # short canonical action code, e.g. "ARTIFACT_SELECTED"
    description: str     # human-readable explanation for the report
    examiner: str
    case_name: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class ActionLogger:
    """Append-only event recorder."""

    def __init__(self, case_name: str = "", examiner: str = "",
                 persistent_path: Optional[str | Path] = None):
        self._entries: List[LogEntry] = []
        self._counter = 0
        self._lock = threading.Lock()
        self._case_name = case_name
        self._examiner = examiner
        self._persistent_path = Path(persistent_path) if persistent_path else None
        self._listeners: List[Any] = []  # callables: fn(entry: LogEntry) -> None

    # ----- configuration -------------------------------------------------
    def set_case_metadata(self, case_name: str, examiner: str) -> None:
        with self._lock:
            self._case_name = case_name
            self._examiner = examiner

    def set_persistent_path(self, path: str | Path) -> None:
        with self._lock:
            self._persistent_path = Path(path)

    def add_listener(self, callback) -> None:
        """Register a UI callback called whenever a new entry is logged."""
        self._listeners.append(callback)

    # ----- main API ------------------------------------------------------
    def log(self, action: str, description: str, **metadata: Any) -> LogEntry:
        with self._lock:
            self._counter += 1
            entry = LogEntry(
                sequence=self._counter,
                timestamp_local=datetime.now(TZ_UTC3).strftime(
                    "%Y-%m-%d %H:%M:%S UTC+3"
                ),
                action=action,
                description=description,
                examiner=self._examiner,
                case_name=self._case_name,
                metadata=metadata or {},
            )
            self._entries.append(entry)
            self._persist(entry)

        # Notify listeners outside the lock to avoid deadlocks if the
        # listener calls back into the logger.
        for cb in list(self._listeners):
            try:
                cb(entry)
            except Exception:  # noqa: BLE001 - listeners must not break logging
                pass
        return entry

    def _persist(self, entry: LogEntry) -> None:
        if not self._persistent_path:
            return
        try:
            self._persistent_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._persistent_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")
        except OSError:
            # Persistence failures must NOT crash the logger; the in-memory
            # log is still the authoritative copy for the session.
            pass

    # ----- query / export -----------------------------------------------
    def all_entries(self) -> List[LogEntry]:
        with self._lock:
            return list(self._entries)

    def to_dict_list(self) -> List[Dict[str, Any]]:
        return [asdict(e) for e in self.all_entries()]

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._counter = 0

    # ----- convenience action shortcuts ---------------------------------
    def log_application_start(self) -> None:
        self.log("APPLICATION_START", "Windows Registry Examination session started.")

    def log_case_opened(self, case_name: str, examiner: str) -> None:
        self.log("CASE_OPENED",
                 f"Case '{case_name}' opened by examiner '{examiner}'.",
                 case_name=case_name, examiner=examiner)

    def log_reference_hash_entered(self, hash_value: str) -> None:
        self.log("REFERENCE_HASH_ENTERED",
                 f"Examiner provided reference SHA-256 hash: {hash_value}",
                 reference_hash=hash_value)

    def log_folder_imported(self, folder: str, file_count: int) -> None:
        self.log("FOLDER_IMPORTED",
                 f"Imported evidence folder '{folder}' containing {file_count} file(s).",
                 folder=folder, file_count=file_count)

    def log_pre_check(self, matched: bool, computed: str, reference: str) -> None:
        verdict = "PASSED" if matched else "FAILED"
        self.log("PRE_ANALYSIS_HASH_CHECK",
                 f"Pre-analysis hash verification {verdict}. "
                 f"Reference={reference}, Computed={computed}.",
                 matched=matched, reference=reference, computed=computed)

    def log_post_check(self, matched: bool, computed: str, reference: str) -> None:
        verdict = "PASSED" if matched else "FAILED"
        self.log("POST_ANALYSIS_HASH_CHECK",
                 f"Post-analysis hash revalidation {verdict}. "
                 f"Reference={reference}, Computed={computed}.",
                 matched=matched, reference=reference, computed=computed)

    def log_hive_loaded(self, hive_type: str, file_path: str) -> None:
        self.log("HIVE_LOADED",
                 f"Registry hive '{hive_type}' loaded from {file_path}.",
                 hive_type=hive_type, file_path=file_path)

    def log_artifact_viewed(self, artifact_name: str, category: str,
                            row_count: int, hive: str) -> None:
        self.log("ARTIFACT_VIEWED",
                 f"Examiner viewed artifact '{artifact_name}' "
                 f"(category: {category}) - {row_count} entr(y/ies) extracted "
                 f"from hive {hive}.",
                 artifact_name=artifact_name, category=category,
                 row_count=row_count, hive=hive)

    def log_artifact_error(self, artifact_name: str, error_message: str) -> None:
        self.log("ARTIFACT_ERROR",
                 f"Error processing artifact '{artifact_name}': {error_message}",
                 artifact_name=artifact_name, error=error_message)

    def log_examiner_note(self, artifact_name: str, note: str) -> None:
        self.log("EXAMINER_NOTE",
                 f"Examiner note added to '{artifact_name}': {note}",
                 artifact_name=artifact_name, note=note)

    def log_export(self, fmt: str, path: str) -> None:
        self.log("REPORT_EXPORTED",
                 f"Forensic report exported as {fmt.upper()} to '{path}'.",
                 format=fmt, path=path)

    def log_integrity_failure(self, reference_hash: str,
                              computed_hash: str, folder_path: str,
                              stage: str = "pre-analysis") -> None:
        """Record an integrity check failure to the audit trail.

        Parameters
        ----------
        reference_hash : str
            The SHA-256 hash the examiner provided at intake.
        computed_hash : str
            The SHA-256 hash actually computed from the evidence.
        folder_path : str
            Path to the evidence folder or staging directory.
        stage : str
            When the failure occurred (e.g. "pre-analysis", "post-analysis").
        """
        self.log("INTEGRITY_FAILURE",
                 f"Integrity check FAILED at stage '{stage}'. "
                 f"Reference={reference_hash}, Computed={computed_hash}, "
                 f"Folder={folder_path}.",
                 reference_hash=reference_hash,
                 computed_hash=computed_hash,
                 folder_path=folder_path,
                 stage=stage)

    def log_application_exit(self) -> None:
        self.log("APPLICATION_EXIT", "Windows Registry Examination session ended.")
