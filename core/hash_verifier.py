"""
Hash Verifier Module
====================
Computes and verifies SHA-256 hashes of registry hive files and folders
to ensure forensic integrity throughout the examination process.

Forensic integrity workflow:
    1. Examiner provides original reference hash (taken at acquisition time)
    2. Tool computes hash of imported folder/files
    3. Pre-analysis verification: imported = reference  -> proceed
    4. Post-analysis revalidation: imported still = reference -> generate report
    5. Any mismatch halts the workflow and is logged.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional


# Block size for streaming hash computation (64 KiB)
_BLOCK_SIZE = 65536

# Hardcoded UTC+3 timezone per v1.5.0 spec
TZ_UTC3 = timezone(timedelta(hours=3))


@dataclass
class FileHashRecord:
    """Hash record for an individual file in the evidence folder."""
    file_name: str
    relative_path: str
    absolute_path: str
    size_bytes: int
    sha256: str
    computed_at_utc: str


@dataclass
class FolderHashResult:
    """Aggregate hash result for an evidence folder.

    The composite_sha256 is a deterministic hash computed over the sorted
    per-file hashes plus their relative paths. This means renaming or
    reordering files produces a different composite hash, but examining
    them in a different order on a different machine will produce the
    same composite hash.
    """
    folder_path: str
    file_records: List[FileHashRecord] = field(default_factory=list)
    composite_sha256: str = ""
    total_files: int = 0
    total_bytes: int = 0
    computed_at_utc: str = ""

    def to_dict(self) -> dict:
        return {
            "folder_path": self.folder_path,
            "composite_sha256": self.composite_sha256,
            "total_files": self.total_files,
            "total_bytes": self.total_bytes,
            "computed_at_utc": self.computed_at_utc,
            "files": [vars(r) for r in self.file_records],
        }


def compute_file_sha256(file_path: str | Path) -> str:
    """Compute the SHA-256 hash of a single file by streaming.

    Uses 64 KiB blocks so we never load entire hive files into memory
    (some hives can be hundreds of MB).
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    sha256 = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(_BLOCK_SIZE)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


def compute_folder_sha256(folder_path: str | Path) -> FolderHashResult:
    """Compute a deterministic composite SHA-256 hash for every file in a folder.

    Walks the folder recursively, hashes each file, sorts results by
    relative path, then hashes the concatenation of `<relpath>:<filehash>`
    lines to produce a single composite hash representing the folder's
    full state.
    """
    root = Path(folder_path).resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Folder not found: {folder_path}")

    result = FolderHashResult(folder_path=str(root))
    result.computed_at_utc = datetime.now(TZ_UTC3).strftime("%Y-%m-%d %H:%M:%S UTC+3")

    file_paths: List[Path] = []
    for dir_path, _dirs, files in os.walk(root):
        for fname in files:
            file_paths.append(Path(dir_path) / fname)

    file_paths.sort(key=lambda p: str(p.relative_to(root)).lower())

    composite = hashlib.sha256()
    for fp in file_paths:
        rel = str(fp.relative_to(root)).replace("\\", "/")
        try:
            digest = compute_file_sha256(fp)
            size = fp.stat().st_size
        except (OSError, PermissionError) as exc:
            digest = f"ERROR:{exc.__class__.__name__}"
            size = -1

        record = FileHashRecord(
            file_name=fp.name,
            relative_path=rel,
            absolute_path=str(fp),
            size_bytes=size,
            sha256=digest,
            computed_at_utc=result.computed_at_utc,
        )
        result.file_records.append(record)
        composite.update(f"{rel}:{digest}\n".encode("utf-8"))
        result.total_files += 1
        if size > 0:
            result.total_bytes += size

    result.composite_sha256 = composite.hexdigest()
    return result


def verify_hash(reference_hash: str, computed_hash: str) -> bool:
    """Constant-time-ish comparison of two hex SHA-256 strings.

    Normalizes whitespace and case before comparison.
    """
    if not reference_hash or not computed_hash:
        return False
    a = reference_hash.strip().lower().replace(" ", "").replace(":", "")
    b = computed_hash.strip().lower().replace(" ", "").replace(":", "")
    if len(a) != 64 or len(b) != 64:
        return False
    # hashlib.compare_digest equivalent
    diff = 0
    for x, y in zip(a, b):
        diff |= ord(x) ^ ord(y)
    return diff == 0


def is_valid_sha256(value: str) -> bool:
    """Return True if `value` is a syntactically valid SHA-256 hex digest."""
    if not value:
        return False
    cleaned = value.strip().lower().replace(" ", "").replace(":", "")
    if len(cleaned) != 64:
        return False
    try:
        int(cleaned, 16)
        return True
    except ValueError:
        return False


@dataclass
class IntegrityCheckResult:
    """Outcome of a pre- or post-analysis integrity check."""
    stage: str  # "pre-analysis" or "post-analysis"
    reference_hash: str
    computed_hash: str
    matched: bool
    timestamp_utc: str
    folder_result: Optional[FolderHashResult] = None

    @property
    def status_text(self) -> str:
        return "VERIFIED - INTEGRITY INTACT" if self.matched else "FAILED - POSSIBLE TAMPERING DETECTED"

    def to_dict(self) -> dict:
        return {
            "stage": self.stage,
            "reference_hash": self.reference_hash,
            "computed_hash": self.computed_hash,
            "matched": self.matched,
            "status": self.status_text,
            "timestamp_utc": self.timestamp_utc,
            "folder_result": self.folder_result.to_dict() if self.folder_result else None,
        }


@dataclass
class FileIntegrityRecord:
    """Per-file integrity state tracked during the upload workflow."""
    file_name: str
    file_path: str
    reference_hash: str
    computed_hash: str
    matched: bool
    verified_at_utc: str

    def to_dict(self) -> dict:
        return {
            "file_name": self.file_name,
            "file_path": self.file_path,
            "reference_hash": self.reference_hash,
            "computed_hash": self.computed_hash,
            "matched": self.matched,
            "verified_at_utc": self.verified_at_utc,
        }


def perform_integrity_check(
    folder_path: str | Path,
    reference_hash: str,
    stage: str = "pre-analysis",
) -> IntegrityCheckResult:
    """Compute the folder hash and compare against the reference hash."""
    folder_result = compute_folder_sha256(folder_path)
    matched = verify_hash(reference_hash, folder_result.composite_sha256)
    return IntegrityCheckResult(
        stage=stage,
        reference_hash=reference_hash.strip().lower(),
        computed_hash=folder_result.composite_sha256,
        matched=matched,
        timestamp_utc=datetime.now(TZ_UTC3).strftime("%Y-%m-%d %H:%M:%S UTC+3"),
        folder_result=folder_result,
    )


def perform_single_file_check(
    file_path: str | Path,
    reference_hash: str,
) -> FileIntegrityRecord:
    """Compute SHA-256 of a single file and compare against reference_hash.

    This is the per-file equivalent of sha256sum <file>.  The computed
    hash is stored internally but is intentionally NOT shown to the user
    on mismatch — the GUI displays only 'Wrong hash value'.
    """
    computed = compute_file_sha256(file_path)
    matched = verify_hash(reference_hash, computed)
    p = Path(file_path)
    return FileIntegrityRecord(
        file_name=p.name,
        file_path=str(p.resolve()),
        reference_hash=reference_hash.strip().lower(),
        computed_hash=computed,
        matched=matched,
        verified_at_utc=datetime.now(TZ_UTC3).strftime(
            "%Y-%m-%d %H:%M:%S UTC+3"),
    )


def perform_multi_file_recheck(
    records: List["FileIntegrityRecord"],
    stage: str = "post-analysis",
) -> IntegrityCheckResult:
    """Re-verify every file recorded during the upload phase.

    Computes a fresh SHA-256 for each file and a composite hash over all
    of them (sorted by filename) so the result fits into the existing
    IntegrityCheckResult pipeline used by reports.
    """
    ts = datetime.now(TZ_UTC3).strftime("%Y-%m-%d %H:%M:%S UTC+3")
    composite = hashlib.sha256()
    file_hash_records: List[FileHashRecord] = []
    all_matched = True
    total_bytes = 0

    for rec in sorted(records, key=lambda r: r.file_name.lower()):
        p = Path(rec.file_path)
        if not p.is_file():
            all_matched = False
            continue
        computed = compute_file_sha256(p)
        size = p.stat().st_size
        total_bytes += size
        if not verify_hash(rec.reference_hash, computed):
            all_matched = False
        file_hash_records.append(FileHashRecord(
            file_name=rec.file_name,
            relative_path=rec.file_name,
            absolute_path=str(p),
            size_bytes=size,
            sha256=computed,
            computed_at_utc=ts,
        ))
        composite.update(f"{rec.file_name}:{computed}\n".encode("utf-8"))

    composite_hex = composite.hexdigest()
    # Build a reference composite from the original reference hashes
    ref_composite = hashlib.sha256()
    for rec in sorted(records, key=lambda r: r.file_name.lower()):
        ref_composite.update(
            f"{rec.file_name}:{rec.reference_hash}\n".encode("utf-8"))
    ref_hex = ref_composite.hexdigest()

    folder_result = FolderHashResult(
        folder_path="(individual files)",
        file_records=file_hash_records,
        composite_sha256=composite_hex,
        total_files=len(file_hash_records),
        total_bytes=total_bytes,
        computed_at_utc=ts,
    )
    return IntegrityCheckResult(
        stage=stage,
        reference_hash=ref_hex,
        computed_hash=composite_hex,
        matched=all_matched,
        timestamp_utc=ts,
        folder_result=folder_result,
    )
