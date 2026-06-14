"""
Decoder Module
==============
Decodes the various encoded formats encountered in Windows Registry values:

  * FILETIME (Windows 64-bit, 100-nanosecond intervals since 1601-01-01 UTC)
  * Unix epoch (32- or 64-bit seconds since 1970-01-01 UTC)
  * SYSTEMTIME (16-byte Windows structure, big-endian fields)
  * ROT-13 (used by UserAssist value names)
  * Base64 (auto-detected from value content)
  * Hexadecimal strings (with or without separators)
  * UTF-16 LE little-endian strings (the dominant format in the registry)
  * UTF-8 / ASCII fallback strings
  * REG_MULTI_SZ (\\0-separated list of strings)

Every decoder returns a tuple of (decoded_text, encoding_label) so the
GUI can both display the human-readable form and tell the examiner what
encoding the raw data used. This keeps the audit trail honest.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Timestamp decoders
# ---------------------------------------------------------------------------

# FILETIME epoch is 1601-01-01 UTC; Unix epoch is 1970-01-01 UTC.
# Difference in 100-ns intervals: 116444736000000000
_FILETIME_EPOCH_DIFFERENCE = 116444736000000000


def decode_filetime(raw: bytes | int) -> Optional[str]:
    """Decode an 8-byte FILETIME or already-unpacked integer to UTC string."""
    try:
        if isinstance(raw, (bytes, bytearray)):
            if len(raw) < 8:
                return None
            value = struct.unpack("<Q", bytes(raw[:8]))[0]
        else:
            value = int(raw)
        if value == 0:
            return "Never (zero FILETIME)"
        unix_seconds = (value - _FILETIME_EPOCH_DIFFERENCE) / 10_000_000.0
        if unix_seconds < 0 or unix_seconds > 32503680000:  # year 3000 upper bound
            return None
        dt = datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (struct.error, OverflowError, ValueError):
        return None


def decode_unix_epoch(value: int | bytes) -> Optional[str]:
    """Decode a Unix epoch integer (32-bit seconds) to UTC datetime string."""
    try:
        if isinstance(value, (bytes, bytearray)):
            if len(value) >= 4:
                value = struct.unpack("<I", bytes(value[:4]))[0]
            else:
                return None
        seconds = int(value)
        if seconds <= 0 or seconds > 4102444800:  # year 2100 upper bound
            return None
        return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, struct.error):
        return None


def decode_systemtime(raw: bytes) -> Optional[str]:
    """Decode a 16-byte SYSTEMTIME structure into a UTC datetime string.

    SYSTEMTIME layout (little-endian WORDs): year, month, day-of-week, day,
    hour, minute, second, milliseconds.
    """
    if not raw or len(raw) < 16:
        return None
    try:
        year, month, _dow, day, hour, minute, second, _ms = struct.unpack(
            "<HHHHHHHH", bytes(raw[:16])
        )
        if not (1601 <= year <= 9999) or not (1 <= month <= 12) or not (1 <= day <= 31):
            return None
        dt = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (struct.error, ValueError):
        return None


def decode_yyyymmdd(value: str | int) -> Optional[str]:
    """Decode an InstallDate-style YYYYMMDD integer/string to a formatted date."""
    s = str(value).strip()
    if len(s) != 8 or not s.isdigit():
        return None
    try:
        dt = datetime.strptime(s, "%Y%m%d")
        return dt.strftime("%Y-%m-%d")
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Encoding decoders
# ---------------------------------------------------------------------------

def decode_rot13(text: str) -> str:
    """ROT-13 decode (used by UserAssist value names)."""
    if not text:
        return ""
    try:
        return codecs.decode(text, "rot_13")
    except Exception:
        return text


_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def looks_like_base64(value: str) -> bool:
    """Heuristic: long, padded base64-looking string with valid alphabet."""
    if not value or len(value) < 16 or len(value) % 4 != 0:
        return False
    return bool(_BASE64_RE.match(value.strip()))


def try_decode_base64(value: str) -> Optional[str]:
    """Try to decode a string as base64 if it looks plausible."""
    if not looks_like_base64(value):
        return None
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    text = _bytes_to_best_string(decoded)
    if text and _is_mostly_printable(text):
        return text
    return None


_HEX_RE = re.compile(r"^[0-9A-Fa-f\s:]+$")


def looks_like_hex(value: str) -> bool:
    if not value or len(value) < 4:
        return False
    cleaned = re.sub(r"[\s:]", "", value)
    return len(cleaned) % 2 == 0 and bool(_HEX_RE.match(value))


def try_decode_hex(value: str) -> Optional[str]:
    if not looks_like_hex(value):
        return None
    try:
        cleaned = re.sub(r"[\s:]", "", value)
        decoded = bytes.fromhex(cleaned)
    except ValueError:
        return None
    text = _bytes_to_best_string(decoded)
    if text and _is_mostly_printable(text):
        return text
    return None


# ---------------------------------------------------------------------------
# Binary -> string helpers
# ---------------------------------------------------------------------------

def utf16le_to_str(raw: bytes) -> str:
    """Decode UTF-16LE bytes, stripping trailing NULs. The registry stores
    REG_SZ and REG_EXPAND_SZ values in this format."""
    if not raw:
        return ""
    try:
        text = raw.decode("utf-16-le", errors="replace")
        return text.rstrip("\x00")
    except Exception:
        return ""


def utf16le_multi_sz(raw: bytes) -> List[str]:
    """Decode a REG_MULTI_SZ block (UTF-16LE, NUL-separated, double-NUL terminated)."""
    text = utf16le_to_str(raw)
    return [s for s in text.split("\x00") if s]


def _bytes_to_best_string(raw: bytes) -> str:
    """Best-effort conversion of raw bytes to a printable string.

    Tries UTF-16LE first (registry preference), then UTF-8, then Latin-1.
    """
    if not raw:
        return ""
    if len(raw) >= 2 and raw[1] == 0:
        try:
            text = raw.decode("utf-16-le", errors="strict").rstrip("\x00")
            if text:
                return text
        except UnicodeDecodeError:
            pass
    try:
        return raw.decode("utf-8", errors="strict").rstrip("\x00")
    except UnicodeDecodeError:
        pass
    try:
        return raw.decode("latin-1", errors="replace").rstrip("\x00")
    except Exception:
        return ""


def _is_mostly_printable(text: str, threshold: float = 0.85) -> bool:
    """Return True if at least `threshold` fraction of characters are printable."""
    if not text:
        return False
    printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    return printable / len(text) >= threshold


# ---------------------------------------------------------------------------
# Hex dump (for the "Raw Data (Advanced)" collapsible section)
# ---------------------------------------------------------------------------

def hex_dump(raw: bytes, width: int = 16, max_bytes: int = 512) -> str:
    """Return a classic xxd-style hex dump of the bytes, capped at `max_bytes`."""
    if not raw:
        return "(no data)"
    truncated = len(raw) > max_bytes
    chunk = raw[:max_bytes]
    lines: List[str] = []
    for i in range(0, len(chunk), width):
        block = chunk[i : i + width]
        hex_part = " ".join(f"{b:02X}" for b in block).ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in block)
        lines.append(f"{i:08X}  {hex_part}  |{ascii_part}|")
    if truncated:
        lines.append(f"... ({len(raw) - max_bytes} more bytes truncated)")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# REG_DWORD / REG_QWORD interpretations
# ---------------------------------------------------------------------------

def interpret_dword(value: int, hint: str = "") -> str:
    """Render a DWORD with both decimal and hex, plus an optional interpretation."""
    base = f"{value} (0x{value & 0xFFFFFFFF:08X})"
    return f"{base}  -  {hint}" if hint else base


def interpret_boolean_dword(value: int, true_label: str = "Enabled",
                            false_label: str = "Disabled") -> str:
    return f"{value} ({true_label})" if value else f"{value} ({false_label})"


# ---------------------------------------------------------------------------
# Auto-decoder - decides what something is and decodes it
# ---------------------------------------------------------------------------

@dataclass
class DecodedValue:
    raw: Any
    display: str
    encoding: str  # human-readable label such as "UTF-16LE", "FILETIME", "Base64"
    raw_hex: str = ""

    def __str__(self) -> str:
        return self.display


def auto_decode(raw: Any, value_type: Optional[str] = None,
                value_name: str = "") -> DecodedValue:
    """Auto-detect the encoding of a registry value and produce a readable form.

    `value_type` is the registry value type name from python-registry such as
    "RegSZ", "RegBin", "RegDWord", "RegMultiSZ", "RegExpandSZ", "RegQWord".
    """
    vt = (value_type or "").lower()

    if isinstance(raw, str):
        # Already a string. Try ROT-13 if the value name was the encoded part
        # (used in UserAssist), otherwise see if it's a bundled base64/hex blob.
        b64 = try_decode_base64(raw)
        if b64:
            return DecodedValue(raw=raw, display=b64, encoding="Base64 -> text")
        hx = try_decode_hex(raw)
        if hx:
            return DecodedValue(raw=raw, display=hx, encoding="Hex -> text")
        return DecodedValue(raw=raw, display=raw, encoding="Text (UTF-16LE/ASCII)")

    if isinstance(raw, int):
        # FILETIME values can sometimes be exposed as ints; only reinterpret
        # when the value name strongly suggests a FILETIME.
        nm = value_name.lower()
        if any(k in nm for k in ("time", "shutdowntime", "lastwrite", "filetime")):
            ft = decode_filetime(raw)
            if ft:
                return DecodedValue(raw=raw, display=ft, encoding="FILETIME")
        if any(k in nm for k in ("installdate", "leaseobtainedtime", "leaseterminatestime")):
            ux = decode_unix_epoch(raw)
            if ux:
                return DecodedValue(raw=raw, display=ux, encoding="Unix epoch")
        return DecodedValue(raw=raw, display=interpret_dword(raw), encoding="REG_DWORD/QWORD")

    if isinstance(raw, (bytes, bytearray)):
        raw_bytes = bytes(raw)

        if vt in ("regsz", "regexpandsz"):
            text = utf16le_to_str(raw_bytes)
            return DecodedValue(raw=raw_bytes, display=text, encoding="UTF-16LE",
                                raw_hex=hex_dump(raw_bytes))

        if vt == "regmultisz":
            parts = utf16le_multi_sz(raw_bytes)
            return DecodedValue(raw=raw_bytes, display="\n".join(parts) or "(empty)",
                                encoding="REG_MULTI_SZ (UTF-16LE list)",
                                raw_hex=hex_dump(raw_bytes))

        # Heuristic order for binary blobs
        if len(raw_bytes) == 8:
            ft = decode_filetime(raw_bytes)
            if ft:
                return DecodedValue(raw=raw_bytes, display=ft, encoding="FILETIME (8 bytes)",
                                    raw_hex=hex_dump(raw_bytes))

        if len(raw_bytes) == 16:
            st = decode_systemtime(raw_bytes)
            if st:
                return DecodedValue(raw=raw_bytes, display=st, encoding="SYSTEMTIME (16 bytes)",
                                    raw_hex=hex_dump(raw_bytes))

        # Try UTF-16LE (most common in registry binary values that are really strings)
        if len(raw_bytes) >= 2 and raw_bytes[1] == 0:
            text = utf16le_to_str(raw_bytes)
            if text and _is_mostly_printable(text):
                return DecodedValue(raw=raw_bytes, display=text, encoding="UTF-16LE (in REG_BINARY)",
                                    raw_hex=hex_dump(raw_bytes))

        # Try UTF-8
        try:
            text = raw_bytes.decode("utf-8").rstrip("\x00")
            if text and _is_mostly_printable(text):
                return DecodedValue(raw=raw_bytes, display=text, encoding="UTF-8 (in REG_BINARY)",
                                    raw_hex=hex_dump(raw_bytes))
        except UnicodeDecodeError:
            pass

        # Fall through: present hex dump labelled as raw binary
        return DecodedValue(raw=raw_bytes, display=hex_dump(raw_bytes),
                            encoding="REG_BINARY (raw - no known structure)",
                            raw_hex=hex_dump(raw_bytes))

    # Fallback for None / unknown types
    return DecodedValue(raw=raw, display=str(raw), encoding="Unknown")


# ---------------------------------------------------------------------------
# Bias / timezone helpers (Bias is in minutes, signed)
# ---------------------------------------------------------------------------

def format_bias(bias_minutes: int) -> str:
    """Convert a Windows TimeZoneInformation Bias (minutes from UTC) to +/-HH:MM."""
    sign = "-" if bias_minutes > 0 else "+"   # Note: Windows Bias is UTC = local + Bias
    abs_minutes = abs(bias_minutes)
    hours, mins = divmod(abs_minutes, 60)
    return f"{sign}{hours:02d}:{mins:02d}"


# ---------------------------------------------------------------------------
# LogonType lookup (Security.evtx event 4624)
# ---------------------------------------------------------------------------

LOGON_TYPES = {
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive (RDP)",
    11: "CachedInteractive",
}


def logon_type_label(code: int) -> str:
    """Return a human-readable logon-type label.

    Format: ``EnglishLabel (code)`` – label first, numeric clarifier
    in parentheses, matching the court-defensible output spec.
    """
    label = LOGON_TYPES.get(code)
    if label:
        return f"{label} ({code})"
    return f"Unknown ({code})"
