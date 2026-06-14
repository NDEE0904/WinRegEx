"""
Tests for Active ControlSet Resolution (Change 1)
===================================================
Validates that:
  1. active_controlset_path() reads Select\\Current correctly.
  2. When Select\\Current = 2, extractors read from ControlSet002.
  3. When Select\\Current is missing, falls back to ControlSet001
     and records a note in the ClassificationTrace.
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

# Ensure the project root is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.registry_parser import (
    ClassificationTrace,
    HiveType,
    LoadedHive,
    active_controlset_path,
)


class _MockValue:
    """Emulates a python-registry value object."""

    def __init__(self, name: str = "", raw_value=None, vtype: str = "RegBin"):
        self._name = name
        self._raw = raw_value
        self._vtype = vtype

    def name(self):
        return self._name

    def value(self):
        return self._raw

    def value_type_str(self):
        return self._vtype


class _MockKey:
    """Emulates a python-registry key object with named values."""

    def __init__(self, values_dict: dict):
        self._values = {
            name: _MockValue(name=name, raw_value=val)
            for name, val in values_dict.items()
        }
        import datetime
        self._ts = datetime.datetime(2024, 6, 15, 12, 0, 0)

    def value(self, name: str):
        if name in self._values:
            return self._values[name]
        raise Exception(f"Value '{name}' not found")

    def values(self):
        return list(self._values.values())

    def timestamp(self):
        return self._ts

    def subkeys(self):
        return []

    def name(self):
        return "(root)"


class _MockRegistry:
    """Minimal mock of Registry.Registry for open() calls."""

    def __init__(self, key_map: dict):
        self._keys = key_map

    def open(self, path: str):
        if path in self._keys:
            return self._keys[path]
        raise Exception(f"Key not found: {path}")


class TestActiveControlsetPath(unittest.TestCase):
    """Tests for the active_controlset_path function."""

    def _make_system_hive(self, select_current: int = 1,
                          include_select: bool = True,
                          controlsets: dict = None) -> LoadedHive:
        """Build a mock SYSTEM hive with Select\\Current set."""
        key_map = {}
        if include_select:
            key_map["Select"] = _MockKey({"Current": select_current})
        if controlsets:
            key_map.update(controlsets)
        reg = _MockRegistry(key_map)
        return LoadedHive(
            file_path="/evidence/SYSTEM",
            file_name="SYSTEM",
            hive_type=HiveType.SYSTEM,
            registry=reg,
            root_subkey_count=5,
            classification=ClassificationTrace(
                method="content", matched_signal="Select"),
        )

    def test_select_current_equals_1(self):
        """Select\\Current = 1 should return 'ControlSet001'."""
        hive = self._make_system_hive(select_current=1)
        result = active_controlset_path(hive)
        self.assertEqual(result, "ControlSet001")

    def test_select_current_equals_2(self):
        """Select\\Current = 2 should return 'ControlSet002'."""
        hive = self._make_system_hive(select_current=2)
        result = active_controlset_path(hive)
        self.assertEqual(result, "ControlSet002")

    def test_select_current_equals_3(self):
        """Select\\Current = 3 should return 'ControlSet003'."""
        hive = self._make_system_hive(select_current=3)
        result = active_controlset_path(hive)
        self.assertEqual(result, "ControlSet003")

    def test_fallback_when_select_missing(self):
        """Missing Select key should fall back to ControlSet001
        and record the fallback in the classification notes."""
        hive = self._make_system_hive(include_select=False)
        result = active_controlset_path(hive)
        self.assertEqual(result, "ControlSet001")
        self.assertIn("fell back to ControlSet001",
                       hive.classification.notes)

    def test_fallback_when_hive_is_none(self):
        """None hive should fall back to ControlSet001."""
        result = active_controlset_path(None)
        self.assertEqual(result, "ControlSet001")

    def test_fallback_when_hive_not_loaded(self):
        """Hive with error should fall back to ControlSet001."""
        hive = LoadedHive(
            file_path="/evidence/SYSTEM",
            file_name="SYSTEM",
            hive_type=HiveType.SYSTEM,
            registry=None,
            error="load failed",
        )
        result = active_controlset_path(hive)
        self.assertEqual(result, "ControlSet001")


class TestExtractorsUseActiveControlSet(unittest.TestCase):
    """Verify that SYSTEM-hive extractors read from the active ControlSet."""

    def _make_system_hive_cs2(self) -> LoadedHive:
        """Build a SYSTEM hive where Select\\Current = 2, with shutdown
        time data ONLY in ControlSet002 (not in ControlSet001)."""
        import struct

        # ShutdownTime: 8-byte FILETIME for 2024-01-15 10:30:00 UTC
        # Using a known FILETIME value
        filetime_val = 133499850000000000  # approx 2024-01-15
        shutdown_bytes = struct.pack("<Q", filetime_val)

        shutdown_key = _MockKey({"ShutdownTime": shutdown_bytes})

        key_map = {
            "Select": _MockKey({"Current": 2}),
            # ControlSet001 does NOT have the shutdown key
            # ControlSet002 DOES have it
            r"ControlSet002\Control\Windows": shutdown_key,
        }
        reg = _MockRegistry(key_map)
        return LoadedHive(
            file_path="/evidence/SYSTEM",
            file_name="SYSTEM",
            hive_type=HiveType.SYSTEM,
            registry=reg,
            root_subkey_count=5,
            classification=ClassificationTrace(
                method="content", matched_signal="Select"),
        )

    def test_shutdown_reads_from_controlset002(self):
        """When Select\\Current = 2, extract_last_shutdown_time must read
        from ControlSet002, not ControlSet001."""
        from core.artifact_definitions import extract_last_shutdown_time

        hive = self._make_system_hive_cs2()
        result = extract_last_shutdown_time(hive)

        # It should NOT have an error — data is in ControlSet002
        self.assertIsNone(result.error,
                          f"Unexpected error: {result.error}")
        # Should have at least one row with the decoded shutdown time
        self.assertGreater(len(result.rows), 0,
                           "Expected at least one row from ControlSet002 data")

    def test_shutdown_fails_if_only_cs001_has_data_but_current_is_2(self):
        """When Select\\Current = 2 but data exists only in ControlSet001,
        the extractor should report key-not-found (it should NOT fall back
        to ControlSet001 on its own)."""
        import struct

        filetime_val = 133499850000000000
        shutdown_bytes = struct.pack("<Q", filetime_val)
        shutdown_key = _MockKey({"ShutdownTime": shutdown_bytes})

        key_map = {
            "Select": _MockKey({"Current": 2}),
            # Data ONLY in ControlSet001 (wrong set)
            r"ControlSet001\Control\Windows": shutdown_key,
        }
        reg = _MockRegistry(key_map)
        hive = LoadedHive(
            file_path="/evidence/SYSTEM",
            file_name="SYSTEM",
            hive_type=HiveType.SYSTEM,
            registry=reg,
            root_subkey_count=5,
            classification=ClassificationTrace(
                method="content", matched_signal="Select"),
        )
        from core.artifact_definitions import extract_last_shutdown_time

        result = extract_last_shutdown_time(hive)

        # Should have an error — ControlSet002 doesn't have the key
        self.assertIsNotNone(result.error,
                             "Expected error when active CS doesn't have data")
        self.assertIn("ControlSet002", result.error,
                      "Error should reference ControlSet002")


if __name__ == "__main__":
    unittest.main()
