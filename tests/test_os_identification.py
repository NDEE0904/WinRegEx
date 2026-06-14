"""
Unit tests for OS Identification — Windows 11 Detection Fix
============================================================
Validates that extract_os_identification correctly identifies
Windows 11 when CurrentBuildNumber >= 22000, even when the raw
ProductName still says "Windows 10".
"""

import sys
import os
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path

# Ensure the project root is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.registry_parser import LoadedHive, HiveType


class _MockValue:
    """Emulates a python-registry value object."""

    def __init__(self, name: str, raw_value, vtype: str = "RegSZ"):
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
    """Emulates a python-registry key object."""

    def __init__(self, values_dict: dict):
        self._values = {
            name: _MockValue(name, val)
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


class _MockRegistry:
    """Minimal mock of Registry.Registry for open() calls."""

    def __init__(self, key_map: dict):
        self._keys = key_map

    def open(self, path: str):
        if path in self._keys:
            return self._keys[path]
        raise Exception(f"Key not found: {path}")


class TestOsIdentificationWin11(unittest.TestCase):
    """Test that Windows 11 is correctly detected from build number."""

    def _make_hive(self, build_number: str, product_name: str,
                   edition_id: str, ubr: int) -> LoadedHive:
        """Create a mock LoadedHive with the given OS values."""
        cv_key = _MockKey({
            "ProductName": product_name,
            "EditionID": edition_id,
            "CurrentBuild": build_number,
            "CurrentBuildNumber": build_number,
            "UBR": ubr,
            "ProductId": "00330-80000-00000-AA123",
            "DisplayVersion": "23H2",
            "SystemRoot": r"C:\WINDOWS",
        })
        reg = _MockRegistry({
            r"Microsoft\Windows NT\CurrentVersion": cv_key,
        })
        return LoadedHive(
            file_path="/evidence/SOFTWARE",
            file_name="SOFTWARE",
            hive_type=HiveType.SOFTWARE,
            registry=reg,
            root_subkey_count=5,
        )

    def test_win11_detected_from_build_22621(self):
        """Build 22621 (Win11 22H2) must produce 'Windows 11 Pro'."""
        from core.artifact_definitions import extract_os_identification

        hive = self._make_hive("22621", "Windows 10 Pro", "Pro", 2506)
        result = extract_os_identification(hive)

        self.assertIsNotNone(result)
        self.assertFalse(result.error, f"Unexpected error: {result.error}")

        # Collect all Field->Value rows
        fields = {
            r.fields["Field"]: r.fields["Value"]
            for r in result.rows if "Field" in r.fields
        }

        # The "Operating System" field must say Windows 11, not Windows 10
        self.assertIn("Operating System", fields,
                      "Missing 'Operating System' field in result")
        os_val = fields["Operating System"]
        self.assertIn("Windows 11", os_val,
                      f"Expected 'Windows 11' in OS string, got: {os_val}")
        self.assertNotIn("Windows 10 ", os_val.split("(")[0],
                         f"OS string should NOT say 'Windows 10': {os_val}")

        # Edition
        self.assertIn("Pro", os_val,
                      f"Expected 'Pro' edition in OS string: {os_val}")

        # Build format: (Build 22621.2506)
        self.assertIn("(Build 22621.2506)", os_val,
                      f"Expected '(Build 22621.2506)' in OS string: {os_val}")

        # Raw ProductName is corrected when build proves Windows 11
        self.assertIn("Product Name (Raw)", fields)
        self.assertEqual(fields["Product Name (Raw)"], "Windows 11 Pro")

    def test_win10_preserved_for_build_19045(self):
        """Build 19045 (Win10 22H2) must remain 'Windows 10'."""
        from core.artifact_definitions import extract_os_identification

        hive = self._make_hive("19045", "Windows 10 Pro", "Pro", 3803)
        result = extract_os_identification(hive)

        fields = {
            r.fields["Field"]: r.fields["Value"]
            for r in result.rows if "Field" in r.fields
        }

        os_val = fields.get("Operating System", "")
        self.assertIn("Windows 10", os_val,
                      f"Expected 'Windows 10' for build 19045: {os_val}")
        self.assertNotIn("Windows 11", os_val,
                         f"Should NOT say Windows 11 for build 19045: {os_val}")

    def test_win11_boundary_build_22000(self):
        """Build 22000 is the exact boundary — must be Windows 11."""
        from core.artifact_definitions import extract_os_identification

        hive = self._make_hive("22000", "Windows 10 Pro", "Pro", 1)
        result = extract_os_identification(hive)

        fields = {
            r.fields["Field"]: r.fields["Value"]
            for r in result.rows if "Field" in r.fields
        }

        os_val = fields.get("Operating System", "")
        self.assertIn("Windows 11", os_val,
                      f"Build 22000 should be Windows 11: {os_val}")

    def test_build_number_format(self):
        """The build string must be 'Windows 11 Pro (Build 22621.2506)'."""
        from core.artifact_definitions import extract_os_identification

        hive = self._make_hive("22621", "Windows 10 Pro", "Pro", 2506)
        result = extract_os_identification(hive)

        fields = {
            r.fields["Field"]: r.fields["Value"]
            for r in result.rows if "Field" in r.fields
        }

        expected = "Windows 11 Pro (Build 22621.2506)"
        os_val = fields.get("Operating System", "")
        self.assertEqual(os_val, expected,
                         f"OS string mismatch: expected '{expected}', got '{os_val}'")


if __name__ == "__main__":
    unittest.main()
