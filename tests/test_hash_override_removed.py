"""
Tests for Change 2 — Hash-mismatch override removal
====================================================
Validates that:
  1. perform_single_file_check correctly detects a mutated file.
  2. No code path in splash_window.py opens MainWindow on mismatch
     (static analysis via grep over the source).
  3. log_integrity_failure records the correct action type and metadata.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure the project root is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.action_logger import ActionLogger
from core.hash_verifier import perform_single_file_check


class TestHashMismatchBlocksAnalysis(unittest.TestCase):
    """Verify that a mutated file fails integrity and no override exists."""

    def test_mutated_file_fails_integrity(self):
        """Mutating one byte of a file must make the hash check fail."""
        # Create a temporary file with known content
        with tempfile.NamedTemporaryFile(
                delete=False, suffix="_SYSTEM") as tmp:
            tmp.write(b"regf" + b"\x00" * 100)
            tmp_path = tmp.name

        try:
            # Get the correct hash first
            good_record = perform_single_file_check(tmp_path, "0" * 64)
            correct_hash = good_record.computed_hash

            # Verify it matches when we supply the correct hash
            match_record = perform_single_file_check(tmp_path, correct_hash)
            self.assertTrue(match_record.matched,
                            "File should match its own hash")

            # Now mutate one byte
            with open(tmp_path, "r+b") as f:
                f.seek(10)
                f.write(b"\xff")

            # Now check with the OLD (correct) hash — must fail
            mutated_record = perform_single_file_check(tmp_path, correct_hash)
            self.assertFalse(mutated_record.matched,
                             "Mutated file must NOT match the original hash")
        finally:
            os.unlink(tmp_path)

    def test_no_override_path_in_splash(self):
        """Static analysis: splash_window.py must NOT contain any override
        dialog that allows proceeding past a hash mismatch."""
        splash_path = (Path(__file__).resolve().parent.parent
                       / "gui" / "splash_window.py")
        source = splash_path.read_text(encoding="utf-8")

        # The old override used "Continue anyway?" prompt
        self.assertNotIn("Continue anyway?", source,
                         "splash_window.py must not offer 'Continue anyway?'")
        self.assertNotIn("OVERRODE", source,
                         "splash_window.py must not reference override logic")
        # The old override used askyesno for "Hash Mismatch" title
        self.assertNotIn('"Hash Mismatch"', source,
                         "splash_window.py must not have a 'Hash Mismatch' "
                         "yes/no dialog")

    def test_no_finish_success_on_mismatch(self):
        """The else branch of _pre_check_done must NOT call _finish_success."""
        splash_path = (Path(__file__).resolve().parent.parent
                       / "gui" / "splash_window.py")
        source = splash_path.read_text(encoding="utf-8")

        # Find the else branch (mismatch path) — it starts after
        # "check.matched" and should NOT contain _finish_success
        lines = source.splitlines()
        in_else_block = False
        else_block_lines = []
        for i, line in enumerate(lines):
            if "check.matched:" in line:
                # We're at the if/else boundary; mark that we'll look
                # for the else
                continue
            if in_else_block:
                # End when we hit a method def at the same indentation
                if line.strip().startswith("def "):
                    break
                else_block_lines.append(line)
            if line.strip() == "else:":
                in_else_block = True

        else_code = "\n".join(else_block_lines)
        self.assertNotIn("_finish_success", else_code,
                         "The mismatch branch must never call _finish_success")


class TestLogIntegrityFailure(unittest.TestCase):
    """Verify the new log_integrity_failure method."""

    def test_log_integrity_failure_records_correct_data(self):
        """log_integrity_failure must create an INTEGRITY_FAILURE entry
        with reference_hash, computed_hash, folder_path, and stage."""
        logger = ActionLogger(case_name="TEST-001", examiner="Tester")
        logger.log_integrity_failure(
            reference_hash="aaa" + "0" * 61,
            computed_hash="bbb" + "1" * 61,
            folder_path="/evidence/staging",
            stage="pre-analysis",
        )
        entries = logger.all_entries()
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry.action, "INTEGRITY_FAILURE")
        self.assertIn("FAILED", entry.description)
        self.assertIn("pre-analysis", entry.description)
        self.assertEqual(entry.metadata["reference_hash"], "aaa" + "0" * 61)
        self.assertEqual(entry.metadata["computed_hash"], "bbb" + "1" * 61)
        self.assertEqual(entry.metadata["folder_path"], "/evidence/staging")
        self.assertEqual(entry.metadata["stage"], "pre-analysis")


if __name__ == "__main__":
    unittest.main()
