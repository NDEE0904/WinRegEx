"""
Regression tests for two defects fixed in this session
=======================================================

Test 1 — "Temporary path detected" dialog removal
   Statically asserts that gui/splash_window.py and gui/main_window.py
   do NOT contain the strings that identify the Yes/No blocking dialog
   that previously appeared when the staging directory was under /tmp.
   Mirrors the pattern in test_hash_override_removed.py.

Test 2 — PDF export does not crash on empty artifacts
   Constructs ExaminedArtifact objects with zero rows, all-empty rows,
   and all columns suppressed, then calls export_pdf() and verifies it
   completes without raising and that the resulting PDF contains the
   fallback text "No meaningful data extracted for this artifact."
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure the project root is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.artifact_definitions import ArtifactResult, ArtifactRow
from core.report_generator import (
    ExaminedArtifact,
    ReportBundle,
    export_pdf,
    PDFUnavailable,
)


# ---------------------------------------------------------------------------
# Test 1: Static-source checks — dialog strings must not reappear
# ---------------------------------------------------------------------------

class TestTempPathDialogRemoved(unittest.TestCase):
    """Ensure the 'Temporary path detected' blocking dialog is gone."""

    _SPLASH = (Path(__file__).resolve().parent.parent
               / "gui" / "splash_window.py")
    _MAIN = (Path(__file__).resolve().parent.parent
             / "gui" / "main_window.py")

    def _read(self, path: Path) -> str:
        return path.read_text(encoding="utf-8")

    def test_splash_has_no_temporary_path_title(self):
        """splash_window.py must not contain the dialog title string."""
        src = self._read(self._SPLASH)
        self.assertNotIn(
            "Temporary path detected", src,
            "splash_window.py must not contain the 'Temporary path detected' "
            "dialog title. Remove the dialog entirely, not just the title.",
        )

    def test_splash_has_no_temporary_paths_body(self):
        """splash_window.py must not contain the dialog body string."""
        src = self._read(self._SPLASH)
        self.assertNotIn(
            "Temporary paths are typically cleaned up", src,
            "splash_window.py must not contain the 'Temporary paths are "
            "typically cleaned up' body text. The whole dialog must be absent.",
        )

    def test_main_window_has_no_temporary_path_title(self):
        """main_window.py must not contain the dialog title string."""
        src = self._read(self._MAIN)
        self.assertNotIn(
            "Temporary path detected", src,
            "main_window.py must not contain the 'Temporary path detected' "
            "dialog title.",
        )

    def test_main_window_has_no_temporary_paths_body(self):
        """main_window.py must not contain the dialog body string."""
        src = self._read(self._MAIN)
        self.assertNotIn(
            "Temporary paths are typically cleaned up", src,
            "main_window.py must not contain the 'Temporary paths are "
            "typically cleaned up' body text.",
        )


# ---------------------------------------------------------------------------
# Test 2: PDF export does not crash on empty / zero-column artifacts
# ---------------------------------------------------------------------------

def _make_bundle(artifacts):
    """Helper: minimal ReportBundle wrapping a list of ExaminedArtifact."""
    return ReportBundle(
        case_name="Test Case",
        case_number="TC-001",
        examiner="Test Examiner",
        evidence_source="/tmp/evidence",
        artifacts=artifacts,
    )


def _empty_result(name: str = "Test Artifact", columns=None, rows=None):
    """Helper: build an ArtifactResult with controllable columns and rows."""
    result = ArtifactResult(
        artifact_name=name,
        columns=columns or [],
    )
    if rows is not None:
        result.rows = rows
    return result


def _make_artifact(name: str, result: ArtifactResult) -> ExaminedArtifact:
    return ExaminedArtifact(
        name=name,
        category="Test",
        hive_or_log="SYSTEM",
        key_path="ControlSet001\\Test",
        forensic_value="Test forensic value",
        forensic_question="Was this tested?",
        examiner_notes="",
        result=result,
    )


def _extract_pdf_text(pdf_bytes: bytes) -> str:
    """Decompress all content streams in a reportlab-generated PDF.

    reportlab writes content streams with two filters applied in order:
        1. ASCII85Decode  — binary → printable ASCII subset
        2. FlateDecode    — zlib compression

    To read the rendered text (PDF drawing operators / text strings) we
    must undo both layers in reverse order:
        1. Strip the ASCII85 end-of-data marker ``~>``.
        2. base64.a85decode() the result.
        3. zlib.decompress() the inflated bytes.

    Python 3.4+ provides ``base64.a85decode`` natively.
    """
    import base64
    import re
    import zlib

    text_parts = []
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", pdf_bytes, re.DOTALL):
        raw = m.group(1).strip()
        # Try ASCII85 + zlib (reportlab default: /ASCII85Decode /FlateDecode).
        # base64.a85decode(adobe=True) requires the "~>" EOD marker to be
        # present in the input — do NOT strip it beforehand.
        try:
            binary = base64.a85decode(raw, adobe=True)
            inflated = zlib.decompress(binary)
            text_parts.append(inflated.decode("latin-1", errors="replace"))
            continue
        except Exception:
            pass
        # Fallback: raw zlib only (no ASCII85 wrapper)
        try:
            inflated = zlib.decompress(raw)
            text_parts.append(inflated.decode("latin-1", errors="replace"))
            continue
        except Exception:
            pass
        # Last resort: treat as Latin-1 text
        text_parts.append(raw.decode("latin-1", errors="replace"))
    return "\n".join(text_parts)


class TestPDFEmptyArtifactFallback(unittest.TestCase):
    """export_pdf() must not crash and must emit fallback text for empty
    artifacts, regardless of which code path caused the empty result."""

    def _run_pdf(self, artifacts):
        """Run export_pdf on a bundle; return the raw PDF bytes."""
        try:
            import reportlab  # noqa: F401
        except ImportError:
            self.skipTest("reportlab not installed – PDF test skipped")

        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            bundle = _make_bundle(artifacts)
            export_pdf(bundle, tmp_path)
            pdf_bytes = Path(tmp_path).read_bytes()
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

        return pdf_bytes

    def _assert_contains_fallback(self, pdf_bytes: bytes):
        """Assert the fallback phrase is in the decoded PDF content."""
        text = _extract_pdf_text(pdf_bytes)
        self.assertIn(
            "No meaningful data extracted for this artifact",
            text,
            "PDF must contain the fallback text for an empty artifact",
        )

    # --- Case A: artifact result has zero rows and zero columns ----------
    def test_zero_rows_zero_cols_does_not_crash(self):
        """export_pdf must not raise for an artifact with 0 rows and 0 cols.

        When rows is empty the pre-existing 'elif not art.result.rows:' branch
        fires before the new empty-table guard — it outputs the 'Key/path was
        located but contained no values.' message.  The primary assertion is
        that export_pdf does NOT raise.  We also confirm the correct message.
        """
        art = _make_artifact(
            "Zero Rows / Zero Cols",
            _empty_result(columns=[], rows=[]),
        )
        pdf = self._run_pdf([art])
        decoded = _extract_pdf_text(pdf)
        # The zero-rows path uses the existing elif branch, not the new guard.
        self.assertIn(
            "Key/path was located but contained no values", decoded,
            "A 0-row artifact must render the 'no values' message")

    # --- Case B: artifact result has rows but every column is suppressed --
    def test_all_columns_suppressed_does_not_crash(self):
        """When every column value is empty, _resolve_columns() returns [].
        export_pdf must not crash and must use the fallback paragraph."""
        row = ArtifactRow(fields={"Col A": "", "Col B": "n/a", "Col C": "—"})
        result = ArtifactResult(
            artifact_name="All-Empty Cols",
            columns=["Col A", "Col B", "Col C"],
        )
        result.rows = [row]
        art = _make_artifact("All-Empty Cols", result)
        pdf = self._run_pdf([art])
        self._assert_contains_fallback(pdf)

    # --- Case C: artifact result is present with an error but no rows ----
    def test_error_result_no_rows_does_not_crash(self):
        """An artifact error is rendered as an error paragraph (not a Table).
        The primary requirement is that export_pdf does NOT raise."""
        result = ArtifactResult(
            artifact_name="Error Artifact",
            columns=[],
            error="Extraction failed: hive not found",
        )
        art = _make_artifact("Error Artifact", result)
        # Must not raise — the error branch renders a dedicated Paragraph
        # already (separate from the fallback), so we only require no crash.
        pdf = self._run_pdf([art])
        self.assertGreater(len(pdf), 100,
                           "export_pdf must produce a non-trivial PDF")

    # --- Case D: mix of normal and empty artifacts — normal must be OK ---
    def test_normal_artifact_still_renders_table(self):
        """A normal artifact (has rows and populated columns) must still
        render as a Table with data — the empty-table guard must not
        trigger for it.  Paired with an all-suppressed-columns artifact
        (rows exist but every value is blank) so both branches are exercised."""
        normal_row = ArtifactRow(
            fields={"Username": "Alice", "SID": "S-1-5-21-1234"})
        normal_result = ArtifactResult(
            artifact_name="Normal Artifact",
            columns=["Username", "SID"],
        )
        normal_result.rows = [normal_row]
        normal_art = _make_artifact("Normal Artifact", normal_result)

        # Use all-suppressed cols (rows present, every value blank) so the
        # new empty-table guard in the else-branch fires for this artifact.
        suppressed_row = ArtifactRow(
            fields={"Col A": "", "Col B": "n/a", "Col C": "—"})
        suppressed_result = ArtifactResult(
            artifact_name="All-Suppressed Artifact",
            columns=["Col A", "Col B", "Col C"],
        )
        suppressed_result.rows = [suppressed_row]
        suppressed_art = _make_artifact("All-Suppressed Artifact", suppressed_result)

        pdf = self._run_pdf([normal_art, suppressed_art])
        decoded = _extract_pdf_text(pdf)

        # The all-suppressed artifact must show the new fallback text
        self.assertIn(
            "No meaningful data extracted for this artifact", decoded,
            "All-suppressed artifact must have the fallback text in the PDF")

        # Normal artifact data must still be present — guard must not fire
        self.assertIn(
            "Alice", decoded,
            "Normal artifact row data ('Alice') must still appear in the PDF")


if __name__ == "__main__":
    unittest.main()
