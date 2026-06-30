"""
Report Generator
================
Produces forensic reports in three formats: PDF, CSV, JSON.

Every export contains, in order:

    1. CHAIN-OF-CUSTODY HEADER
       Case name, case number, examiner, evidence source path,
       reference SHA-256, pre-/post-analysis integrity check stamps,
       tool name + version, date of analysis, report-generation
       timestamp (UTC).

    2. EXECUTIVE SUMMARY  (auto-generated, never blocks export)
       - Total artifacts examined
       - Total findings broken down by severity
       - Top 5 most concerning findings (one line each)
       - Hive files loaded (filename -> classified type)
       - Time range covered by the evidence
       - Optional examiner_notes string (defaults to empty)

    3. ARTIFACTS
       Each artifact's findings as a table. The Interpretation and
       Flag columns are suppressed if EVERY row in that artifact
       leaves them empty - matching the GUI's behaviour.

    4. ACTION LOG
       The full audit trail.

The PDF specifically includes a forensic-format COVER PAGE as the
first page (before the executive summary).
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .action_logger import ActionLogger
from .artifact_definitions import ArtifactResult
from .hash_verifier import IntegrityCheckResult

# Hardcoded UTC+3 timezone per v1.5.0 spec
TZ_UTC3 = timezone(timedelta(hours=3))


TOOL_NAME = "Windows Registry Examination"
TOOL_VERSION = "1.5.0"


# ---------------------------------------------------------------------------
# Bundle types
# ---------------------------------------------------------------------------

@dataclass
class ExaminedArtifact:
    name: str
    category: str
    hive_or_log: str
    key_path: str
    forensic_value: str
    forensic_question: str
    examiner_notes: str
    result: ArtifactResult


@dataclass
class LoadedHiveSummary:
    """Used in the Executive Summary so misclassifications are visible."""
    file_name: str
    file_path: str
    hive_type: str
    classification_method: str   # "content" | "filename" | "unknown"
    classification_signal: str = ""


@dataclass
class ReportBundle:
    case_name: str
    case_number: str = ""
    examiner: str = ""
    evidence_source: str = ""
    reference_hash: str = ""
    pre_check: Optional[IntegrityCheckResult] = None
    post_check: Optional[IntegrityCheckResult] = None
    artifacts: List[ExaminedArtifact] = field(default_factory=list)
    action_log: List[Dict[str, Any]] = field(default_factory=list)
    loaded_hives: List[LoadedHiveSummary] = field(default_factory=list)
    examiner_summary_notes: str = ""
    extraction_report_json: Optional[Dict[str, Any]] = None

    @property
    def export_timestamp(self) -> str:
        return datetime.now(TZ_UTC3).strftime("%Y-%m-%d %H:%M:%S UTC+3")

    @property
    def date_of_analysis(self) -> str:
        if self.pre_check and self.pre_check.timestamp_utc:
            # take just the date portion
            return self.pre_check.timestamp_utc.split(" ")[0]
        return datetime.now(TZ_UTC3).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# Executive summary (auto-generated)
# ---------------------------------------------------------------------------

@dataclass
class ExecutiveSummary:
    artifact_count: int = 0
    total_rows: int = 0
    high_risk: int = 0
    suspicious: int = 0
    warnings: int = 0
    informational: int = 0
    top_findings: List[str] = field(default_factory=list)  # already-formatted lines
    hive_lines: List[str] = field(default_factory=list)
    earliest_seen: str = ""
    latest_seen: str = ""

    def as_text_lines(self, examiner_notes: str = "") -> List[str]:
        out = [
            f"Total artifacts examined : {self.artifact_count}",
            f"Total finding rows       : {self.total_rows}",
            f"  HIGH RISK              : {self.high_risk}",
            f"  SUSPICIOUS             : {self.suspicious}",
            f"  WARNING                : {self.warnings}",
            f"  INFORMATIONAL          : {self.informational}",
        ]
        if self.earliest_seen and self.latest_seen:
            out.append(f"Evidence time range      : "
                       f"{self.earliest_seen} -> {self.latest_seen}")
        if self.hive_lines:
            out.append("")
            out.append("Hives loaded:")
            for ln in self.hive_lines:
                out.append(f"  - {ln}")
        if self.top_findings:
            out.append("")
            out.append("Top concerning findings:")
            for ln in self.top_findings:
                out.append(f"  - {ln}")
        if examiner_notes.strip():
            out.append("")
            out.append("Examiner Notes:")
            for ln in examiner_notes.splitlines():
                out.append(f"  {ln}")
        return out


def _severity_rank(flag: str) -> int:
    return {"HIGH RISK": 3, "SUSPICIOUS": 2, "WARNING": 1}.get(flag, 0)


_DATE_PREFIX_FIELDS = (
    "Last Connected (UTC)", "Last Login (UTC)", "Last Password Change (UTC)",
    "Account Expires (UTC)", "Last Failed Login (UTC)",
    "Date Created (UTC)", "Date Last Connected (UTC)",
    "Last Write (UTC)", "Timestamp", "Time", "InstallDate", "Install Date",
    "Last Shutdown Time", "ShutdownTime", "FILETIME",
)


def _maybe_extract_date(value: str) -> Optional[str]:
    """Pull a yyyy-mm-dd HH:MM:SS prefix out of a cell value, if present."""
    if not value:
        return None
    s = str(value).strip()
    if len(s) < 10:
        return None
    # yyyy-mm-dd at the start counts; the rest is optional
    head = s[:10]
    if head[4] == "-" and head[7] == "-":
        return s[:19] if len(s) >= 19 else head
    return None


def build_executive_summary(bundle: ReportBundle) -> ExecutiveSummary:
    s = ExecutiveSummary()
    s.artifact_count = len(bundle.artifacts)

    candidate_findings: List[Tuple[int, str]] = []
    earliest: Optional[str] = None
    latest: Optional[str] = None

    for art in bundle.artifacts:
        s.total_rows += art.result.row_count
        for row in art.result.rows:
            f = row.flag or ""
            if f == "HIGH RISK":
                s.high_risk += 1
            elif f == "SUSPICIOUS":
                s.suspicious += 1
            elif f == "WARNING":
                s.warnings += 1
            else:
                s.informational += 1

            if f in ("HIGH RISK", "SUSPICIOUS", "WARNING"):
                # Find a representative label - first non-empty field value
                label = ""
                for k in ("Username", "DisplayName", "Device Name",
                          "Service Name", "SSID", "Path", "Field"):
                    if row.fields.get(k):
                        label = str(row.fields[k])
                        break
                if not label and row.fields:
                    label = str(next(iter(row.fields.values())))
                desc = (row.interpretation or label or "(no description)")[:160]
                candidate_findings.append(
                    (_severity_rank(f),
                     f"[{f}] {art.name} - {desc}"))

            # Track the earliest / latest timestamp seen
            for k, v in row.fields.items():
                if k in _DATE_PREFIX_FIELDS or "UTC" in k or "Time" in k:
                    iso = _maybe_extract_date(v)
                    if iso is None:
                        continue
                    if earliest is None or iso < earliest:
                        earliest = iso
                    if latest is None or iso > latest:
                        latest = iso

    candidate_findings.sort(key=lambda t: -t[0])
    s.top_findings = [line for _, line in candidate_findings[:5]]

    if earliest:
        s.earliest_seen = earliest
    if latest:
        s.latest_seen = latest

    for h in bundle.loaded_hives:
        method = (f" (via {h.classification_method}"
                  + (f": {h.classification_signal}"
                     if h.classification_signal else "")
                  + ")") if h.classification_method else ""
        s.hive_lines.append(f"{h.file_name} -> {h.hive_type}{method}")

    return s


# ---------------------------------------------------------------------------
# Column suppression (mirrors the GUI rule)
# ---------------------------------------------------------------------------

# Sentinel values that are treated as "empty" for column-suppression purposes.
_EMPTY_SENTINELS = frozenset({"", "n/a", "—", "-", "none", "null", "unknown"})


def _is_col_value_empty(v: str) -> bool:
    """Return True if v is blank, whitespace-only, or an N/A-equivalent."""
    return v.strip().lower() in _EMPTY_SENTINELS


def _resolve_columns(art: ExaminedArtifact) -> List[str]:
    """Return the ordered column list for an artifact.

    Rules (applied in order):
    1. Start from art.result.columns (or the first row's keys as fallback).
    2. Drop any base column where EVERY row's _row_value_for() is empty /
       whitespace / N/A-equivalent — the column carries no information.
    3. Append 'Interpretation' if at least one row has a non-empty value
       and the column is not already present.
    4. Append 'Flag' under the same condition.
    """
    base = list(art.result.columns)
    if not base and art.result.rows:
        base = list(art.result.rows[0].fields.keys())
    base = [str(c) for c in base]

    # Step 2: drop base columns that are empty across every row
    if art.result.rows:
        base = [
            col for col in base
            if not all(
                _is_col_value_empty(_row_value_for(row, col))
                for row in art.result.rows
            )
        ]

    cols = list(base)
    any_interp = any((r.interpretation or "").strip() for r in art.result.rows)
    any_flag = any((r.flag or "").strip() for r in art.result.rows)
    if any_interp and "Interpretation" not in cols:
        cols.append("Interpretation")
    if any_flag and "Flag" not in cols:
        cols.append("Flag")
    return cols


def _row_value_for(row, col: str) -> str:
    if col == "Interpretation":
        return row.interpretation or ""
    if col == "Flag":
        return row.flag or ""
    return str(row.fields.get(col, ""))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _check_line(check: Optional[IntegrityCheckResult], label: str) -> str:
    if check is None:
        return f"{label}: NOT PERFORMED"
    status = "PASS" if check.matched else "FAIL"
    return (f"{label}: {status} | computed={check.computed_hash} | "
            f"reference={check.reference_hash} | at {check.timestamp_utc}")


# ===========================================================================
# JSON
# ===========================================================================

def export_json(bundle: ReportBundle, output_path: str | Path) -> str:
    out = Path(output_path).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    summary = build_executive_summary(bundle)

    payload: Dict[str, Any] = {
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "chain_of_custody": {
            "case_name": bundle.case_name,
            "case_number": bundle.case_number,
            "examiner": bundle.examiner,
            "evidence_source": bundle.evidence_source,
            "date_of_analysis": bundle.date_of_analysis,
            "report_generated_utc": bundle.export_timestamp,
            "reference_hash": bundle.reference_hash,
            "pre_analysis_check": (bundle.pre_check.to_dict()
                                   if bundle.pre_check else None),
            "post_analysis_check": (bundle.post_check.to_dict()
                                    if bundle.post_check else None),
        },
        "executive_summary": {
            "artifacts_examined": summary.artifact_count,
            "total_rows": summary.total_rows,
            "severity_counts": {
                "HIGH RISK": summary.high_risk,
                "SUSPICIOUS": summary.suspicious,
                "WARNING": summary.warnings,
                "INFORMATIONAL": summary.informational,
            },
            "evidence_time_range": {
                "earliest": summary.earliest_seen,
                "latest": summary.latest_seen,
            },
            "hives_loaded": [
                {"file_name": h.file_name, "file_path": h.file_path,
                 "hive_type": h.hive_type,
                 "classification_method": h.classification_method,
                 "classification_signal": h.classification_signal}
                for h in bundle.loaded_hives
            ],
            "top_findings": summary.top_findings,
            "examiner_notes": bundle.examiner_summary_notes,
        },
        "artifacts": [],
        "action_log": bundle.action_log,
    }

    for art in bundle.artifacts:
        cols = _resolve_columns(art)
        payload["artifacts"].append({
            "name": art.name,
            "category": art.category,
            "hive_or_log": art.hive_or_log,
            "key_path": art.key_path,
            "forensic_value": art.forensic_value,
            "forensic_question": art.forensic_question,
            "examiner_notes": art.examiner_notes,
            "raw_key_last_write": art.result.raw_key_last_write,
            "summary": art.result.summary,
            "error": art.result.error,
            "columns": cols,
            "rows": [
                {col: _row_value_for(row, col) for col in cols}
                for row in art.result.rows
            ],
        })

    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    return str(out)


# ===========================================================================
# CSV
# ===========================================================================

def export_csv(bundle: ReportBundle, output_path: str | Path) -> str:
    out = Path(output_path).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    summary = build_executive_summary(bundle)

    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)

        # ------ Chain of custody ---------------------------------------
        w.writerow([f"{TOOL_NAME} v{TOOL_VERSION} - Forensic Export"])
        w.writerow(["Case Name", bundle.case_name])
        w.writerow(["Case Number", bundle.case_number])
        w.writerow(["Examiner", bundle.examiner])
        w.writerow(["Evidence Source", bundle.evidence_source])
        w.writerow(["Date of Analysis", bundle.date_of_analysis])
        w.writerow(["Report Generated (UTC)", bundle.export_timestamp])
        w.writerow(["Reference Hash", bundle.reference_hash])
        w.writerow(["Pre-Analysis Integrity",
                    _check_line(bundle.pre_check, "PRE")])
        w.writerow(["Post-Analysis Integrity",
                    _check_line(bundle.post_check, "POST")])
        w.writerow(["Artifacts Examined", str(len(bundle.artifacts))])
        w.writerow([])

        # ------ Executive summary --------------------------------------
        w.writerow(["--- EXECUTIVE SUMMARY ---"])
        for line in summary.as_text_lines(bundle.examiner_summary_notes):
            w.writerow([line])
        w.writerow([])

        # ------ Artifact rows ------------------------------------------
        w.writerow(["Category", "Artifact", "Hive/Log", "Key Path",
                    "Field", "Value", "Examiner Notes"])
        for art in bundle.artifacts:
            if art.result.error:
                w.writerow([art.category, art.name, art.hive_or_log,
                            art.key_path, "ERROR", art.result.error,
                            art.examiner_notes])
                continue
            cols = _resolve_columns(art)
            if not art.result.rows:
                w.writerow([art.category, art.name, art.hive_or_log,
                            art.key_path, "(no data)", "",
                            art.examiner_notes])
                continue
            for row in art.result.rows:
                for col in cols:
                    val = _row_value_for(row, col)
                    if col in ("Interpretation", "Flag") and not val:
                        continue
                    w.writerow([art.category, art.name, art.hive_or_log,
                                art.key_path, col, val, art.examiner_notes])

        # ------ Action log ---------------------------------------------
        w.writerow([])
        w.writerow(["--- ACTION LOG (AUDIT TRAIL) ---"])
        w.writerow(["Sequence", "Timestamp (Local)", "Action", "Description"])
        for entry in bundle.action_log:
            w.writerow([entry.get("sequence", ""),
                        entry.get("timestamp_local", ""),
                        entry.get("action", ""),
                        entry.get("description", "")])

    return str(out)


# ===========================================================================
# PDF
# ===========================================================================

class PDFUnavailable(RuntimeError):
    """Raised when reportlab is not installed."""


def _import_reportlab():
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, KeepTogether,
        )
        return {
            "colors": colors, "A4": A4, "cm": cm,
            "getSampleStyleSheet": getSampleStyleSheet,
            "ParagraphStyle": ParagraphStyle,
            "SimpleDocTemplate": SimpleDocTemplate,
            "Paragraph": Paragraph, "Spacer": Spacer,
            "Table": Table, "TableStyle": TableStyle,
            "PageBreak": PageBreak, "KeepTogether": KeepTogether,
        }
    except ImportError as exc:
        raise PDFUnavailable(
            "The 'reportlab' package is required for PDF export. "
            "Install with: pip install reportlab"
        ) from exc


def _safe_text(value: Any, max_len: int = 500) -> str:
    s = "" if value is None else str(value)
    if len(s) > max_len:
        s = s[:max_len] + " ..."
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;"))


def export_pdf(bundle: ReportBundle, output_path: str | Path) -> str:
    rl = _import_reportlab()
    out = Path(output_path).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    summary = build_executive_summary(bundle)

    Paragraph = rl["Paragraph"]
    Spacer = rl["Spacer"]
    Table = rl["Table"]
    TableStyle = rl["TableStyle"]
    colors = rl["colors"]
    cm = rl["cm"]
    A4 = rl["A4"]

    # ---- Page templates with header/footer ----------------------------
    def _on_page(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#666666"))
        # Header
        canvas.drawString(2 * cm, A4[1] - 1 * cm,
                          f"{TOOL_NAME} v{TOOL_VERSION}  |  "
                          f"Case: {bundle.case_name}")
        canvas.drawRightString(A4[0] - 2 * cm, A4[1] - 1 * cm,
                               f"Report generated: {bundle.export_timestamp}")
        # Footer
        canvas.drawString(2 * cm, 1 * cm,
                          f"Examiner: {bundle.examiner}")
        canvas.drawRightString(A4[0] - 2 * cm, 1 * cm,
                               f"Page {doc.page}")
        canvas.restoreState()

    doc = rl["SimpleDocTemplate"](
        str(out), pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
        title=f"Forensic Report - {bundle.case_name}",
        author=bundle.examiner,
    )

    styles = rl["getSampleStyleSheet"]()
    title_style = rl["ParagraphStyle"](
        "title", parent=styles["Title"], fontSize=22, leading=26,
        spaceAfter=14, alignment=1,
        textColor=colors.HexColor("#1f3a5f"),
    )
    cover_sub = rl["ParagraphStyle"](
        "coversub", parent=styles["Heading2"], fontSize=14, leading=18,
        spaceAfter=20, alignment=1,
        textColor=colors.HexColor("#2c5e8e"),
    )
    h1 = rl["ParagraphStyle"](
        "h1", parent=styles["Heading1"], fontSize=14, spaceBefore=14,
        spaceAfter=6, textColor=colors.HexColor("#1f3a5f"),
    )
    h2 = rl["ParagraphStyle"](
        "h2", parent=styles["Heading2"], fontSize=11, spaceBefore=10,
        spaceAfter=4, textColor=colors.HexColor("#2c5e8e"),
    )
    body = rl["ParagraphStyle"](
        "body", parent=styles["BodyText"], fontSize=9, leading=12,
    )
    mono = rl["ParagraphStyle"](
        "mono", parent=styles["BodyText"], fontSize=8, leading=10,
        fontName="Courier",
    )
    forensic_box = rl["ParagraphStyle"](
        "fbox", parent=styles["BodyText"], fontSize=9, leading=12,
        leftIndent=8, borderPadding=6,
        backColor=colors.HexColor("#eef3f8"),
        borderColor=colors.HexColor("#1f3a5f"), borderWidth=0.5,
    )

    story: List[Any] = []

    # ============================================================
    # COVER PAGE
    # ============================================================
    story.append(Spacer(1, 4 * cm))
    story.append(Paragraph("DIGITAL FORENSIC ANALYSIS REPORT", title_style))
    story.append(Paragraph("Windows Registry Examination", cover_sub))
    story.append(Spacer(1, 1 * cm))

    cover_data = [
        ["Case Name:",        _safe_text(bundle.case_name) or "(not specified)"],
        ["Case Number:",      _safe_text(bundle.case_number) or "(not specified)"],
        ["Examiner:",         _safe_text(bundle.examiner) or "(not specified)"],
        ["Evidence Source:",  _safe_text(bundle.evidence_source, max_len=120)
                              or "(not specified)"],
        ["Date of Analysis:", bundle.date_of_analysis],
        ["Report Generated:", bundle.export_timestamp],
        ["", ""],
        ["Tool:",             TOOL_NAME],
        ["Tool Version:",     TOOL_VERSION],
    ]
    cover_tbl = Table(cover_data, colWidths=[5 * cm, 11 * cm])
    cover_tbl.setStyle(TableStyle([
        ("FONT", (0, 0), (-1, -1), "Helvetica", 11),
        ("FONT", (0, 0), (0, -1), "Helvetica-Bold", 11),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef3f8")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#1f3a5f")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#9bb4d1")),
    ]))
    story.append(cover_tbl)

    story.append(Spacer(1, 2 * cm))
    story.append(Paragraph(
        "<i>This report was produced by an offline forensic analysis tool. "
        "All hive files were processed in strict read-only mode. "
        "A SHA-256 integrity check was performed before and after analysis. "
        "The complete examiner action log is appended at the end of this "
        "report.</i>", body))

    story.append(rl["PageBreak"]())

    # ============================================================
    # EXTRACTION REPORT SUMMARY (from uploaded JSON)
    # ============================================================
    if bundle.extraction_report_json:
        _build_extraction_summary_section(
            story, bundle.extraction_report_json,
            rl, h1, h2, body, mono, forensic_box, colors, cm, Paragraph,
            Spacer, Table, TableStyle,
        )
        story.append(rl["PageBreak"]())

    # ============================================================
    # EXECUTIVE SUMMARY
    # ============================================================
    story.append(Paragraph("Executive Summary", h1))

    sev_data = [
        ["Total artifacts examined", str(summary.artifact_count)],
        ["Total finding rows",       str(summary.total_rows)],
        ["HIGH RISK findings",       str(summary.high_risk)],
        ["SUSPICIOUS findings",      str(summary.suspicious)],
        ["WARNING findings",         str(summary.warnings)],
        ["INFORMATIONAL findings",   str(summary.informational)],
    ]
    if summary.earliest_seen and summary.latest_seen:
        sev_data.append(["Evidence time range",
                         f"{summary.earliest_seen}  ->  {summary.latest_seen}"])
    sev_tbl = Table(sev_data, colWidths=[6 * cm, 10 * cm])
    sev_tbl.setStyle(TableStyle([
        ("FONT", (0, 0), (-1, -1), "Helvetica", 9),
        ("FONT", (0, 0), (0, -1), "Helvetica-Bold", 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef3f8")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#1f3a5f")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#9bb4d1")),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    # severity row coloring
    severity_row_colors = {
        2: colors.HexColor("#f8c6c6"),  # HIGH RISK
        3: colors.HexColor("#ffe2c2"),  # SUSPICIOUS
        4: colors.HexColor("#fff3cd"),  # WARNING
    }
    extra = []
    for r, c in severity_row_colors.items():
        if r < len(sev_data):
            extra.append(("BACKGROUND", (1, r), (1, r), c))
    sev_tbl.setStyle(TableStyle(extra))
    story.append(sev_tbl)

    if summary.hive_lines:
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph("Hive Files Loaded", h2))
        for line in summary.hive_lines:
            story.append(Paragraph("- " + _safe_text(line), body))

    if summary.top_findings:
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph("Top Concerning Findings", h2))
        for line in summary.top_findings:
            story.append(Paragraph("- " + _safe_text(line, max_len=300), body))

    if bundle.examiner_summary_notes.strip():
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph("Examiner Notes", h2))
        story.append(Paragraph(_safe_text(bundle.examiner_summary_notes, 2000),
                               forensic_box))

    # ============================================================
    # INTEGRITY VERIFICATION
    # ============================================================
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph("Hash Integrity Verification", h1))

    def _check_table(check: Optional[IntegrityCheckResult], label: str):
        if check is None:
            data = [[label, "Not performed"]]
            bg_color = colors.HexColor("#f0f0f0")
        else:
            status = ("PASS - integrity intact" if check.matched
                      else "FAIL - tampering detected")
            data = [
                [label, ""],
                ["Stage:", check.stage],
                ["Status:", status],
                ["Timestamp:", check.timestamp_utc],
                ["Reference SHA-256:", check.reference_hash],
                ["Computed SHA-256:", check.computed_hash],
            ]
            bg_color = (colors.HexColor("#e0f0e0") if check.matched
                        else colors.HexColor("#fce4e4"))
        t = Table(data, colWidths=[4.5 * cm, 12 * cm])
        ts = [
            ("FONT", (0, 0), (-1, -1), "Helvetica", 8),
            ("FONT", (0, 0), (0, -1), "Helvetica-Bold", 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BACKGROUND", (0, 0), (-1, 0), bg_color),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.grey),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        t.setStyle(TableStyle(ts))
        return t

    story.append(_check_table(bundle.pre_check, "Pre-Analysis Check"))
    story.append(Spacer(1, 0.3 * cm))
    story.append(_check_table(bundle.post_check, "Post-Analysis Check"))

    # ============================================================
    # ARTIFACTS
    # ============================================================
    story.append(rl["PageBreak"]())
    story.append(Paragraph("Forensic Artifacts", h1))

    flag_color_map = {
        "WARNING":   colors.HexColor("#fff3cd"),
        "SUSPICIOUS": colors.HexColor("#ffe2c2"),
        "HIGH RISK": colors.HexColor("#f8c6c6"),
    }

    if not bundle.artifacts:
        story.append(Paragraph(
            "<i>No artifacts were viewed during this examination session.</i>",
            body))
    for idx, art in enumerate(bundle.artifacts, 1):
        story.append(Paragraph(f"{idx}. {_safe_text(art.name)}", h1))
        meta_data = [
            ["Category:", _safe_text(art.category)],
            ["Hive / Log File:", _safe_text(art.hive_or_log)],
            ["Key Path:", _safe_text(art.key_path)],
        ]
        if art.result.raw_key_last_write:
            meta_data.append(["Key Last Write:",
                              _safe_text(art.result.raw_key_last_write)])
        meta_table = Table(meta_data, colWidths=[3.5 * cm, 13 * cm])
        meta_table.setStyle(TableStyle([
            ("FONT", (0, 0), (-1, -1), "Helvetica", 8),
            ("FONT", (0, 0), (0, -1), "Helvetica-Bold", 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.2 * cm))

        story.append(Paragraph("Findings", h2))
        if art.result.error:
            story.append(Paragraph(
                f"<font color='#a94442'><b>Error:</b> "
                f"{_safe_text(art.result.error)}</font>", body))
        elif not art.result.rows:
            story.append(Paragraph(
                "<i>Key/path was located but contained no values.</i>", body))
        else:
            # Determine full column set and detect suppressed columns
            all_base = list(art.result.columns)
            if not all_base and art.result.rows:
                all_base = list(art.result.rows[0].fields.keys())
            all_base = [str(c) for c in all_base]
            cols = _resolve_columns(art)
            suppressed = [c for c in all_base if c not in cols]

            data_rows = [[c for c in cols]]
            row_flags = []
            display_rows = art.result.rows[:200]
            for row in display_rows:
                cells = [_safe_text(_row_value_for(row, c), max_len=200)
                         for c in cols]
                data_rows.append([Paragraph(c, mono) for c in cells])
                row_flags.append(row.flag)

            available_width = 17 * cm
            n = max(len(cols), 1)
            col_widths = [available_width / n] * n
            t = Table(data_rows, colWidths=col_widths, repeatRows=1)
            ts = [
                ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f3a5f")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]
            for ridx, fl in enumerate(row_flags, start=1):
                if fl in flag_color_map:
                    ts.append(("BACKGROUND", (0, ridx), (-1, ridx),
                               flag_color_map[fl]))
            t.setStyle(TableStyle(ts))
            story.append(t)
            if suppressed:
                omit_style = rl["ParagraphStyle"](
                    "omit_note", parent=styles["BodyText"],
                    fontSize=8, leading=10, fontName="Helvetica-Oblique",
                    textColor=colors.HexColor("#555555"),
                )
                story.append(Paragraph(
                    f"<i>Columns suppressed (all values empty): "
                    f"{', '.join(_safe_text(c) for c in suppressed)}</i>",
                    omit_style))
            if len(art.result.rows) > 200:
                story.append(Paragraph(
                    f"<i>... showing first 200 of {len(art.result.rows)} "
                    f"rows. See JSON export for the full dataset.</i>", body))

        story.append(Spacer(1, 0.2 * cm))
        story.append(Paragraph("Forensic Context", h2))
        ctx_html = (
            f"<b>Forensic Value:</b> {_safe_text(art.forensic_value)}<br/>"
            f"<b>Question Answered:</b> {_safe_text(art.forensic_question)}<br/>"
        )
        if art.result.summary:
            ctx_html += f"<b>Interpretation:</b> {_safe_text(art.result.summary)}<br/>"
        if art.examiner_notes:
            ctx_html += (f"<b>Examiner Notes:</b> "
                         f"{_safe_text(art.examiner_notes, max_len=2000)}")
        story.append(Paragraph(ctx_html, forensic_box))
        story.append(Spacer(1, 0.5 * cm))

    # ============================================================
    # ACTION LOG
    # ============================================================
    story.append(rl["PageBreak"]())
    story.append(Paragraph("Action Log (Audit Trail)", h1))
    if not bundle.action_log:
        story.append(Paragraph("<i>No action log entries recorded.</i>", body))
    else:
        log_rows = [["#", "Timestamp (Local)", "Action", "Description"]]
        for entry in bundle.action_log:
            log_rows.append([
                Paragraph(str(entry.get("sequence", "")), mono),
                Paragraph(_safe_text(entry.get("timestamp_local", "")), mono),
                Paragraph(_safe_text(entry.get("action", "")), mono),
                Paragraph(_safe_text(entry.get("description", ""), 400), mono),
            ])
        log_tbl = Table(log_rows,
                        colWidths=[1 * cm, 4 * cm, 4 * cm, 8 * cm],
                        repeatRows=1)
        log_tbl.setStyle(TableStyle([
            ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f3a5f")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 3),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        story.append(log_tbl)

    # ============================================================
    # SIGNATURE BLOCK
    # ============================================================
    story.append(Spacer(1, 1 * cm))
    story.append(Paragraph("___________________________________", body))
    story.append(Paragraph(
        f"Examiner Signature - {_safe_text(bundle.examiner)}", body))
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph("Date: ____________________________", body))

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    return str(out)


# ===========================================================================
# Extraction Report Summary (PDF section builder)
# ===========================================================================

def _fmt_bytes(n: Any) -> str:
    """Format a byte count into a human-readable string."""
    try:
        b = int(n)
    except (TypeError, ValueError):
        return str(n)
    if b < 1024:
        return f"{b} B"
    if b < 1024 ** 2:
        return f"{b / 1024:.1f} KB"
    if b < 1024 ** 3:
        return f"{b / (1024 ** 2):.1f} MB"
    return f"{b / (1024 ** 3):.2f} GB"


def _build_extraction_summary_section(
    story, report: Dict[str, Any],
    rl, h1, h2, body, mono, forensic_box, colors, cm,
    Paragraph, Spacer, Table, TableStyle,
) -> None:
    """Render a professional Extraction Report Summary section from the
    uploaded JSON extraction report.  This is placed immediately after
    the cover page and before the Executive Summary."""

    story.append(Paragraph("Extraction Report Summary", h1))
    story.append(Paragraph(
        "<i>The following data was imported from the DFIR Portable Evidence "
        "Collector extraction report (JSON) uploaded by the examiner. "
        "It documents the acquisition chain-of-custody metadata, source "
        "machine details, and per-artifact integrity verification "
        "performed at collection time.</i>", body))
    story.append(Spacer(1, 0.4 * cm))

    # --- Shared table style builder ------------------------------------
    def _info_table(data, label_w=5, value_w=11.5):
        t = Table(data, colWidths=[label_w * cm, value_w * cm])
        t.setStyle(TableStyle([
            ("FONT", (0, 0), (-1, -1), "Helvetica", 9),
            ("FONT", (0, 0), (0, -1), "Helvetica-Bold", 9),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef3f8")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#1f3a5f")),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#9bb4d1")),
        ]))
        return t

    # 1. Collection Overview -------------------------------------------
    story.append(Paragraph("Collection Overview", h2))
    tool_info = report.get("tool", {})
    timestamps = report.get("timestamps", {})
    overview_data = [
        ["Case ID:",        _safe_text(report.get("case_id", "N/A"))],
        ["Collection Tool:", _safe_text(tool_info.get("name", "N/A"))],
        ["Tool Suite:",     _safe_text(tool_info.get("suite", "N/A"))],
        ["Tool Version:",   _safe_text(tool_info.get("version", "N/A"))],
        ["Started (UTC):",  _safe_text(timestamps.get("started_utc", "N/A"))],
        ["Completed (UTC):", _safe_text(timestamps.get("completed_utc", "N/A"))],
    ]
    story.append(_info_table(overview_data))
    story.append(Spacer(1, 0.4 * cm))

    # 2. Source Machine ------------------------------------------------
    machine = report.get("source_machine", {})
    if machine:
        story.append(Paragraph("Source Machine", h2))
        win_ed = machine.get("windows_edition", {})
        machine_data = [
            ["Hostname:",        _safe_text(machine.get("hostname", "N/A"))],
            ["Operating System:", _safe_text(machine.get("os", "N/A"))],
            ["Platform:",        _safe_text(machine.get("platform", "N/A"))],
            ["Windows Release:", _safe_text(win_ed.get("release", "N/A"))],
            ["Windows Build:",   _safe_text(win_ed.get("build", "N/A"))],
            ["Is Server:",       "Yes" if win_ed.get("is_server") else "No"],
            ["User Running:",    _safe_text(machine.get("user_running", "N/A"))],
            ["Elevated:",        "Yes" if machine.get("elevated") else "No"],
            ["System Drive:",    _safe_text(machine.get("system_drive", "N/A"))],
        ]
        story.append(_info_table(machine_data))
        story.append(Spacer(1, 0.4 * cm))

    # 3. Volume Shadow Copy Service ------------------------------------
    vss = report.get("vss", {})
    if vss:
        story.append(Paragraph("Volume Shadow Copy (VSS)", h2))
        vss_data = [
            ["Shadow ID:",     _safe_text(vss.get("shadow_id", "N/A"))],
            ["Shadow Device:", _safe_text(vss.get("shadow_device", "N/A"),
                                          max_len=200)],
        ]
        story.append(_info_table(vss_data))
        story.append(Spacer(1, 0.4 * cm))

    # 4. Hashing & Evidence Protection ---------------------------------
    hashing = report.get("hashing", {})
    protection = report.get("evidence_protection", {})
    if hashing or protection:
        story.append(Paragraph("Hashing \u0026amp; Evidence Protection", h2))
        hp_data = []
        if hashing:
            hp_data.append(["Hash Algorithm:",
                            _safe_text(hashing.get("algorithm", "N/A"))])
            hp_data.append(["Hash Provider:",
                            _safe_text(hashing.get("provider", "N/A"))])
            hp_data.append(["Hardware Native:",
                            "Yes" if hashing.get("hardware_native") else "No"])
        if protection:
            raw_wbm = str(protection.get("write_block_mode", "N/A"))
            # Clarify the meaning of the raw POSIX permission value so
            # report readers are not misled into thinking this is a
            # hardware or software write-blocker.  The value itself is
            # passed through verbatim from the DFIR Collector JSON.
            if raw_wbm not in ("N/A", ""):
                # Attempt to render octal shorthand in a human-readable way
                try:
                    perm_int = int(raw_wbm, 8) if raw_wbm.startswith("0o") else int(raw_wbm)
                    perm_bits = oct(perm_int)  # normalise to 0oXXX
                    wbm_display = (
                        f"{raw_wbm} (r--r--r--) "
                        "[POSIX read-only file permission applied to analysis "
                        "copies \u2014 not hardware/software write-blocking]"
                    )
                except (ValueError, TypeError):
                    wbm_display = (
                        f"{raw_wbm} "
                        "[POSIX read-only file permission applied to analysis "
                        "copies \u2014 not hardware/software write-blocking]"
                    )
            else:
                wbm_display = raw_wbm
            hp_data.append(["Write Block Mode:",
                            _safe_text(wbm_display, max_len=300)])
            hp_data.append(["Artifacts Write-Blocked:",
                            str(protection.get("artifacts_write_blocked", "N/A"))])
        story.append(_info_table(hp_data))
        story.append(Spacer(1, 0.4 * cm))

    # 5. Acquired Artifacts (per-file integrity table) ------------------
    artifacts_section = report.get("artifacts", {})
    all_items: List[Dict[str, Any]] = []
    for group_key in ("registry_hives", "user_hives", "evtx_logs"):
        all_items.extend(artifacts_section.get(group_key, []))

    if all_items:
        story.append(Paragraph("Acquired Artifacts \u0026amp; Integrity Verification", h2))

        header = ["Artifact", "Type", "Size", "Integrity",
                  "SHA-256 (In-Flight)"]
        tbl_data = [header]
        row_integrity: List[str] = []
        for item in all_items:
            name = _safe_text(item.get("logical_name", "N/A"), max_len=60)
            atype = _safe_text(item.get("artifact_type", "N/A"))
            size = _fmt_bytes(item.get("size_bytes", 0))
            integrity = _safe_text(item.get("integrity", "N/A"))
            sha = _safe_text(item.get("sha256_inflight", "N/A"), max_len=64)
            tbl_data.append([
                Paragraph(name, mono),
                Paragraph(atype, mono),
                Paragraph(size, mono),
                Paragraph(f"<b>{integrity}</b>", mono),
                Paragraph(sha, mono),
            ])
            row_integrity.append(integrity)

        art_tbl = Table(
            tbl_data,
            colWidths=[3 * cm, 2.5 * cm, 2 * cm, 1.8 * cm, 7.2 * cm],
            repeatRows=1,
        )
        art_ts = [
            ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f3a5f")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        for ridx, integ in enumerate(row_integrity, start=1):
            if integ == "PASS":
                art_ts.append(
                    ("BACKGROUND", (3, ridx), (3, ridx),
                     colors.HexColor("#d4edda")))
            elif integ == "FAIL":
                art_ts.append(
                    ("BACKGROUND", (3, ridx), (3, ridx),
                     colors.HexColor("#f8d7da")))
        art_tbl.setStyle(TableStyle(art_ts))
        story.append(art_tbl)
        story.append(Spacer(1, 0.4 * cm))

    # 6. Collection Summary --------------------------------------------
    summary_data = report.get("summary", {})
    if summary_data:
        story.append(Paragraph("Collection Summary", h2))
        overall_integrity = _safe_text(report.get("integrity", "N/A"))
        sum_rows = [
            ["Total Artifacts:",   str(summary_data.get("total_artifacts", 0))],
            ["PASS:",              str(summary_data.get("pass", 0))],
            ["FAIL:",              str(summary_data.get("fail", 0))],
            ["Error:",             str(summary_data.get("error", 0))],
            ["Write-Blocked:",     str(summary_data.get("write_blocked", 0))],
            ["Total Acquired:",    _fmt_bytes(summary_data.get("bytes_acquired", 0))],
            ["Overall Integrity:", overall_integrity],
        ]
        sum_tbl = _info_table(sum_rows)
        # Highlight overall integrity row
        if overall_integrity == "PASS":
            sum_tbl.setStyle(TableStyle([
                ("BACKGROUND", (1, 6), (1, 6), colors.HexColor("#d4edda")),
                ("FONT", (1, 6), (1, 6), "Helvetica-Bold", 9),
            ]))
        elif overall_integrity == "FAIL":
            sum_tbl.setStyle(TableStyle([
                ("BACKGROUND", (1, 6), (1, 6), colors.HexColor("#f8d7da")),
                ("FONT", (1, 6), (1, 6), "Helvetica-Bold", 9),
            ]))
        story.append(sum_tbl)


# ===========================================================================
# Bundle builder
# ===========================================================================

def build_bundle_from_session(
    case_name: str,
    examiner: str,
    reference_hash: str,
    pre_check: Optional[IntegrityCheckResult],
    post_check: Optional[IntegrityCheckResult],
    examined: List[ExaminedArtifact],
    logger: ActionLogger,
    case_number: str = "",
    evidence_source: str = "",
    loaded_hives: Optional[List[LoadedHiveSummary]] = None,
    examiner_summary_notes: str = "",
    extraction_report_json: Optional[Dict[str, Any]] = None,
) -> ReportBundle:
    return ReportBundle(
        case_name=case_name,
        case_number=case_number,
        examiner=examiner,
        evidence_source=evidence_source,
        reference_hash=reference_hash,
        pre_check=pre_check,
        post_check=post_check,
        artifacts=examined,
        action_log=logger.to_dict_list(),
        loaded_hives=list(loaded_hives or []),
        examiner_summary_notes=examiner_summary_notes,
        extraction_report_json=extraction_report_json,
    )
