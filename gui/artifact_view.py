"""
Artifact View Widget
====================
Renders one ArtifactResult inside the main window's right pane.

Per-table dynamic column rules:
  * Each row supplies a `fields` dict, plus optional `interpretation`
    and `flag`. The "Interpretation" and "Flag" columns are appended
    to the table only if at least ONE row has a non-empty value for
    that column. This is decided per artifact, on the fly.
  * Severity flags (WARNING / SUSPICIOUS / HIGH RISK) still color the
    row when present, even if the Flag column itself is hidden.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, Dict, List, Optional

from core.artifact_definitions import ArtifactDefinition, ArtifactResult, ArtifactRow


_FLAG_COLORS = {
    "WARNING":    {"bg": "#fff3cd", "fg": "#7a5b00"},
    "SUSPICIOUS": {"bg": "#ffe2c2", "fg": "#7a3f00"},
    "HIGH RISK":  {"bg": "#f8c6c6", "fg": "#8a1a1a"},
}


class ArtifactView(tk.Frame):
    """Read-only viewer for one ArtifactResult."""

    def __init__(self, master: tk.Misc,
                 on_notes_changed: Optional[Callable[[str, str], None]] = None):
        super().__init__(master, bg="#ffffff")
        self._on_notes_changed = on_notes_changed
        self._current_definition: Optional[ArtifactDefinition] = None
        self._current_result: Optional[ArtifactResult] = None
        self._notes_by_artifact: Dict[str, str] = {}
        # Track which result-row index corresponds to each iid so row
        # selection still works after the columns are reshaped.
        self._iid_to_row_idx: Dict[str, int] = {}
        self._build_ui()
        self.show_placeholder()

    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        # Header strip
        header = tk.Frame(self, bg="#1f3a5f")
        header.pack(fill="x")
        self._title_var = tk.StringVar(value="(no artifact selected)")
        tk.Label(header, textvariable=self._title_var,
                 font=("DejaVu Sans", 13, "bold"),
                 fg="white", bg="#1f3a5f", anchor="w"
                 ).pack(fill="x", padx=14, pady=(10, 2))
        self._meta_var = tk.StringVar(value="")
        tk.Label(header, textvariable=self._meta_var,
                 font=("DejaVu Sans", 9),
                 fg="#cfdcec", bg="#1f3a5f", anchor="w"
                 ).pack(fill="x", padx=14, pady=(0, 10))

        # Summary / error strip
        self._summary_var = tk.StringVar(value="")
        self._summary_label = tk.Label(
            self, textvariable=self._summary_var,
            font=("DejaVu Sans", 9),
            bg="#eef3f8", fg="#1f3a5f", anchor="w",
            wraplength=1100, justify="left",
            padx=14, pady=8,
        )
        self._summary_label.pack(fill="x")

        # Body: findings table + row detail
        body = tk.Frame(self, bg="#ffffff")
        body.pack(fill="both", expand=True, padx=14, pady=(8, 0))
        body.rowconfigure(1, weight=3)
        body.rowconfigure(3, weight=2)
        body.columnconfigure(0, weight=1)

        tk.Label(body, text="Findings",
                 font=("DejaVu Sans", 10, "bold"),
                 bg="#ffffff", fg="#1f3a5f", anchor="w"
                 ).grid(row=0, column=0, sticky="w", pady=(0, 4))

        tree_frame = tk.Frame(body, bg="#ffffff")
        tree_frame.grid(row=1, column=0, sticky="nsew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        self._tree = ttk.Treeview(tree_frame, show="headings", selectmode="browse")
        self._tree.grid(row=0, column=0, sticky="nsew")

        vsb = ttk.Scrollbar(tree_frame, orient="vertical",
                            command=self._tree.yview)
        vsb.grid(row=0, column=1, sticky="ns")
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal",
                            command=self._tree.xview)
        hsb.grid(row=1, column=0, sticky="ew")
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        for flag, cfg in _FLAG_COLORS.items():
            self._tree.tag_configure(flag, background=cfg["bg"],
                                     foreground=cfg["fg"])
        self._tree.bind("<<TreeviewSelect>>", self._on_row_select)

        tk.Label(body, text="Selected Row Detail",
                 font=("DejaVu Sans", 10, "bold"),
                 bg="#ffffff", fg="#1f3a5f", anchor="w"
                 ).grid(row=2, column=0, sticky="w", pady=(10, 4))

        self._detail = tk.Text(body, height=6, wrap="word",
                               font=("DejaVu Sans Mono", 9),
                               bg="#fafbfc", fg="#222",
                               relief="solid", bd=1)
        self._detail.grid(row=3, column=0, sticky="nsew")
        self._detail.configure(state="disabled")

        # Forensic context block
        ctx = tk.LabelFrame(self, text=" Forensic Context ",
                            font=("DejaVu Sans", 10, "bold"),
                            fg="#1f3a5f", bg="#ffffff",
                            padx=10, pady=8)
        ctx.pack(fill="x", padx=14, pady=(10, 12))

        self._fv_label = tk.Label(ctx, text="", anchor="w", justify="left",
                                  bg="#ffffff", font=("DejaVu Sans", 9),
                                  wraplength=1100)
        self._fv_label.pack(fill="x", pady=(0, 4))
        self._fq_label = tk.Label(ctx, text="", anchor="w", justify="left",
                                  bg="#ffffff", font=("DejaVu Sans", 9),
                                  wraplength=1100)
        self._fq_label.pack(fill="x", pady=(0, 4))

        tk.Label(ctx, text="Examiner Notes (included in final report):",
                 font=("DejaVu Sans", 9, "italic"),
                 bg="#ffffff", fg="#555", anchor="w"
                 ).pack(fill="x", pady=(6, 2))
        self._notes = tk.Text(ctx, height=3, wrap="word",
                              font=("DejaVu Sans", 9),
                              bg="#fffef5", fg="#222",
                              relief="solid", bd=1)
        self._notes.pack(fill="x")
        self._notes.bind("<FocusOut>", self._on_notes_blur)

    # ------------------------------------------------------------------
    def show_placeholder(self) -> None:
        self._title_var.set("Windows Registry Examiner")  # BRANDING: title
        self._meta_var.set("Select an artifact from the sidebar to begin.")
        self._summary_var.set(
            "All examined registry data appears here in human-readable form. "
            "Encoded values (Base64, hexadecimal, ROT-13, FILETIME, UTF-16) "
            "are decoded automatically. Suspicious findings are highlighted "
            "by severity. Your every action is recorded in the audit log "
            "and included in the final forensic report.")
        self._summary_label.configure(bg="#eef3f8", fg="#1f3a5f")
        self._tree["columns"] = ()
        self._tree.delete(*self._tree.get_children())
        self._iid_to_row_idx.clear()
        self._set_detail_text("(nothing selected)")
        self._fv_label.configure(text="")
        self._fq_label.configure(text="")
        self._set_notes("", read_only=True)

    def display(self, definition: ArtifactDefinition,
                result: ArtifactResult) -> None:
        self._capture_current_notes()

        self._current_definition = definition
        self._current_result = result

        self._title_var.set(definition.name)
        meta_parts = [f"Category: {definition.category}"]
        if definition.required_hive.value not in ("UNKNOWN",):
            meta_parts.append(f"Hive: {definition.required_hive.value}")
        meta_parts.append(f"Key Path: {definition.key_path or '-'}")
        if result.raw_key_last_write:
            meta_parts.append(f"Last Write: {result.raw_key_last_write}")
        self._meta_var.set("    ".join(meta_parts))

        # Summary strip
        if result.error:
            self._summary_label.configure(bg="#fce4e4", fg="#a02020")
            self._summary_var.set(f"Could not extract: {result.error}")
        elif not result.rows:
            self._summary_label.configure(bg="#fff8e0", fg="#7a5b00")
            self._summary_var.set(
                result.summary or "Key was located but contains no values.")
        else:
            self._summary_label.configure(bg="#eef3f8", fg="#1f3a5f")
            self._summary_var.set(
                result.summary or f"{result.row_count} record(s) extracted.")

        # ------- Build column list, with dynamic Interp/Flag suppression
        base_cols: List[str] = list(result.columns)
        if not base_cols and result.rows:
            base_cols = list(result.rows[0].fields.keys())
        base_cols = [str(c) for c in base_cols]

        # Drop base columns that are entirely empty across every row
        _na = frozenset({"", "n/a", "\u2014", "-", "none", "null", "unknown"})

        def _cell(row, col: str) -> str:
            if col == "Interpretation":
                return row.interpretation or ""
            if col == "Flag":
                return row.flag or ""
            return str(row.fields.get(col, ""))

        if result.rows:
            base_cols = [
                col for col in base_cols
                if not all(_cell(r, col).strip().lower() in _na for r in result.rows)
            ]

        any_interp = any((row.interpretation or "").strip() for row in result.rows)
        any_flag = any((row.flag or "").strip() for row in result.rows)

        cols = list(base_cols)
        if any_interp and "Interpretation" not in cols:
            cols.append("Interpretation")
        if any_flag and "Flag" not in cols:
            cols.append("Flag")

        # Reset tree
        self._tree.delete(*self._tree.get_children())
        self._iid_to_row_idx.clear()

        if cols:
            self._tree["columns"] = cols
            for c in cols:
                self._tree.heading(c, text=c)
                width = self._column_width_for(c)
                self._tree.column(c, width=width, anchor="w", stretch=True)

            for idx, row in enumerate(result.rows):
                values: List[str] = []
                for c in cols:
                    if c == "Interpretation":
                        values.append(self._truncate_cell(row.interpretation))
                    elif c == "Flag":
                        values.append(self._truncate_cell(row.flag))
                    else:
                        values.append(self._truncate_cell(row.fields.get(c, "")))
                tags = (row.flag,) if row.flag in _FLAG_COLORS else ()
                iid = str(idx)
                self._tree.insert("", "end", iid=iid, values=values, tags=tags)
                self._iid_to_row_idx[iid] = idx
        else:
            self._tree["columns"] = ()

        self._set_detail_text(
            "Click a row to see its full content here, including the "
            "decoded plain-English interpretation.")

        self._fv_label.configure(
            text=f"Forensic Value: {definition.forensic_value}")
        self._fq_label.configure(
            text=f"Question Answered: {definition.forensic_question}")

        prior = self._notes_by_artifact.get(definition.name, "")
        self._set_notes(prior, read_only=False)

    def show_loading(self, definition: ArtifactDefinition) -> None:
        """Show a 'loading' state for an artifact while it's being parsed."""
        self._capture_current_notes()
        self._current_definition = definition
        self._current_result = None

        self._title_var.set(definition.name)
        meta_parts = [f"Category: {definition.category}"]
        if definition.required_hive.value not in ("UNKNOWN",):
            meta_parts.append(f"Hive: {definition.required_hive.value}")
        meta_parts.append(f"Key Path: {definition.key_path or '-'}")
        self._meta_var.set("    ".join(meta_parts))

        self._summary_label.configure(bg="#eef3f8", fg="#1f3a5f")
        self._summary_var.set(
            "⏳  Parsing event log file — this may take a moment for "
            "large log files...")

        self._tree.delete(*self._tree.get_children())
        self._iid_to_row_idx.clear()
        self._tree["columns"] = ()

        self._set_detail_text("Extraction in progress...")
        self._fv_label.configure(
            text=f"Forensic Value: {definition.forensic_value}")
        self._fq_label.configure(
            text=f"Question Answered: {definition.forensic_question}")

        prior = self._notes_by_artifact.get(definition.name, "")
        self._set_notes(prior, read_only=False)

    # ------------------------------------------------------------------
    def get_notes(self, artifact_name: str) -> str:
        if (self._current_definition
                and self._current_definition.name == artifact_name):
            self._capture_current_notes()
        return self._notes_by_artifact.get(artifact_name, "")

    def get_current_artifact_name(self) -> Optional[str]:
        return self._current_definition.name if self._current_definition else None

    # ------------------------------------------------------------------
    @staticmethod
    def _column_width_for(col_name: str) -> int:
        wide = {"Interpretation", "Description", "Path", "Install Location",
                "Capability Path", "Account Flags", "Key Path",
                "Details", "Application"}
        medium = {"Event Time", "Event Type", "Source IP", "Logon Type",
                  "Severity", "Source", "Computer", "Result", "Status",
                  "User", "Event ID"}
        narrow = {"RID", "Login Count", "Failed Logon Count",
                  "Account Disabled", "Account Locked", "Password Required"}
        if col_name in wide:
            return 280
        if col_name in medium:
            return 140
        if col_name in narrow:
            return 90
        return max(110, min(280, len(col_name) * 11 + 30))

    @staticmethod
    def _truncate_cell(value, max_len: int = 220) -> str:
        s = "" if value is None else str(value)
        if len(s) > max_len:
            return s[:max_len] + " ..."
        return s

    def _on_row_select(self, _event=None) -> None:
        sel = self._tree.selection()
        if not sel or not self._current_result:
            return
        idx = self._iid_to_row_idx.get(sel[0])
        if idx is None or not (0 <= idx < len(self._current_result.rows)):
            return
        row = self._current_result.rows[idx]
        self._set_detail_text(self._format_row_detail(row))

    def _format_row_detail(self, row: ArtifactRow) -> str:
        lines = []
        if row.flag:
            lines.append(f"[ {row.flag} ]")
            lines.append("")
        if row.fields:
            lines.append("Decoded Fields")
            lines.append("--------------")
            width = max((len(k) for k in row.fields.keys()), default=0)
            for k, v in row.fields.items():
                lines.append(f"  {k.ljust(width)} : {v}")
            lines.append("")
        if row.interpretation:
            lines.append("Interpretation")
            lines.append("--------------")
            lines.append(row.interpretation)
        return "\n".join(lines) if lines else "(empty row)"

    def _set_detail_text(self, text: str) -> None:
        self._detail.configure(state="normal")
        self._detail.delete("1.0", tk.END)
        self._detail.insert("1.0", text)
        self._detail.configure(state="disabled")

    def _set_notes(self, text: str, read_only: bool = False) -> None:
        self._notes.configure(state="normal")
        self._notes.delete("1.0", tk.END)
        self._notes.insert("1.0", text)
        if read_only:
            self._notes.configure(state="disabled")

    def _capture_current_notes(self) -> None:
        if not self._current_definition:
            return
        try:
            text = self._notes.get("1.0", tk.END).rstrip("\n")
        except tk.TclError:
            return
        self._notes_by_artifact[self._current_definition.name] = text

    def _on_notes_blur(self, _event=None) -> None:
        if not self._current_definition:
            return
        text = self._notes.get("1.0", tk.END).rstrip("\n")
        prev = self._notes_by_artifact.get(self._current_definition.name, "")
        self._notes_by_artifact[self._current_definition.name] = text
        if text != prev and self._on_notes_changed:
            self._on_notes_changed(self._current_definition.name, text)
