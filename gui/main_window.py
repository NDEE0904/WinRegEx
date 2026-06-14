"""
Main Analysis Window
====================
The primary forensic-analysis interface, opened after a successful
pre-analysis hash check.

Layout:
    +------------------------------------------------------------------+
    |  Toolbar:  Case info  |  Import Hive  |  Export PDF/CSV/JSON     |
    +-----------------+------------------------------------------------+
    | Sidebar:        | Artifact View                                  |
    |  9 categories   |  - Header                                      |
    |  collapsible    |  - Findings table (color-flagged)              |
    |  All 36 hard-   |  - Selected row detail                         |
    |  coded artifacts|  - Forensic context + examiner notes           |
    +-----------------+------------------------------------------------+
    |  Action Log: live-updating audit trail                            |
    +------------------------------------------------------------------+

Examiner actions captured automatically:
    * ARTIFACT_SELECTED      - every click in the sidebar
    * ARTIFACT_VIEWED        - data successfully extracted
    * ARTIFACT_ERROR         - extraction failed
    * EXAMINER_NOTE          - notes added/changed
    * HIVE_LOADED            - new hive imported during the session
    * REPORT_EXPORTED        - PDF/CSV/JSON written
    * POST_INTEGRITY_PASS    - revalidation succeeded
    * POST_INTEGRITY_FAIL    - revalidation failed (report blocked)

The post-analysis hash check is mandatory before any export. If it
fails, the user is shown a clear error and given the choice to
override - the override is itself logged.
"""

from __future__ import annotations

import os
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Dict, List, Optional

try:
    from PIL import Image, ImageTk
    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False

from core.action_logger import ActionLogger, LogEntry
from core.artifact_definitions import (
    ALL_ARTIFACTS,
    ArtifactDefinition,
    ArtifactResult,
    ArtifactRow,
    EVTX_ARTIFACTS,
    HiveType,
    list_artifacts_by_category,
    parse_application_log,
    parse_security_log,
    parse_system_log,
)
from core.hash_verifier import (
    FileIntegrityRecord,
    IntegrityCheckResult,
    perform_integrity_check,
    perform_multi_file_recheck,
)
from core.registry_parser import HiveRegistry, RegistryUnavailable
from core.report_generator import (
    ExaminedArtifact,
    LoadedHiveSummary,
    PDFUnavailable,
    build_bundle_from_session,
    export_csv,
    export_json,
    export_pdf,
)

from gui.artifact_view import ArtifactView


# Map evtx canonical filenames to their extractor callables
_EVTX_EXTRACTORS = {
    "System.evtx":      parse_system_log,
    "Security.evtx":    parse_security_log,
    "Application.evtx": parse_application_log,
}


class MainWindow:
    """Top-level controller for the analysis interface."""

    def __init__(self, root: tk.Tk, logger: ActionLogger, ctx: dict):
        self._root = root
        self._logger = logger
        self._ctx = ctx
        self._examiner: str = ctx["examiner"]
        self._case_name: str = ctx["case_name"]
        self._case_number: str = ctx.get("case_number", "")
        self._reference_hash: str = ctx.get("reference_hash", "")
        self._evidence_folder: str = ctx["evidence_folder"]
        self._pre_check: IntegrityCheckResult = ctx["pre_check"]
        self._post_check: Optional[IntegrityCheckResult] = None
        # Per-file integrity records from the splash upload workflow
        self._file_records: List[FileIntegrityRecord] = ctx.get(
            "file_records", [])
        # Update 3: extraction report JSON for report generation
        self._extraction_report_json: Optional[dict] = ctx.get(
            "extraction_report_json")
        # Update 5: verification log for report generation
        self._verification_log: list = ctx.get("verification_log", [])

        self._registry = HiveRegistry()
        # cache: artifact_name -> ExaminedArtifact (so we know what was viewed)
        self._examined: Dict[str, ExaminedArtifact] = {}
        # evtx file paths discovered in the evidence folder
        self._evtx_paths: Dict[str, str] = {}
        # Summary records of every successfully-classified hive, used in
        # the Executive Summary so misclassifications are visible.
        self._loaded_hive_summaries: List[LoadedHiveSummary] = []
        # Track the artifact currently being parsed in the background so
        # a late-arriving result does not silently overwrite a different
        # artifact that the examiner navigated to in the meantime.
        self._pending_artifact: Optional[str] = None

        self._build_ui()
        self._logger.add_listener(self._on_log_entry)
        # Auto-load hives + evtx files from the evidence folder
        self._auto_load_evidence()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        title_bits = [f"Case: {self._case_name}"]
        if self._case_number:
            title_bits.append(f"#{self._case_number}")
        title_bits.append(f"Examiner: {self._examiner}")
        self._root.title(
            "WinRegEx  -  " + "  ".join(title_bits))  # BRANDING: title
        # NB: do NOT call self._root.geometry("1280x820") here - that
        # would undo the maximize applied by main._maximise_window().
        # We only set a minsize so the window can't be shrunk below
        # something sensible.
        self._root.minsize(1100, 700)
        self._root.configure(bg="#f4f6f9")

        self._build_toolbar()
        self._build_main_area()
        self._build_action_log_pane()

        # Re-apply maximize AFTER all widgets are packed - this ensures
        # the toolbar / action-log pane / sidebar all participate in the
        # full-screen layout instead of being clipped to the small
        # original geometry.
        self._root.after(80, self._reapply_maximise)

    def _reapply_maximise(self) -> None:
        try:
            import sys
            if sys.platform.startswith("win"):
                self._root.state("zoomed")
                return
            try:
                self._root.attributes("-zoomed", True)
                return
            except tk.TclError:
                pass
            sw = self._root.winfo_screenwidth()
            sh = self._root.winfo_screenheight()
            self._root.geometry(f"{sw}x{sh}+0+0")
        except tk.TclError:
            pass

    def _build_toolbar(self) -> None:
        bar = tk.Frame(self._root, bg="#1f3a5f", height=56)
        bar.pack(fill="x")
        bar.pack_propagate(False)



        # Left: case/examiner banner
        left = tk.Frame(bar, bg="#1f3a5f")
        left.pack(side="left", fill="y", padx=14, pady=6)
        tk.Label(left, text="Windows Registry Examiner",  # BRANDING: title
                 font=("DejaVu Sans", 12, "bold"),
                 fg="white", bg="#1f3a5f").pack(anchor="w")
        case_line = f"Case: {self._case_name}"
        if self._case_number:
            case_line += f"  (#{self._case_number})"
        case_line += f"    Examiner: {self._examiner}"
        tk.Label(left,
                 text=case_line,
                 font=("DejaVu Sans", 8),
                 fg="#cfdcec", bg="#1f3a5f").pack(anchor="w")

        # Right: action buttons
        right = tk.Frame(bar, bg="#1f3a5f")
        right.pack(side="right", fill="y", padx=10, pady=10)

        def _btn(text, cmd, color="#e9eef5"):
            return tk.Button(
                right, text=text, command=cmd,
                font=("DejaVu Sans", 9, "bold"),
                bg=color, fg="#1f3a5f",
                activebackground="#cfdcec",
                relief="flat", bd=0, padx=12, pady=6,
                cursor="hand2",
            )


        _btn("Export PDF",  lambda: self._export("pdf"),
             color="#a8d8a8").pack(side="left", padx=4)
        _btn("Export CSV",  lambda: self._export("csv"),
             color="#a8d8a8").pack(side="left", padx=4)
        _btn("Export JSON", lambda: self._export("json"),
             color="#a8d8a8").pack(side="left", padx=4)

    def _build_main_area(self) -> None:
        body = tk.PanedWindow(self._root, orient="horizontal",
                              sashrelief="raised", sashwidth=4,
                              bg="#cfd5dc")
        body.pack(fill="both", expand=True)

        # ---- Left: sidebar with categories ---------------------------
        side_outer = tk.Frame(body, bg="#ffffff")
        body.add(side_outer, minsize=280, width=320)

        tk.Label(side_outer, text="Forensic Artifacts",
                 font=("DejaVu Sans", 11, "bold"),
                 bg="#ffffff", fg="#1f3a5f", anchor="w",
                 padx=10, pady=8).pack(fill="x")

        sidebar_frame = tk.Frame(side_outer, bg="#ffffff")
        sidebar_frame.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        sidebar_frame.rowconfigure(0, weight=1)
        sidebar_frame.columnconfigure(0, weight=1)

        self._sidebar = ttk.Treeview(sidebar_frame, show="tree",
                                     selectmode="browse")
        self._sidebar.grid(row=0, column=0, sticky="nsew")
        sb = ttk.Scrollbar(sidebar_frame, orient="vertical",
                           command=self._sidebar.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self._sidebar.configure(yscrollcommand=sb.set)
        self._sidebar.bind("<<TreeviewSelect>>", self._on_artifact_clicked)

        # Map: tree iid -> ArtifactDefinition
        self._iid_to_def: Dict[str, ArtifactDefinition] = {}
        self._populate_sidebar()

        # Hive-status strip below sidebar
        self._hive_status_var = tk.StringVar(value="No hives loaded.")
        tk.Label(side_outer, textvariable=self._hive_status_var,
                 font=("DejaVu Sans", 8, "italic"),
                 bg="#eef3f8", fg="#444",
                 anchor="w", justify="left",
                 wraplength=300, padx=10, pady=8
                 ).pack(fill="x", side="bottom")

        # ---- Right: artifact view -----------------------------------
        right_outer = tk.Frame(body, bg="#ffffff")
        body.add(right_outer, minsize=600)
        self._artifact_view = ArtifactView(
            right_outer, on_notes_changed=self._on_notes_changed)
        self._artifact_view.pack(fill="both", expand=True)

    def _populate_sidebar(self) -> None:
        by_cat = list_artifacts_by_category()
        for cat_name in sorted(by_cat.keys()):
            cat_iid = self._sidebar.insert("", "end", text=cat_name, open=True)
            for art in by_cat[cat_name]:
                node = self._sidebar.insert(cat_iid, "end", text=art.name)
                self._iid_to_def[node] = art

    def _build_action_log_pane(self) -> None:
        wrap = tk.Frame(self._root, bg="#f4f6f9", height=170)
        wrap.pack(fill="x", side="bottom")
        wrap.pack_propagate(False)

        bar = tk.Frame(wrap, bg="#1f3a5f", height=26)
        bar.pack(fill="x")
        tk.Label(bar, text="  Action Log  -  every action below is "
                           "recorded in the final report",
                 font=("DejaVu Sans", 9, "bold"),
                 fg="white", bg="#1f3a5f", anchor="w"
                 ).pack(fill="x", side="left", padx=6, pady=4)
        self._log_count_var = tk.StringVar(value="0 entries")
        tk.Label(bar, textvariable=self._log_count_var,
                 font=("DejaVu Sans", 9),
                 fg="#cfdcec", bg="#1f3a5f"
                 ).pack(side="right", padx=10)

        log_frame = tk.Frame(wrap, bg="#ffffff")
        log_frame.pack(fill="both", expand=True, padx=6, pady=6)
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)

        cols = ("seq", "ts", "action", "desc")
        self._log_tree = ttk.Treeview(log_frame, columns=cols,
                                      show="headings", height=6)
        self._log_tree.grid(row=0, column=0, sticky="nsew")
        for c, hd, w in (("seq", "#", 50),
                         ("ts", "Timestamp (Local)", 190),
                         ("action", "Action", 180),
                         ("desc", "Description", 700)):
            self._log_tree.heading(c, text=hd)
            self._log_tree.column(c, width=w, anchor="w", stretch=(c == "desc"))

        vs = ttk.Scrollbar(log_frame, orient="vertical",
                           command=self._log_tree.yview)
        vs.grid(row=0, column=1, sticky="ns")
        self._log_tree.configure(yscrollcommand=vs.set)

    # ------------------------------------------------------------------
    # Evidence loading
    # ------------------------------------------------------------------
    def _auto_load_evidence(self) -> None:
        """Auto-detect and load all hive files + evtx files from the folder."""
        try:
            results = self._registry.load_folder(self._evidence_folder)
        except RegistryUnavailable as exc:
            messagebox.showerror(
                "Missing dependency", str(exc), parent=self._root)
            return
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror(
                "Could not scan folder",
                f"Failed to scan evidence folder:\n{exc}",
                parent=self._root)
            return

        loaded_lines: List[str] = []
        for r in results:
            if r.loaded_ok:
                trace = (r.classification.describe()
                         if r.classification else "via legacy detector")
                # Log a single classification line per loaded hive so
                # misclassifications are never silent (per spec).
                self._logger.log_hive_loaded(
                    r.hive_type.value,
                    f"{r.file_path}  ({trace})")
                loaded_lines.append(
                    f"[OK]  {r.hive_type.value:<12}  {r.file_name}  ({trace})")
                # Capture the classification metadata for the Executive
                # Summary - filename + classified type + how we decided.
                self._loaded_hive_summaries.append(LoadedHiveSummary(
                    file_name=r.file_name,
                    file_path=r.file_path,
                    hive_type=r.hive_type.value,
                    classification_method=(r.classification.method
                                           if r.classification else ""),
                    classification_signal=(r.classification.matched_signal
                                           if r.classification else ""),
                ))
            else:
                # Failed loads must also surface a clear message
                self._logger.log_artifact_error(
                    f"hive load: {r.file_name}",
                    r.error or "load failed")
                loaded_lines.append(
                    f"[!]   {r.file_name}  -  {r.error or 'load failed'}")

        # Discover evtx files separately
        ev_count = 0
        try:
            for fp in Path(self._evidence_folder).rglob("*.evtx"):
                self._evtx_paths[fp.name] = str(fp)
                ev_count += 1
                self._logger.log_hive_loaded("EVTX", str(fp))
        except Exception:
            pass

        if loaded_lines:
            self._hive_status_var.set(
                f"Loaded {len(self._registry.loaded_types())} hive(s) + "
                f"{ev_count} event-log file(s).\n"
                + "\n".join(loaded_lines[:6])
                + ("\n..." if len(loaded_lines) > 6 else ""))
        else:
            self._hive_status_var.set(
                f"No registry hive files were detected in "
                f"{self._evidence_folder}.")



    # ------------------------------------------------------------------
    # Sidebar selection -> extraction
    # ------------------------------------------------------------------
    def _on_artifact_clicked(self, _event=None) -> None:
        sel = self._sidebar.selection()
        if not sel:
            return
        iid = sel[0]
        definition = self._iid_to_def.get(iid)
        if definition is None:
            return  # category header was clicked

        self._logger.log_examiner_note(definition.name,
                                       "Artifact selected from sidebar.")

        # Decide: registry-hive artifact or event-log artifact?
        is_evtx_artifact = (
            definition.required_hive == HiveType.UNKNOWN
            and definition.key_path.lower().endswith(".evtx")
        )
        if is_evtx_artifact:
            self._extract_evtx(definition)
        else:
            self._extract_hive(definition)

    def _extract_hive(self, definition: ArtifactDefinition) -> None:
        hive = self._registry.get(definition.required_hive)
        if hive is None or not hive.loaded_ok:
            result = ArtifactResult(
                artifact_name=definition.name,
                columns=[],
                error=(f"The {definition.required_hive.value} hive has not "
                       f"been loaded. Place it in the evidence folder or "
                       f"use the evidence folder to load it."),
            )
            self._logger.log_artifact_error(definition.name, result.error or "")
            self._record_view(definition, result)
            return

        # Run extraction in a background thread so the UI stays
        # responsive while large hives (e.g. 120 MB SOFTWARE) are
        # parsed.  The pattern mirrors _run_evtx_threaded().
        self._run_hive_threaded(definition, hive)

    def _run_hive_threaded(self, definition: ArtifactDefinition,
                           hive) -> None:
        """Parse a registry artifact off the main thread.

        Threading contract (mirrors the EVTX threading model):
          1. The extractor runs on a daemon worker thread.
          2. Within the first frame the artifact pane shows a
             placeholder row ("Extracting, please wait...").
          3. The worker marshals its result back via ``after(0, ...)``
             so all widget updates happen on the main thread.
          4. If the examiner navigates away before extraction finishes,
             the result is still recorded in ``_examined`` but the
             visible pane is NOT overwritten.
          5. Exceptions are caught and surfaced as ArtifactResult.error.
        """
        self._pending_artifact = definition.name

        # Immediate placeholder so the examiner sees feedback instantly.
        placeholder = ArtifactResult(
            artifact_name=definition.name,
            columns=["Status"],
        )
        placeholder.rows.append(ArtifactRow(
            fields={"Status": "Extracting artifact data, please wait..."}))
        placeholder.summary = (
            "Registry extraction is running in the background. "
            "The UI remains fully responsive.")
        self._artifact_view.display(definition, placeholder)

        result_holder: Dict[str, Optional[ArtifactResult]] = {"v": None}

        def _worker():
            try:
                result_holder["v"] = definition.extractor(hive)
            except Exception as exc:  # noqa: BLE001
                result_holder["v"] = ArtifactResult(
                    artifact_name=definition.name, columns=[],
                    error=f"Extractor crashed: {exc.__class__.__name__}: {exc}")
            self._root.after(0, _on_complete)

        def _on_complete():
            result = result_holder["v"]
            if result is None:
                result = ArtifactResult(
                    artifact_name=definition.name, columns=[],
                    error="Extraction returned no result.")

            # Always record so the report includes this artifact.
            self._record_examined(definition, result)

            # Navigation guard: only update the pane if the examiner
            # is still looking at this artifact.
            if self._pending_artifact == definition.name:
                self._artifact_view.display(definition, result)
                self._pending_artifact = None

        threading.Thread(target=_worker, daemon=True).start()

    def _extract_evtx(self, definition: ArtifactDefinition) -> None:
        target = definition.key_path  # canonical filename
        path = self._evtx_paths.get(target)
        # Fallback: find by case-insensitive match
        if not path:
            for fname, fpath in self._evtx_paths.items():
                if fname.lower() == target.lower():
                    path = fpath
                    break

        if not path:
            result = ArtifactResult(
                artifact_name=definition.name,
                columns=[],
                error=(f"Event log file '{target}' was not found in the "
                       f"evidence folder. Place the .evtx file there and "
                       f"re-open the case, or import it directly."),
            )
            self._logger.log_artifact_error(definition.name, result.error or "")
            self._record_view(definition, result)
            return

        extractor = _EVTX_EXTRACTORS.get(target)
        if not extractor:
            result = ArtifactResult(
                artifact_name=definition.name, columns=[],
                error=f"No parser available for {target}.")
            self._record_view(definition, result)
            return

        # Fast path: if python-evtx is not installed, show the dependency
        # error immediately without spawning a threaded dialog.
        from core.artifact_definitions import _EVTX_AVAILABLE
        if not _EVTX_AVAILABLE:
            result = ArtifactResult(
                artifact_name=definition.name,
                columns=[],
                error=("The 'python-evtx' package is required for .evtx "
                       "parsing. Install with: pip install python-evtx"),
            )
            self._record_view(definition, result)
            return

        # Always run EVTX extraction in a background thread to prevent
        # UI freeze. Large .evtx files can contain millions of records
        # and parsing them blocks the Tk event loop for minutes.
        self._run_evtx_threaded(definition, extractor, path)

    def _run_evtx_threaded(self, definition: ArtifactDefinition,
                           extractor, file_path: str) -> None:
        """Parse an .evtx file off the main thread.

        Threading contract (hard constraints from the spec):
          1. The parser runs on a daemon worker thread, never on the
             UI thread.
          2. Within 100 ms the artifact pane shows a placeholder result
             with a Status column reading "Parsing in background, please
             wait..." so the examiner has immediate visual feedback.
          3. The worker marshals its result back via ``after(0, ...)``
             so all widget updates happen on the main thread.
          4. If the examiner navigates away before the parse completes,
             the result is still recorded in ``_examined`` (so reports
             include it) but the visible pane is NOT overwritten.
          5. Exceptions are caught at the worker boundary and surfaced
             as ``ArtifactResult.error`` with class name only (no
             stack trace shown to the analyst).
        """
        # Track which artifact this background parse is for.
        self._pending_artifact = definition.name

        # Immediately display a placeholder result so the UI responds
        # within the first frame (well under 100 ms).  The placeholder
        # has a "Status" column and a single row reading exactly
        # "Parsing in background, please wait..." per spec.
        placeholder = ArtifactResult(
            artifact_name=definition.name,
            columns=["Status"],
        )
        placeholder.rows.append(ArtifactRow(
            fields={"Status": "Parsing in background, please wait..."}))
        placeholder.summary = (
            "Event log parsing is running in the background. "
            "The UI remains fully responsive.")
        self._artifact_view.display(definition, placeholder)

        result_holder: Dict[str, Optional[ArtifactResult]] = {"v": None}

        def _worker():
            try:
                result_holder["v"] = extractor(file_path)
            except Exception as exc:  # noqa: BLE001
                result_holder["v"] = ArtifactResult(
                    artifact_name=definition.name, columns=[],
                    error=f"{exc.__class__.__name__}: {exc}")
            # Marshal the result back to the UI thread immediately.
            self._root.after(0, _on_complete)

        def _on_complete():
            result = result_holder["v"]
            if result is None:
                result = ArtifactResult(
                    artifact_name=definition.name, columns=[],
                    error="Extraction returned no result.")

            # Always record in _examined so the report includes this
            # artifact even if the examiner navigated away.
            self._record_examined(definition, result)

            # Navigation guard: only update the visible pane if the
            # examiner is still looking at this artifact.
            if self._pending_artifact == definition.name:
                self._artifact_view.display(definition, result)
                self._pending_artifact = None

        threading.Thread(target=_worker, daemon=True).start()

    def _record_examined(self, definition: ArtifactDefinition,
                         result: ArtifactResult) -> None:
        """Log + cache an examined artifact WITHOUT touching the view."""
        hive_label = (definition.required_hive.value
                      if definition.required_hive != HiveType.UNKNOWN
                      else definition.key_path)
        if result.error:
            self._logger.log_artifact_error(definition.name, result.error)
        else:
            self._logger.log_artifact_viewed(
                definition.name, definition.category,
                row_count=result.row_count, hive=hive_label)

        examined = ExaminedArtifact(
            name=definition.name,
            category=definition.category,
            hive_or_log=(definition.required_hive.value
                         if definition.required_hive != HiveType.UNKNOWN
                         else definition.key_path),
            key_path=definition.key_path,
            forensic_value=definition.forensic_value,
            forensic_question=definition.forensic_question,
            examiner_notes=self._artifact_view.get_notes(definition.name),
            result=result,
        )
        self._examined[definition.name] = examined

    def _record_view(self, definition: ArtifactDefinition,
                     result: ArtifactResult) -> None:
        """Log + cache + display an artifact result (synchronous path)."""
        self._record_examined(definition, result)
        self._artifact_view.display(definition, result)

    def _on_notes_changed(self, artifact_name: str, notes: str) -> None:
        self._logger.log_examiner_note(artifact_name, notes or "(cleared)")
        if artifact_name in self._examined:
            self._examined[artifact_name].examiner_notes = notes

    # ------------------------------------------------------------------
    # Action log live updates
    # ------------------------------------------------------------------
    def _on_log_entry(self, entry: LogEntry) -> None:
        # Tk is single-threaded; marshal back to UI thread.
        self._root.after(0, self._append_log_row, entry)

    def _append_log_row(self, entry: LogEntry) -> None:
        try:
            self._log_tree.insert("", "end", values=(
                entry.sequence, entry.timestamp_local,
                entry.action, entry.description,
            ))
            children = self._log_tree.get_children()
            if children:
                self._log_tree.see(children[-1])
            self._log_count_var.set(f"{len(children)} entries")
        except tk.TclError:
            pass  # window may be closing

    # ------------------------------------------------------------------
    # Report export
    # ------------------------------------------------------------------
    def _export(self, fmt: str) -> None:
        if not self._examined:
            messagebox.showwarning(
                "Nothing to export",
                "No artifacts have been viewed yet. Open at least one "
                "artifact from the sidebar before exporting a report.",
                parent=self._root)
            return

        # Capture any in-flight notes from the active artifact
        active_name = self._artifact_view.get_current_artifact_name()
        if active_name and active_name in self._examined:
            self._examined[active_name].examiner_notes = (
                self._artifact_view.get_notes(active_name))

        # ----- POST-ANALYSIS HASH RECHECK -----------------------------
        # This is mandatory - the report must NOT be generated without
        # a fresh integrity check, regardless of which format is requested.
        proceed = self._run_post_check_blocking()
        if not proceed:
            return

        # ----- File save dialog ---------------------------------------
        ext_map = {"pdf": ".pdf", "csv": ".csv", "json": ".json"}
        type_map = {
            "pdf":  [("PDF document", "*.pdf")],
            "csv":  [("CSV spreadsheet", "*.csv")],
            "json": [("JSON report", "*.json")],
        }
        default_name = (f"{self._case_name.replace(' ', '_')}_"
                        f"report{ext_map[fmt]}")
        out_path = filedialog.asksaveasfilename(
            parent=self._root,
            title=f"Save {fmt.upper()} report",
            defaultextension=ext_map[fmt],
            filetypes=type_map[fmt],
            initialfile=default_name,
        )
        if not out_path:
            return

        bundle = build_bundle_from_session(
            case_name=self._case_name,
            examiner=self._examiner,
            reference_hash=self._reference_hash,
            pre_check=self._pre_check,
            post_check=self._post_check,
            examined=list(self._examined.values()),
            logger=self._logger,
            case_number=self._case_number,
            evidence_source=self._evidence_folder,
            loaded_hives=list(self._loaded_hive_summaries),
            examiner_summary_notes="",  # reserved for a future Case Notes UI
        )

        try:
            if fmt == "pdf":
                final = export_pdf(bundle, out_path)
            elif fmt == "csv":
                final = export_csv(bundle, out_path)
            else:
                final = export_json(bundle, out_path)
        except PDFUnavailable as exc:
            messagebox.showerror("Missing dependency", str(exc),
                                 parent=self._root)
            return
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror(
                "Export failed",
                f"Failed to write {fmt.upper()} report:\n{exc}",
                parent=self._root)
            return

        self._logger.log_export(fmt.upper(), final)
        messagebox.showinfo(
            "Report exported",
            f"{fmt.upper()} report saved successfully:\n\n{final}",
            parent=self._root)

    def _run_post_check_blocking(self) -> bool:
        """Run the post-analysis hash check synchronously (with a
        wait dialog). Returns True if export should proceed.
        """
        wait = tk.Toplevel(self._root)
        wait.transient(self._root)
        wait.title("Verifying integrity...")
        wait.configure(bg="#f4f6f9")
        wait.resizable(False, False)
        wait.grab_set()
        ww, wh = 460, 130
        sw, sh = self._root.winfo_screenwidth(), self._root.winfo_screenheight()
        wait.geometry(f"{ww}x{wh}+{(sw - ww) // 2}+{(sh - wh) // 2}")
        tk.Label(wait,
                 text="Re-computing SHA-256 of the evidence files\n"
                      "to confirm no tampering occurred during analysis...",
                 font=("DejaVu Sans", 10), bg="#f4f6f9",
                 justify="center", pady=10
                 ).pack(fill="x", padx=20, pady=(20, 8))
        pb = ttk.Progressbar(wait, mode="indeterminate", length=400)
        pb.pack(padx=20, pady=(0, 14))
        pb.start(12)

        check_holder: Dict[str, Optional[IntegrityCheckResult]] = {"v": None}
        error_holder: Dict[str, Optional[str]] = {"v": None}
        done = threading.Event()

        def _worker():
            try:
                if self._file_records:
                    # Per-file workflow: re-verify each uploaded file
                    check_holder["v"] = perform_multi_file_recheck(
                        self._file_records,
                        stage="post-analysis")
                else:
                    # Fallback: legacy folder workflow
                    check_holder["v"] = perform_integrity_check(
                        self._evidence_folder, self._reference_hash,
                        stage="post-analysis")
            except Exception as exc:  # noqa: BLE001
                error_holder["v"] = f"{exc.__class__.__name__}: {exc}"
            finally:
                done.set()

        threading.Thread(target=_worker, daemon=True).start()

        # Pump the UI while the worker runs
        while not done.is_set():
            self._root.update()
            self._root.after(50)
        pb.stop()
        wait.grab_release()
        wait.destroy()

        if error_holder["v"]:
            messagebox.showerror(
                "Integrity check failed",
                f"Could not compute the post-analysis hash:\n"
                f"{error_holder['v']}",
                parent=self._root)
            return False

        check = check_holder["v"]
        self._post_check = check
        if check is None:
            return False

        self._logger.log_post_check(check.matched, check.computed_hash,
                                    check.reference_hash)

        if check.matched:
            messagebox.showinfo(
                "Integrity verified",
                "Post-analysis hash matches the reference hash. "
                "No tampering detected. Proceeding with report generation.",
                parent=self._root)
            return True

        # Mismatch path
        override = messagebox.askyesno(
            "POST-ANALYSIS HASH MISMATCH",
            "The composite hash of the evidence folder no longer matches "
            "the reference hash recorded at acquisition.\n\n"
            f"Computed:  {check.computed_hash}\n"
            f"Reference: {check.reference_hash}\n\n"
            "This may indicate that the evidence files were modified "
            "during the examination session. Generating a report on "
            "potentially-tampered evidence is strongly discouraged.\n\n"
            "Continue and mark the report as OVERRIDE?",
            icon="warning",
            parent=self._root)
        if override:
            self._logger.log_examiner_note(
                "INTEGRITY",
                "Examiner OVERRODE failed post-analysis integrity check "
                "and elected to generate the report anyway.")
            return True
        return False
