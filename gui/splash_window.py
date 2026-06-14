"""
Splash / Case Intake Window
===========================
First dialog presented when the application starts. Collects the
chain-of-custody preconditions:

    * Examiner name
    * Case name / case number
    * Individual hive files uploaded one at a time, each with its own
      reference SHA-256 hash verified at upload time.

Upload workflow:
    1. Examiner fills in name, case name, and (optionally) case number.
    2. Clicks "Upload Hive File" → selects a file via the file dialog.
    3. A prompt asks for the file's reference SHA-256 hash.
    4. The tool computes sha256sum of the file and compares:
       - Match   → file appears in the list with ✓ and its verified hash.
       - Mismatch→ error message "Wrong hash value" (computed hash is
         NOT revealed).
    5. Steps 2-4 repeat for as many files as needed.
    6. "Begin Analysis" is enabled once at least one file is uploaded
       successfully.  Clicking it opens the main analysis window.

Every step is recorded in the ActionLogger so the chain-of-custody
is complete.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

try:
    from PIL import Image, ImageTk
    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False
from typing import Callable, Dict, List, Optional

from core.action_logger import ActionLogger
from core.hash_verifier import (
    FileIntegrityRecord,
    IntegrityCheckResult,
    is_valid_sha256,
    perform_multi_file_recheck,
    perform_single_file_check,
)


# Update 6: accepted evidence file types (case-insensitive basename match)
_ACCEPTED_HIVE_NAMES = {"sam", "system", "security", "software", "ntuser.dat", "default"}
_ACCEPTED_EVTX_NAMES = {"application.evtx", "system.evtx", "security.evtx"}
_ACCEPTED_ALL = _ACCEPTED_HIVE_NAMES | _ACCEPTED_EVTX_NAMES

_REJECTION_MESSAGE = (
    "WinRegEx accepts only Windows Registry hive files\n"
    "(SAM, SYSTEM, SECURITY, SOFTWARE, NTUSER.DAT, DEFAULT)\n"
    "and Windows Event Logs\n"
    "(Application.evtx, System.evtx, Security.evtx).\n\n"
    "Please select a valid evidence file."
)


def _is_accepted_evidence_file(filename: str) -> bool:
    """Return True if filename matches the accepted evidence file whitelist."""
    return filename.strip().lower() in _ACCEPTED_ALL


class SplashWindow(tk.Toplevel):
    """Modal intake dialog. Returns a SessionContext on success."""

    def __init__(self,
                 master: tk.Tk,
                 logger: ActionLogger,
                 on_ready: Callable[[dict], None]):
        super().__init__(master)
        self._logger = logger
        self._on_ready = on_ready
        self._pre_check: Optional[IntegrityCheckResult] = None
        self._busy = False

        # Per-file integrity records accumulated during upload
        self._file_records: List[FileIntegrityRecord] = []
        # Staging directory where uploaded files are copied
        self._staging_dir: Optional[str] = None
        # Update 3: parsed extraction report JSON content
        self._extraction_report_json: Optional[dict] = None
        # Update 4: hash dictionary from .sha256 file {filename: hash}
        self._hash_dictionary: Dict[str, str] = {}
        # Update 5: integrity verification log entries
        self._verification_log: List[Dict[str, str]] = []

        self.title("WinRegEx - Case Intake")  # BRANDING: title
        self.configure(bg="#f4f6f9")
        # IMPORTANT: do NOT call resizable(False, False) here. On most
        # Linux window managers that hint removes the maximize button
        # from the title bar. The splash must be resizable so the user
        # can maximize it.
        self.resizable(True, True)
        # NOTE: do NOT call self.transient(master) here. On Mutter
        # (GNOME / Ubuntu 22+), a Toplevel marked transient to a
        # withdrawn parent is silently NOT mapped by the compositor -
        # the splash exists but never appears on screen. We rely on
        # grab_set() below to keep the splash modal, and on
        # attributes('-topmost', True) in main.py to ensure it surfaces
        # above any other window. The splash is therefore an
        # independent top-level window with full title-bar decorations
        # (minimize / maximize / close all functional).
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Sized big enough that the Begin Analysis / Cancel buttons are
        # visible without scrolling on a 768-tall screen.
        w, h = 780, 780
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        # Don't request more than the screen has
        w = min(w, sw - 40)
        h = min(h, sh - 80)
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")
        self.minsize(640, 640)

        # Maximize the splash on launch so the buttons are always
        # visible and the layout has full room.
        self.after(50, self._maximise_self)

        self._build_ui()
        self._examiner_entry.focus_set()

    def _maximise_self(self) -> None:
        try:
            import sys
            if sys.platform.startswith("win"):
                self.state("zoomed")
                return
            try:
                self.attributes("-zoomed", True)
                return
            except tk.TclError:
                pass
            sw = self.winfo_screenwidth()
            sh = self.winfo_screenheight()
            self.geometry(f"{sw}x{sh}+0+0")
        except tk.TclError:
            pass

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        # --- Header banner ---------------------------------------------
        header = tk.Frame(self, bg="#1f3a5f", height=70)
        header.pack(side="top", fill="x")




        tk.Label(header, text="Windows Registry Examiner",  # BRANDING: title
                 font=("DejaVu Sans", 16, "bold"),
                 fg="white", bg="#1f3a5f").pack(anchor="w", padx=20, pady=(12, 0))
        tk.Label(header, text="Offline Windows Registry analysis - Case Intake",
                 font=("DejaVu Sans", 9),
                 fg="#cfdcec", bg="#1f3a5f").pack(anchor="w", padx=20)

        # --- Buttons (PINNED TO BOTTOM) -------------------------------
        btnbar = tk.Frame(self, bg="#f4f6f9", padx=24, pady=12,
                          relief="solid", bd=0,
                          highlightthickness=1,
                          highlightbackground="#cfdcec")
        btnbar.pack(side="bottom", fill="x")
        ttk.Button(btnbar, text="Cancel", command=self._on_close,
                   width=12).pack(side="right", padx=4)
        self._begin_btn = ttk.Button(
            btnbar, text="Begin Analysis", command=self._begin_clicked,
            width=18,
        )
        self._begin_btn.pack(side="right", padx=4)
        self._begin_btn.configure(state="disabled")

        # --- Form (FILLS THE REMAINING SPACE) -------------------------
        form = tk.Frame(self, bg="#f4f6f9", padx=24, pady=20)
        form.pack(side="top", fill="both", expand=True)

        instr = ("Provide the case metadata below. Upload an extraction "
                 "hashes file (.sha256) to enable automatic integrity "
                 "verification, then upload evidence files one at a time.")
        tk.Label(form, text=instr, wraplength=680, justify="left",
                 font=("DejaVu Sans", 9), bg="#f4f6f9", fg="#333"
                 ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 14))

        def _label(text: str, row: int) -> None:
            tk.Label(form, text=text, font=("DejaVu Sans", 10, "bold"),
                     bg="#f4f6f9", fg="#1f3a5f"
                     ).grid(row=row, column=0, sticky="w", pady=(8, 2))

        _label("Examiner Name", 1)
        self._examiner_entry = ttk.Entry(form, width=60)
        self._examiner_entry.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(0, 4))

        _label("Case Name", 3)
        self._case_entry = ttk.Entry(form, width=60)
        self._case_entry.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(0, 4))

        _label("Case Number", 5)
        self._case_number_entry = ttk.Entry(form, width=60)
        self._case_number_entry.grid(row=6, column=0, columnspan=3, sticky="ew", pady=(0, 4))

        # --- Update 3: Extraction Report (JSON) upload ---
        _label("Extraction Report (JSON)", 7)
        json_row = tk.Frame(form, bg="#f4f6f9")
        json_row.grid(row=8, column=0, columnspan=3, sticky="ew", pady=(0, 4))
        self._json_path_var = tk.StringVar(value="(no file selected)")
        ttk.Button(json_row, text="Browse...",
                   command=self._browse_extraction_json, width=12
                   ).pack(side="left", padx=(0, 8))
        tk.Label(json_row, textvariable=self._json_path_var,
                 font=("DejaVu Sans", 9), bg="#f4f6f9", fg="#444",
                 anchor="w").pack(side="left", fill="x", expand=True)

        # --- Update 4: Extraction Hashes File (.sha256) upload ---
        _label("Extraction Hashes File", 9)
        hash_row = tk.Frame(form, bg="#f4f6f9")
        hash_row.grid(row=10, column=0, columnspan=3, sticky="ew", pady=(0, 4))
        self._hash_path_var = tk.StringVar(value="(no file selected)")
        ttk.Button(hash_row, text="Browse...",
                   command=self._browse_hash_file, width=12
                   ).pack(side="left", padx=(0, 8))
        tk.Label(hash_row, textvariable=self._hash_path_var,
                 font=("DejaVu Sans", 9), bg="#f4f6f9", fg="#444",
                 anchor="w").pack(side="left", fill="x", expand=True)

        form.columnconfigure(0, weight=1)

        # --- Upload section --------------------------------------------
        upload_frame = tk.LabelFrame(
            form, text=" Evidence Files ",
            font=("DejaVu Sans", 10, "bold"),
            fg="#1f3a5f", bg="#f4f6f9",
            padx=10, pady=8)
        upload_frame.grid(row=11, column=0, columnspan=3,
                          sticky="nsew", pady=(12, 6))
        form.rowconfigure(11, weight=1)

        tk.Label(upload_frame,
                 text="Upload evidence files one at a time. Integrity is "
                      "verified automatically against the loaded hash file.",
                 font=("DejaVu Sans", 8, "italic"),
                 bg="#f4f6f9", fg="#666", wraplength=640, justify="left",
                 anchor="w").pack(fill="x", pady=(0, 6))

        self._upload_btn = ttk.Button(
            upload_frame, text="Upload Evidence File...",
            command=self._upload_file, width=22)
        self._upload_btn.pack(anchor="w", pady=(0, 8))

        # Scrollable list of uploaded files
        list_frame = tk.Frame(upload_frame, bg="#ffffff",
                              relief="solid", bd=1)
        list_frame.pack(fill="both", expand=True)
        list_frame.rowconfigure(0, weight=1)
        list_frame.columnconfigure(0, weight=1)

        cols = ("status", "filename", "hash")
        self._file_tree = ttk.Treeview(
            list_frame, columns=cols, show="headings", height=6)
        self._file_tree.grid(row=0, column=0, sticky="nsew")

        self._file_tree.heading("status", text="Status")
        self._file_tree.heading("filename", text="File Name")
        self._file_tree.heading("hash", text="Integrity Result")
        self._file_tree.column("status", width=60, anchor="center",
                               stretch=False)
        self._file_tree.column("filename", width=250, anchor="w")
        self._file_tree.column("hash", width=420, anchor="w")

        # Color tags for the file list
        self._file_tree.tag_configure("ok", background="#dff5dd",
                                       foreground="#1a6b1a")
        self._file_tree.tag_configure("fail", background="#fce4e4",
                                       foreground="#a02020")
        self._file_tree.tag_configure("warn", background="#fff3cd",
                                       foreground="#7a5b00")

        vsb = ttk.Scrollbar(list_frame, orient="vertical",
                            command=self._file_tree.yview)
        vsb.grid(row=0, column=1, sticky="ns")
        self._file_tree.configure(yscrollcommand=vsb.set)

        self._file_count_var = tk.StringVar(value="No files uploaded yet.")
        tk.Label(upload_frame, textvariable=self._file_count_var,
                 font=("DejaVu Sans", 8, "italic"),
                 bg="#f4f6f9", fg="#444", anchor="w"
                 ).pack(fill="x", pady=(6, 0))

        # --- Status banner ---------------------------------------------
        self._status_var = tk.StringVar(value="Ready. Upload evidence files to begin.")
        self._status_label = tk.Label(
            form, textvariable=self._status_var,
            wraplength=640, justify="left",
            font=("DejaVu Sans", 9),
            bg="#eef3f8", fg="#1f3a5f",
            relief="solid", bd=1, padx=10, pady=8,
        )
        self._status_label.grid(row=12, column=0, columnspan=3,
                                sticky="ew", pady=(10, 6))

        self._progress = ttk.Progressbar(form, mode="indeterminate", length=580)
        self._progress.grid(row=13, column=0, columnspan=3, sticky="ew", pady=(0, 4))
        self._progress.grid_remove()

    # ------------------------------------------------------------------
    # Update 3: Extraction Report (JSON) browse
    # ------------------------------------------------------------------
    def _browse_extraction_json(self) -> None:
        """Select and parse a JSON extraction report."""
        path = filedialog.askopenfilename(
            parent=self,
            title="Select extraction report (JSON)",
            filetypes=[("JSON files", "*.json")],
        )
        if not path:
            return
        try:
            import json
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self._extraction_report_json = data
            key_count = len(data) if isinstance(data, dict) else 0
            fname = os.path.basename(path)
            self._json_path_var.set(
                f"✓ {fname} ({key_count} top-level keys)")
            self._set_status(
                f"Extraction report loaded: {fname}", "success")
        except Exception as exc:  # noqa: BLE001
            self._json_path_var.set("(load failed)")
            self._set_status(f"Failed to parse JSON: {exc}", "error")

    # ------------------------------------------------------------------
    # Update 4: Extraction Hashes File (.sha256) browse
    # ------------------------------------------------------------------
    def _browse_hash_file(self) -> None:
        """Select and parse a .sha256 hash file."""
        path = filedialog.askopenfilename(
            parent=self,
            title="Select extraction hashes file (.sha256)",
            filetypes=[("SHA256 hash files", "*.sha256"),
                       ("All files", "*")],
        )
        if not path:
            return
        try:
            loaded = {}
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or ":" not in line:
                        continue
                    parts = line.rsplit(":", 1)
                    if len(parts) == 2:
                        fname = parts[0].strip()
                        hval = parts[1].strip().lower()
                        if len(hval) == 64 and is_valid_sha256(hval):
                            loaded[fname] = hval
            self._hash_dictionary = loaded
            self._hash_path_var.set(
                f"✓ {os.path.basename(path)} "
                f"({len(loaded)} file hashes loaded)")
            self._set_status(
                f"{len(loaded)} file hashes loaded from "
                f"{os.path.basename(path)}", "success")
        except Exception as exc:  # noqa: BLE001
            self._hash_path_var.set("(load failed)")
            self._set_status(f"Failed to parse hash file: {exc}", "error")

    # ------------------------------------------------------------------
    # File upload workflow (Updates 5 + 6)
    # ------------------------------------------------------------------
    def _upload_file(self) -> None:
        """Open a file dialog, validate file type, auto-verify integrity."""
        if self._busy:
            return

        file_path = filedialog.askopenfilename(
            parent=self,
            title="Select an evidence file",
            filetypes=[("All files", "*"),
                       ("Registry hive", "*.DAT *.dat"),
                       ("Event log", "*.evtx")],
        )
        if not file_path:
            return

        basename = os.path.basename(file_path)

        # Update 6: validate filename against accepted list
        if not _is_accepted_evidence_file(basename):
            messagebox.showerror(
                "Unsupported file",
                f"Unsupported file: '{basename}'.\n\n"
                + _REJECTION_MESSAGE,
                parent=self)
            return

        # Check for duplicate
        for rec in self._file_records:
            if basename == rec.file_name:
                messagebox.showwarning(
                    "Duplicate file",
                    f"A file named '{rec.file_name}' has already been "
                    f"uploaded. Please rename it or choose a different file.",
                    parent=self)
                return

        # Update 5: auto-verify — no manual hash prompt
        self._busy = True
        self._upload_btn.configure(state="disabled")
        self._progress.grid()
        self._progress.start(12)
        self._set_status(f"Computing SHA-256 of {basename}...", "info")

        threading.Thread(
            target=self._verify_file_worker,
            args=(file_path,),
            daemon=True).start()

    def _verify_file_worker(self, file_path: str) -> None:
        """Background: compute hash and compare against hash dictionary."""
        from core.hash_verifier import compute_file_sha256
        try:
            computed = compute_file_sha256(file_path)
        except Exception as exc:  # noqa: BLE001
            self.after(0, self._file_verify_error,
                       os.path.basename(file_path), str(exc))
            return
        self.after(0, self._file_verify_done, file_path, computed)

    def _file_verify_error(self, filename: str, message: str) -> None:
        self._busy = False
        self._progress.stop()
        self._progress.grid_remove()
        self._upload_btn.configure(state="normal")
        self._set_status(
            f"Hash computation failed for {filename}: {message}", "error")

    def _file_verify_done(self, original_path: str,
                          computed_hash: str) -> None:
        self._progress.stop()
        self._progress.grid_remove()
        self._busy = False
        self._upload_btn.configure(state="normal")

        basename = os.path.basename(original_path)
        expected = self._hash_dictionary.get(basename)

        # Determine verification result
        if not self._hash_dictionary:
            result_tag, result_icon = "warn", "⚠️"
            result_text = "No hash list loaded — integrity check skipped"
            matched, ref_hash = True, ""
        elif expected is None:
            result_tag, result_icon = "warn", "⚠️"
            result_text = "Hash not found in extraction hashes — cannot verify"
            matched, ref_hash = True, ""
        elif computed_hash.lower() == expected.lower():
            result_tag, result_icon = "ok", "✅"
            result_text = "Integrity verified — hash matches"
            matched, ref_hash = True, expected
        else:
            result_tag, result_icon = "fail", "❌"
            result_text = "Integrity FAILED — hash mismatch"
            matched, ref_hash = False, expected

        # Log verification result
        self._verification_log.append({
            "filename": basename,
            "computed_hash": computed_hash,
            "expected_hash": ref_hash or "(not available)",
            "result": result_text,
        })

        if matched:
            staging = self._ensure_staging_dir()
            dest = os.path.join(staging, basename)
            try:
                shutil.copy2(original_path, dest)
            except Exception as exc:  # noqa: BLE001
                self._set_status(f"Failed to copy file: {exc}", "error")
                return

            record = FileIntegrityRecord(
                file_name=basename, file_path=dest,
                reference_hash=ref_hash, computed_hash=computed_hash,
                matched=True, verified_at_utc="",
            )
            self._file_records.append(record)
            self._file_tree.insert(
                "", "end",
                values=(result_icon, basename, result_text),
                tags=(result_tag,))
            self._set_status(
                f"{result_icon} {basename} — {result_text}. "
                f"Upload another file or click 'Begin Analysis'.",
                "success" if result_tag == "ok" else "warn")
        else:
            self._file_tree.insert(
                "", "end",
                values=(result_icon, basename, result_text),
                tags=(result_tag,))
            self._set_status(
                f"{result_icon} {basename} — {result_text}", "error")
            messagebox.showerror(
                "Integrity FAILED",
                f"The SHA-256 hash of '{basename}' does NOT match "
                f"the expected hash from the extraction hashes file.\n\n"
                f"The file was NOT added to the evidence set.",
                parent=self)

        ok_count = len(self._file_records)
        self._file_count_var.set(
            f"{ok_count} file(s) uploaded and ready for analysis.")
        if ok_count > 0:
            self._begin_btn.configure(state="normal")

    def _ensure_staging_dir(self) -> str:
        """Create (once) a temporary staging directory for uploaded files."""
        if self._staging_dir and os.path.isdir(self._staging_dir):
            return self._staging_dir
        self._staging_dir = tempfile.mkdtemp(prefix="reghive_evidence_")
        return self._staging_dir



    # ------------------------------------------------------------------
    # Status helpers
    # ------------------------------------------------------------------
    def _set_status(self, text: str, kind: str = "info") -> None:
        self._status_var.set(text)
        bg = {"info": "#eef3f8", "success": "#dff5dd",
              "warn": "#fff3cd", "error": "#fce4e4"}.get(kind, "#eef3f8")
        fg = {"info": "#1f3a5f", "success": "#1a6b1a",
              "warn": "#7a5b00", "error": "#a02020"}.get(kind, "#1f3a5f")
        self._status_label.configure(bg=bg, fg=fg)

    # ------------------------------------------------------------------
    # Begin Analysis
    # ------------------------------------------------------------------
    def _begin_clicked(self) -> None:
        if self._busy:
            return
        examiner = self._examiner_entry.get().strip()
        case = self._case_entry.get().strip()
        case_number = self._case_number_entry.get().strip()

        if not examiner:
            self._set_status("Examiner name is required.", "error")
            return
        if not case:
            self._set_status("Case name is required.", "error")
            return
        if not self._file_records:
            self._set_status(
                "At least one hive file must be uploaded and verified.",
                "error")
            return

        # Configure logger and record acquisition metadata
        self._logger.set_case_metadata(case, examiner)
        self._logger.log_case_opened(case, examiner)

        # Build a composite pre-check from all uploaded files
        self._busy = True
        self._begin_btn.configure(state="disabled")
        self._upload_btn.configure(state="disabled")
        self._progress.grid()
        self._progress.start(12)
        self._set_status(
            "Building composite integrity check ... please wait.", "info")

        threading.Thread(
            target=self._run_pre_check,
            args=(examiner, case, case_number),
            daemon=True).start()

    def _run_pre_check(self, examiner: str, case: str,
                       case_number: str) -> None:
        try:
            check = perform_multi_file_recheck(
                self._file_records, stage="pre-analysis")
        except Exception as exc:  # noqa: BLE001
            self.after(0, self._pre_check_error, str(exc))
            return
        self.after(0, self._pre_check_done, check)

    def _pre_check_error(self, message: str) -> None:
        self._busy = False
        self._progress.stop()
        self._progress.grid_remove()
        self._begin_btn.configure(state="normal")
        self._upload_btn.configure(state="normal")
        self._set_status(f"Integrity check failed: {message}", "error")

    def _pre_check_done(self, check: IntegrityCheckResult) -> None:
        self._progress.stop()
        self._progress.grid_remove()
        self._pre_check = check
        file_count = len(self._file_records)
        folder = self._staging_dir or "(individual files)"

        self._logger.log_folder_imported(folder, file_count)
        self._logger.log_pre_check(check.matched, check.computed_hash,
                                   check.reference_hash)

        if check.matched:
            self._set_status(
                f"Integrity verified: {file_count} file(s) checked. "
                f"All hashes match. Opening main analysis window...",
                "success")
            self.after(800, self._finish_success)
        else:
            self._busy = False
            self._upload_btn.configure(state="normal")
            # Log the integrity failure for the audit trail
            self._logger.log_integrity_failure(
                reference_hash=check.reference_hash,
                computed_hash=check.computed_hash,
                folder_path=self._staging_dir or "(individual files)",
                stage="pre-analysis",
            )
            self._set_status(
                "INTEGRITY CHECK FAILED. Evidence cannot be analysed in "
                "this session. Re-acquire the evidence or verify the "
                "reference hash and try again.",
                "error")
            messagebox.showerror(
                "Integrity Check Failed",
                "Integrity check FAILED. Evidence cannot be analysed in "
                "this session. Re-acquire the evidence or verify the "
                "reference hash and try again.",
                parent=self,
            )
            # Reset to input state: clear uploaded files so the examiner
            # can correct hashes and re-upload.
            self._file_records.clear()
            for item in self._file_tree.get_children():
                self._file_tree.delete(item)
            self._file_count_var.set("No files uploaded yet.")
            self._begin_btn.configure(state="disabled")

    def _finish_success(self) -> None:
        folder = self._staging_dir or "(individual files)"
        ctx = {
            "examiner": self._examiner_entry.get().strip(),
            "case_name": self._case_entry.get().strip(),
            "case_number": self._case_number_entry.get().strip(),
            "reference_hash": "",  # no single reference hash in per-file mode
            "evidence_folder": folder,
            "pre_check": self._pre_check,
            "file_records": list(self._file_records),
            # Update 3: extraction report JSON
            "extraction_report_json": self._extraction_report_json,
            # Update 4/5: verification log
            "verification_log": list(self._verification_log),
        }
        self.grab_release()
        self.destroy()
        self._on_ready(ctx)

    def _on_close(self) -> None:
        if messagebox.askyesno(
                "Cancel intake",
                "Cancel and exit the application?",
                parent=self):
            self._logger.log_application_exit()
            self.master.destroy()
