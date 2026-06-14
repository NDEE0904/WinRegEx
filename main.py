"""
Windows Registry Examination (WinRegEx) - Entry Point
"""

from __future__ import annotations

import os
import sys
import traceback
import tkinter as tk
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tkinter import messagebox, ttk

try:
    from PIL import Image, ImageTk
    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# Hardcoded UTC+3 timezone per v1.5.0 spec
TZ_UTC3 = timezone(timedelta(hours=3))


def _log_dir() -> Path:
    base = Path.home() / ".reghive_analyzer" / "logs"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _configure_ttk_style(root: tk.Tk) -> None:
    """Apply the global ttk style. The Treeview row-height + heading
    padding are critical: with default values the heading text overlaps
    the first data row on many Linux themes."""
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    # Treeview - rowheight bumped so the header doesn't overlap the
    # first row, and a clear inter-row separator is visible.
    style.configure(
        "Treeview",
        rowheight=28,
        font=("DejaVu Sans", 10),
        background="#ffffff",
        fieldbackground="#ffffff",
    )
    style.configure(
        "Treeview.Heading",
        font=("DejaVu Sans", 10, "bold"),
        padding=(6, 6),
        background="#1f3a5f",
        foreground="white",
    )
    style.map("Treeview.Heading",
              background=[("active", "#2c5e8e")])
    # Force the header element to render even on themes (some macOS
    # variants) where it would otherwise be missing.
    try:
        style.layout("Treeview", [
            ("Treeview.field", {
                "sticky": "nswe", "border": 1, "children": [
                    ("Treeview.padding", {
                        "sticky": "nswe", "children": [
                            ("Treeview.treearea", {"sticky": "nswe"}),
                        ],
                    }),
                ],
            }),
        ])
    except tk.TclError:
        pass

    style.configure("TButton", padding=4)


def _maximise_window(root: tk.Tk) -> None:
    """Open the window full-size on every platform."""
    try:
        root.update_idletasks()
        # Windows / some Linux themes
        if sys.platform.startswith("win"):
            root.state("zoomed")
            return
        # X11
        try:
            root.attributes("-zoomed", True)
            return
        except tk.TclError:
            pass
        # Final fallback: explicit screen geometry
        sw = root.winfo_screenwidth()
        sh = root.winfo_screenheight()
        root.geometry(f"{sw}x{sh}+0+0")
    except tk.TclError:
        pass


def main() -> int:
    print("[reghive] starting ...", flush=True)
    try:
        from core.action_logger import ActionLogger
        from gui.main_window import MainWindow
        from gui.splash_window import SplashWindow
    except Exception:
        print("[reghive] import failure:", flush=True)
        traceback.print_exc()
        input("Press Enter to exit...")
        return 1

    print("[reghive] imports ok, creating Tk root ...", flush=True)
    root = tk.Tk()
    root.title("WinRegEx")  # BRANDING: title

    # BRANDING: icon — set logo.png as the window icon for all windows
    _branding_icon_photo = None  # prevent garbage collection
    try:
        if _PIL_AVAILABLE:
            _logo_path = os.path.join(str(_ROOT), "assets", "logo.png")
            if not os.path.isfile(_logo_path):
                _logo_path = os.path.join(str(_ROOT), "logo.png")
            if os.path.isfile(_logo_path):
                _branding_icon_photo = ImageTk.PhotoImage(
                    Image.open(_logo_path))
                root.iconphoto(True, _branding_icon_photo)
    except Exception:
        pass  # graceful fallback to default icon
    # The window manager places the standard min/max/close buttons on
    # the title bar by default - we deliberately do NOT call
    # overrideredirect() or any -toolwindow style, so all three
    # decorations are present.
    #
    # Hide the root entirely while the splash dialog is up. A visible
    # 1x1 root window confuses the window manager when the splash is
    # marked as a transient child, which on Mutter/GNOME causes the
    # splash's own minimize / maximize / close buttons to malfunction.
    # Hiding the root means the splash is the only visible window and
    # gets full, working decorations.
    root.withdraw()
    _configure_ttk_style(root)

    ts = datetime.now(TZ_UTC3).strftime("%Y%m%d_%H%M%S_UTC+3")
    log_path = _log_dir() / f"session_{ts}.jsonl"
    logger = ActionLogger(persistent_path=log_path)
    logger.log_application_start()
    print(f"[reghive] log: {log_path}", flush=True)

    def _on_intake_complete(ctx: dict) -> None:
        print("[reghive] intake complete, opening main window ...", flush=True)
        # Show the root again - it was hidden during the splash.
        # The window manager re-draws the title bar with full
        # min/max/close decorations on this re-mapping.
        root.deiconify()
        root.update_idletasks()
        _maximise_window(root)
        try:
            MainWindow(root, logger, ctx)
        except Exception as exc:  # noqa: BLE001
            traceback.print_exc()
            messagebox.showerror(
                "Startup error",
                f"Could not initialize the analysis window:\n{exc}",
                parent=root)
            root.destroy()

    print("[reghive] showing splash ...", flush=True)
    splash = SplashWindow(root, logger, on_ready=_on_intake_complete)
    # Belt-and-braces: in case any framework code marked the splash
    # as withdrawn, force it to be mapped before mainloop runs.
    splash.deiconify()
    splash.update_idletasks()
    splash.lift()
    splash.attributes("-topmost", True)
    splash.after(200, lambda: splash.attributes("-topmost", False))
    splash.focus_force()

    def _on_root_close() -> None:
        logger.log_application_exit()
        try:
            root.destroy()
        except tk.TclError:
            pass

    root.protocol("WM_DELETE_WINDOW", _on_root_close)
    print("[reghive] entering mainloop", flush=True)
    root.mainloop()
    print("[reghive] mainloop exited cleanly", flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        input("Press Enter to exit...")
