# -*- coding: utf-8 -*-
"""
sternuke.gui
============

A clean desktop interface for the sternuke framework.

The GUI prefers ``customtkinter`` for a modern look and falls back to plain
``tkinter`` (standard library) when it is not installed, so the interface always
launches. It provides:

* a target input box,
* scan configuration selectors (mode, model, AI toggle, concurrency),
* an interactive, live-updating execution log, and
* a vulnerability findings dashboard (sortable severity table).

The scan runs on a background thread with its own asyncio event loop so the UI
stays responsive; log lines and findings are marshalled back to the Tk main
thread through a thread-safe queue.
"""

from __future__ import annotations

import asyncio
import os
import queue
import threading
from typing import List, Optional

from .cli import run_assessment
from .engine import Finding

# Prefer customtkinter; degrade gracefully to tkinter.
try:
    import customtkinter as ctk
    _CTK = True
except ImportError:  # pragma: no cover
    ctk = None
    _CTK = False

try:
    import tkinter as tk
    from tkinter import ttk, filedialog
    _TK_AVAILABLE = True
except ImportError:  # pragma: no cover - headless / no Tk installed
    tk = None  # type: ignore
    ttk = None  # type: ignore
    filedialog = None  # type: ignore
    _TK_AVAILABLE = False


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLORS = {
    "critical": "#b00020", "high": "#d1495b", "medium": "#e08e0b",
    "low": "#2a9d8f", "info": "#577590",
}


class ScanWorker(threading.Thread):
    """Runs :func:`run_assessment` on a private asyncio loop off the UI thread."""

    def __init__(self, params: dict, log_queue: "queue.Queue[str]",
                 result_queue: "queue.Queue[object]"):
        super().__init__(daemon=True)
        self.params = params
        self.log_queue = log_queue
        self.result_queue = result_queue

    def run(self) -> None:  # noqa: D401 - thread entry point
        def gui_logger(msg: str) -> None:
            self.log_queue.put(msg)

        async def _go() -> List[Finding]:
            # Inject the queue-backed logger by wrapping run_assessment's inputs.
            return await run_assessment(
                target=self.params["target"],
                mode=self.params["mode"],
                rules_path=self.params.get("rules_path"),
                output_dir=self.params["output_dir"],
                use_ai=self.params["use_ai"],
                model=self.params["model"],
                base_url=self.params["base_url"],
                concurrency=self.params["concurrency"],
                rps=self.params["rps"],
                verbose=True,
            )

        # run_assessment prints to stderr via its own logger; to route logs into
        # the GUI we temporarily monkeypatch the console logger factory.
        import sternuke.cli as cli_module
        original = cli_module._console_logger
        cli_module._console_logger = lambda verbose: gui_logger  # type: ignore
        try:
            findings = asyncio.run(_go())
            self.result_queue.put(findings)
        except Exception as exc:  # noqa: BLE001 - surface errors in the UI
            self.log_queue.put(f"[error] {exc}")
            self.result_queue.put(exc)
        finally:
            cli_module._console_logger = original  # type: ignore


class SternukeApp:
    """The main application window."""

    def __init__(self) -> None:
        self.log_queue: "queue.Queue[str]" = queue.Queue()
        self.result_queue: "queue.Queue[object]" = queue.Queue()
        self.worker: Optional[ScanWorker] = None

        if _CTK:
            ctk.set_appearance_mode("dark")
            ctk.set_default_color_theme("blue")
            self.root = ctk.CTk()
        else:
            self.root = tk.Tk()
        self.root.title("sternuke - vulnerability assessment")
        self.root.geometry("1000x720")

        self._build_widgets()
        self.root.after(120, self._drain_queues)

    # -- layout ---------------------------------------------------------------
    def _frame(self, parent, **kw):
        return ctk.CTkFrame(parent, **kw) if _CTK else ttk.Frame(parent, **kw)

    def _label(self, parent, text, **kw):
        return ctk.CTkLabel(parent, text=text, **kw) if _CTK else ttk.Label(parent, text=text, **kw)

    def _button(self, parent, text, command, **kw):
        return (ctk.CTkButton(parent, text=text, command=command, **kw)
                if _CTK else ttk.Button(parent, text=text, command=command, **kw))

    def _entry(self, parent, textvariable, **kw):
        return (ctk.CTkEntry(parent, textvariable=textvariable, **kw)
                if _CTK else ttk.Entry(parent, textvariable=textvariable, **kw))

    def _build_widgets(self) -> None:
        pad = {"padx": 8, "pady": 6}

        # --- configuration bar ---
        cfg = self._frame(self.root)
        cfg.pack(fill="x", **pad)

        self._label(cfg, "Target:").grid(row=0, column=0, sticky="w", padx=6, pady=6)
        self.target_var = tk.StringVar(value="https://example.test")
        self._entry(cfg, self.target_var, width=380).grid(row=0, column=1, columnspan=3,
                                                          sticky="we", padx=6)
        self._button(cfg, "Browse dir", self._browse).grid(row=0, column=4, padx=6)

        self._label(cfg, "Mode:").grid(row=1, column=0, sticky="w", padx=6)
        self.mode_var = tk.StringVar(value="web")
        mode_box = ttk.Combobox(cfg, textvariable=self.mode_var,
                                values=["web", "blockchain"], width=12, state="readonly")
        mode_box.grid(row=1, column=1, sticky="w", padx=6)

        self._label(cfg, "Model:").grid(row=1, column=2, sticky="w", padx=6)
        self.model_var = tk.StringVar(value="deepseek-coder")
        self._entry(cfg, self.model_var, width=160).grid(row=1, column=3, sticky="w", padx=6)

        self._label(cfg, "Local API:").grid(row=2, column=0, sticky="w", padx=6)
        self.base_url_var = tk.StringVar(value="http://localhost:11434/v1")
        self._entry(cfg, self.base_url_var, width=260).grid(row=2, column=1, columnspan=2,
                                                           sticky="we", padx=6)

        self.ai_var = tk.BooleanVar(value=False)
        ai_chk = (ctk.CTkCheckBox(cfg, text="Use local AI agent", variable=self.ai_var)
                  if _CTK else ttk.Checkbutton(cfg, text="Use local AI agent",
                                               variable=self.ai_var))
        ai_chk.grid(row=2, column=3, sticky="w", padx=6)

        self._label(cfg, "Concurrency:").grid(row=3, column=0, sticky="w", padx=6)
        self.conc_var = tk.IntVar(value=20)
        self._entry(cfg, self.conc_var, width=80).grid(row=3, column=1, sticky="w", padx=6)
        self._label(cfg, "Req/s:").grid(row=3, column=2, sticky="w", padx=6)
        self.rps_var = tk.DoubleVar(value=25.0)
        self._entry(cfg, self.rps_var, width=80).grid(row=3, column=3, sticky="w", padx=6)

        self.run_btn = self._button(cfg, "Start assessment", self._start_scan)
        self.run_btn.grid(row=4, column=1, sticky="w", padx=6, pady=8)
        self._button(cfg, "Clear log", self._clear_log).grid(row=4, column=2, sticky="w", pady=8)

        # --- findings dashboard ---
        dash = self._frame(self.root)
        dash.pack(fill="both", expand=False, **pad)
        self._label(dash, "Findings dashboard").pack(anchor="w", padx=6)
        cols = ("severity", "name", "location")
        self.tree = ttk.Treeview(dash, columns=cols, show="headings", height=9)
        for c, w in zip(cols, (100, 420, 380)):
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="x", padx=6, pady=4)
        for sev, color in SEVERITY_COLORS.items():
            self.tree.tag_configure(sev, foreground=color)

        # --- live log ---
        logframe = self._frame(self.root)
        logframe.pack(fill="both", expand=True, **pad)
        self._label(logframe, "Live execution log").pack(anchor="w", padx=6)
        self.log_text = tk.Text(logframe, height=14, bg="#101418", fg="#d6e2f0",
                                insertbackground="#d6e2f0", wrap="word")
        self.log_text.pack(fill="both", expand=True, padx=6, pady=4)
        self.log_text.configure(state="disabled")

        self.status_var = tk.StringVar(value="Ready.")
        self._label(self.root, textvariable=self.status_var).pack(anchor="w", padx=14, pady=4)

    # -- actions --------------------------------------------------------------
    def _browse(self) -> None:
        path = filedialog.askdirectory()
        if path:
            self.target_var.set(path)
            self.mode_var.set("blockchain")

    def _clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _append_log(self, line: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", line + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _start_scan(self) -> None:
        if self.worker and self.worker.is_alive():
            self.status_var.set("A scan is already running.")
            return
        for row in self.tree.get_children():
            self.tree.delete(row)
        params = {
            "target": self.target_var.get().strip(),
            "mode": self.mode_var.get(),
            "model": self.model_var.get().strip(),
            "base_url": self.base_url_var.get().strip(),
            "use_ai": bool(self.ai_var.get()),
            "rules_path": os.path.join(os.path.dirname(__file__), "rules"),
            "output_dir": os.path.abspath("./sternuke-out"),
            "concurrency": int(self.conc_var.get()),
            "rps": float(self.rps_var.get()),
        }
        self.status_var.set(f"Scanning {params['target']} ({params['mode']}) ...")
        self.run_btn.configure(state="disabled")
        self.worker = ScanWorker(params, self.log_queue, self.result_queue)
        self.worker.start()

    def _drain_queues(self) -> None:
        # Pump log lines.
        while True:
            try:
                self._append_log(self.log_queue.get_nowait())
            except queue.Empty:
                break
        # Pump results.
        try:
            result = self.result_queue.get_nowait()
        except queue.Empty:
            result = None
        if result is not None:
            self.run_btn.configure(state="normal")
            if isinstance(result, Exception):
                self.status_var.set(f"Scan failed: {result}")
            else:
                self._populate_findings(result)
                self.status_var.set(f"Done. {len(result)} finding(s).")
        self.root.after(120, self._drain_queues)

    def _populate_findings(self, findings: List[Finding]) -> None:
        findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
        for f in findings:
            self.tree.insert("", "end",
                             values=(f.severity.upper(), f.name, f.matched_at),
                             tags=(f.severity,))

    def run(self) -> None:
        self.root.mainloop()


def launch_gui() -> None:
    """Entry point used by the CLI (`sternuke gui`) and :mod:`sternuke.main`."""
    if not _TK_AVAILABLE:
        raise SystemExit(
            "The GUI requires Tk. Install the Tk bindings (e.g. 'apt install "
            "python3-tk' or 'pip install customtkinter') or use the CLI:\n"
            "    python -m sternuke.main scan --target <target> --mode web"
        )
    SternukeApp().run()


if __name__ == "__main__":  # pragma: no cover
    launch_gui()
