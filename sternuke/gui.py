# -*- coding: utf-8 -*-
"""
sternuke.gui
============

The sternuke desktop orchestration dashboard.

Prefers ``customtkinter`` for a modern look and falls back to the standard
library ``tkinter`` when it is not installed, so the interface always launches.
It is organised as two tabs:

* **Quick Scan** - single-target web/blockchain assessment (the original flow).
* **Orchestration** - a multi-asset ingestion wizard: paste raw targets or load
  a ``.txt`` / ``.csv`` scope file, review the auto-classified assets (wildcard
  domains, FQDNs, IPv4/IPv6, API endpoints, smart-contract addresses), toggle
  the execution modes (Web Stateful Chain / Advanced ABI Contract Fuzzing / AI
  Template Generation Loop) and run them across every asset.

All work runs on a background thread with its own asyncio loop; log lines and
findings are marshalled back to the Tk main thread through thread-safe queues.
"""

from __future__ import annotations

import asyncio
import os
import queue
import threading
from typing import List, Optional

from .cli import run_assessment, run_orchestration
from .engine import Finding
from .assets import Asset, AssetParser

# Prefer customtkinter; degrade gracefully to tkinter.
try:
    import customtkinter as ctk
    _CTK = True
except ImportError:  # pragma: no cover
    ctk = None
    _CTK = False

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    _TK_AVAILABLE = True
except ImportError:  # pragma: no cover - headless / no Tk installed
    tk = None  # type: ignore
    ttk = None  # type: ignore
    filedialog = None  # type: ignore
    messagebox = None  # type: ignore
    _TK_AVAILABLE = False


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLORS = {
    "critical": "#b00020", "high": "#d1495b", "medium": "#e08e0b",
    "low": "#2a9d8f", "info": "#577590",
}


# ===========================================================================
# Background workers
# ===========================================================================
class _AsyncWorker(threading.Thread):
    """Base worker that runs a coroutine factory on a private event loop."""

    def __init__(self, log_queue: "queue.Queue[str]",
                 result_queue: "queue.Queue[object]") -> None:
        super().__init__(daemon=True)
        self.log_queue = log_queue
        self.result_queue = result_queue

    def _log(self, msg: str) -> None:
        self.log_queue.put(msg)

    def _run_coro(self, coro) -> None:
        try:
            findings = asyncio.run(coro)
            self.result_queue.put(findings)
        except Exception as exc:  # noqa: BLE001 - surface errors in the UI
            self.log_queue.put(f"[error] {exc}")
            self.result_queue.put(exc)


class ScanWorker(_AsyncWorker):
    """Runs a single-target quick scan."""

    def __init__(self, params: dict, log_queue, result_queue) -> None:
        super().__init__(log_queue, result_queue)
        self.params = params

    def run(self) -> None:
        import sternuke.cli as cli_module
        original = cli_module._console_logger
        cli_module._console_logger = lambda verbose: self._log  # type: ignore
        try:
            self._run_coro(run_assessment(
                target=self.params["target"], mode=self.params["mode"],
                rules_path=self.params.get("rules_path"),
                output_dir=self.params["output_dir"], use_ai=self.params["use_ai"],
                model=self.params["model"], base_url=self.params["base_url"],
                concurrency=self.params["concurrency"], rps=self.params["rps"],
                verbose=True))
        finally:
            cli_module._console_logger = original  # type: ignore


class OrchestrationWorker(_AsyncWorker):
    """Runs the multi-asset orchestration loop with selected modes."""

    def __init__(self, params: dict, log_queue, result_queue) -> None:
        super().__init__(log_queue, result_queue)
        self.params = params

    def run(self) -> None:
        self._run_coro(run_orchestration(
            assets=self.params["assets"], modes=self.params["modes"],
            output_dir=self.params["output_dir"], model=self.params["model"],
            base_url=self.params["base_url"], rpc_url=self.params["rpc_url"],
            concurrency=self.params["concurrency"], rps=self.params["rps"],
            verbose=True, allow_remote=self.params["allow_remote"],
            log_sink=self._log))


# ===========================================================================
# Application
# ===========================================================================
class SternukeApp:
    """The main application window with Quick Scan and Orchestration tabs."""

    def __init__(self) -> None:
        self.log_queue: "queue.Queue[str]" = queue.Queue()
        self.result_queue: "queue.Queue[object]" = queue.Queue()
        self.worker: Optional[_AsyncWorker] = None
        self.assets: List[Asset] = []
        self.parser = AssetParser()

        if _CTK:
            ctk.set_appearance_mode("dark")
            ctk.set_default_color_theme("blue")
            self.root = ctk.CTk()
        else:
            self.root = tk.Tk()
        self.root.title("sternuke - orchestration dashboard")
        self.root.geometry("1080x780")

        self._build_widgets()
        self.root.after(120, self._drain_queues)

    # -- widget factories (ctk or ttk) --------------------------------------
    def _frame(self, parent, **kw):
        return ctk.CTkFrame(parent, **kw) if _CTK else ttk.Frame(parent, **kw)

    def _label(self, parent, text=None, **kw):
        if _CTK:
            return ctk.CTkLabel(parent, text=text or "", **kw)
        return ttk.Label(parent, text=text or "", **kw)

    def _button(self, parent, text, command, **kw):
        return (ctk.CTkButton(parent, text=text, command=command, **kw)
                if _CTK else ttk.Button(parent, text=text, command=command, **kw))

    def _entry(self, parent, textvariable, **kw):
        return (ctk.CTkEntry(parent, textvariable=textvariable, **kw)
                if _CTK else ttk.Entry(parent, textvariable=textvariable, **kw))

    def _check(self, parent, text, variable):
        return (ctk.CTkCheckBox(parent, text=text, variable=variable)
                if _CTK else ttk.Checkbutton(parent, text=text, variable=variable))

    # -- layout --------------------------------------------------------------
    def _build_widgets(self) -> None:
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=8)
        self.quick_tab = ttk.Frame(self.notebook)
        self.orch_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.quick_tab, text="Quick Scan")
        self.notebook.add(self.orch_tab, text="Orchestration")

        self._build_quick_tab(self.quick_tab)
        self._build_orch_tab(self.orch_tab)

        # Shared findings dashboard + log below the notebook.
        self._build_dashboard(self.root)

        self.status_var = tk.StringVar(value="Ready.")
        self._label(self.root, textvariable=self.status_var).pack(anchor="w", padx=14, pady=4)

    def _build_quick_tab(self, parent) -> None:
        pad = {"padx": 6, "pady": 5}
        self._label(parent, "Target:").grid(row=0, column=0, sticky="w", **pad)
        self.target_var = tk.StringVar(value="http://127.0.0.1:8080")
        self._entry(parent, self.target_var, width=360).grid(
            row=0, column=1, columnspan=3, sticky="we", **pad)

        self._label(parent, "Mode:").grid(row=1, column=0, sticky="w", **pad)
        self.mode_var = tk.StringVar(value="web")
        ttk.Combobox(parent, textvariable=self.mode_var, values=["web", "blockchain"],
                     width=12, state="readonly").grid(row=1, column=1, sticky="w", **pad)
        self._label(parent, "Model:").grid(row=1, column=2, sticky="w", **pad)
        self.model_var = tk.StringVar(value="deepseek-coder")
        self._entry(parent, self.model_var, width=160).grid(row=1, column=3, sticky="w", **pad)

        self.ai_var = tk.BooleanVar(value=False)
        self._check(parent, "Use local AI agent", self.ai_var).grid(
            row=2, column=1, sticky="w", **pad)
        self.run_btn = self._button(parent, "Start quick scan", self._start_scan)
        self.run_btn.grid(row=3, column=1, sticky="w", **pad)

    def _build_orch_tab(self, parent) -> None:
        pad = {"padx": 6, "pady": 4}
        self._label(parent, "Paste targets (one per line) or load a scope file:").grid(
            row=0, column=0, columnspan=4, sticky="w", **pad)
        self.targets_text = tk.Text(parent, height=7, width=90, wrap="none",
                                    bg="#0f1115", fg="#d6e2f0", insertbackground="#d6e2f0")
        self.targets_text.grid(row=1, column=0, columnspan=4, sticky="we", **pad)
        self.targets_text.insert("1.0", "# e.g.\n# *.target.com\n# https://api.target.com/v1\n"
                                 "# 192.0.2.10\n# 0x" + "0" * 40 + "\n")

        self._button(parent, "Load scope file (.txt/.csv)", self._load_scope_file).grid(
            row=2, column=0, sticky="w", **pad)
        self._button(parent, "Parse assets", self._parse_assets).grid(
            row=2, column=1, sticky="w", **pad)
        self.assets_summary = tk.StringVar(value="No assets parsed yet.")
        self._label(parent, textvariable=self.assets_summary).grid(
            row=2, column=2, columnspan=2, sticky="w", **pad)

        # Detected assets preview.
        cols = ("type", "value")
        self.assets_tree = ttk.Treeview(parent, columns=cols, show="headings", height=7)
        for c, w in zip(cols, (180, 560)):
            self.assets_tree.heading(c, text=c.capitalize())
            self.assets_tree.column(c, width=w, anchor="w")
        self.assets_tree.grid(row=3, column=0, columnspan=4, sticky="we", **pad)

        # Mode selectors.
        self.m_web = tk.BooleanVar(value=True)
        self.m_abi = tk.BooleanVar(value=False)
        self.m_ai = tk.BooleanVar(value=True)
        self._check(parent, "Web Stateful Chain", self.m_web).grid(
            row=4, column=0, sticky="w", **pad)
        self._check(parent, "Advanced ABI Contract Fuzzing", self.m_abi).grid(
            row=4, column=1, sticky="w", **pad)
        self._check(parent, "AI Template Generation Loop", self.m_ai).grid(
            row=4, column=2, sticky="w", **pad)

        self.allow_remote_var = tk.BooleanVar(value=False)
        self._check(parent, "Allow non-local targets (I am authorised)",
                    self.allow_remote_var).grid(row=5, column=0, columnspan=2,
                                                sticky="w", **pad)
        self._label(parent, "RPC (local node):").grid(row=5, column=2, sticky="e", **pad)
        self.rpc_var = tk.StringVar(value="http://127.0.0.1:8545")
        self._entry(parent, self.rpc_var, width=200).grid(row=5, column=3, sticky="w", **pad)

        self.orch_btn = self._button(parent, "Run Orchestration", self._start_orchestration)
        self.orch_btn.grid(row=6, column=1, sticky="w", **pad)

    def _build_dashboard(self, parent) -> None:
        dash = self._frame(parent)
        dash.pack(fill="both", expand=False, padx=8, pady=4)
        self._label(dash, "Findings dashboard").pack(anchor="w", padx=6)
        cols = ("severity", "name", "location")
        self.tree = ttk.Treeview(dash, columns=cols, show="headings", height=8)
        for c, w in zip(cols, (100, 460, 420)):
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="x", padx=6, pady=4)
        for sev, color in SEVERITY_COLORS.items():
            self.tree.tag_configure(sev, foreground=color)

        logframe = self._frame(parent)
        logframe.pack(fill="both", expand=True, padx=8, pady=4)
        self._label(logframe, "Live execution log").pack(anchor="w", padx=6)
        self.log_text = tk.Text(logframe, height=12, bg="#101418", fg="#d6e2f0",
                                insertbackground="#d6e2f0", wrap="word")
        self.log_text.pack(fill="both", expand=True, padx=6, pady=4)
        self.log_text.configure(state="disabled")

    # -- asset ingestion handlers -------------------------------------------
    def _load_scope_file(self) -> None:
        path = filedialog.askopenfilename(
            filetypes=[("Scope files", "*.txt *.csv"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError as exc:
            messagebox.showerror("Load failed", str(exc))
            return
        self.targets_text.delete("1.0", "end")
        self.targets_text.insert("1.0", content)
        self._loaded_path = path
        self._parse_assets(source_path=path)

    def _parse_assets(self, source_path: Optional[str] = None) -> None:
        raw = self.targets_text.get("1.0", "end")
        if source_path and source_path.lower().endswith(".csv"):
            self.assets = self.parser.parse_csv(raw)
        else:
            self.assets = self.parser.parse_text(raw)
        for row in self.assets_tree.get_children():
            self.assets_tree.delete(row)
        for a in self.assets:
            self.assets_tree.insert("", "end", values=(a.type.value, a.value))
        summary = self.parser.summary(self.assets)
        self.assets_summary.set(
            f"{len(self.assets)} asset(s): " +
            ", ".join(f"{k}={v}" for k, v in summary.items()) if summary else "No assets.")

    # -- run handlers --------------------------------------------------------
    def _busy(self) -> bool:
        if self.worker and self.worker.is_alive():
            self.status_var.set("A job is already running.")
            return True
        return False

    def _clear_findings(self) -> None:
        for row in self.tree.get_children():
            self.tree.delete(row)

    def _start_scan(self) -> None:
        if self._busy():
            return
        self._clear_findings()
        params = {
            "target": self.target_var.get().strip(), "mode": self.mode_var.get(),
            "model": self.model_var.get().strip(),
            "base_url": "http://localhost:11434/v1", "use_ai": bool(self.ai_var.get()),
            "rules_path": os.path.join(os.path.dirname(__file__), "rules"),
            "output_dir": os.path.abspath("./sternuke-out"),
            "concurrency": 15, "rps": 20.0,
        }
        self.status_var.set(f"Scanning {params['target']} ...")
        self.run_btn.configure(state="disabled")
        self.worker = ScanWorker(params, self.log_queue, self.result_queue)
        self.worker.start()

    def _start_orchestration(self) -> None:
        if self._busy():
            return
        if not self.assets:
            self._parse_assets()
        if not self.assets:
            self.status_var.set("No assets to orchestrate. Parse targets first.")
            return
        modes: List[str] = []
        if self.m_web.get():
            modes.append("web_chain")
        if self.m_abi.get():
            modes.append("abi_fuzz")
        if self.m_ai.get():
            modes.append("ai_templates")
        if not modes:
            self.status_var.set("Select at least one mode.")
            return
        self._clear_findings()
        params = {
            "assets": self.assets, "modes": modes,
            "output_dir": os.path.abspath("./sternuke-out"),
            "model": "deepseek-coder", "base_url": "http://localhost:11434/v1",
            "rpc_url": self.rpc_var.get().strip(), "concurrency": 15, "rps": 15.0,
            "allow_remote": bool(self.allow_remote_var.get()),
        }
        self.status_var.set(f"Orchestrating {len(self.assets)} asset(s): {', '.join(modes)}")
        self.orch_btn.configure(state="disabled")
        self.worker = OrchestrationWorker(params, self.log_queue, self.result_queue)
        self.worker.start()

    # -- UI pump -------------------------------------------------------------
    def _append_log(self, line: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", line + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _drain_queues(self) -> None:
        while True:
            try:
                self._append_log(self.log_queue.get_nowait())
            except queue.Empty:
                break
        try:
            result = self.result_queue.get_nowait()
        except queue.Empty:
            result = None
        if result is not None:
            self.run_btn.configure(state="normal")
            self.orch_btn.configure(state="normal")
            if isinstance(result, Exception):
                self.status_var.set(f"Job failed: {result}")
            else:
                self._populate_findings(result)
                self.status_var.set(f"Done. {len(result)} finding(s).")
        self.root.after(120, self._drain_queues)

    def _populate_findings(self, findings: List[Finding]) -> None:
        for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 9)):
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
            "    python -m sternuke.main orchestrate --scope-file scope.txt")
    SternukeApp().run()


if __name__ == "__main__":  # pragma: no cover
    launch_gui()
