# -*- coding: utf-8 -*-
"""
sternuke.main
=============

Single entry point that stitches the CLI, GUI, engine and AI components
together.

Behaviour
---------
* ``python -m sternuke.main`` with no arguments launches the GUI dashboard.
* ``python -m sternuke.main gui`` launches the GUI explicitly.
* ``python -m sternuke.main scan ...`` runs a single-target assessment.
* ``python -m sternuke.main orchestrate ...`` runs the multi-asset loop.
* ``python -m sternuke.main fuzz|chain|intel ...`` runs the respective module.
* ``python -m sternuke.main --help`` shows CLI usage.

All heavy lifting lives in the dedicated modules:

* :mod:`sternuke.engine`       - async networking, filesystem crawler, rules.
* :mod:`sternuke.ai_agent`     - local model orchestration + static analysis.
* :mod:`sternuke.state_engine` - session vault + dependency-graph chaining.
* :mod:`sternuke.fuzzing`      - web/contract/binary mutation fuzzers + ABI codec.
* :mod:`sternuke.intelligence` - CVSS scoring, Nuclei + HackerOne generation.
* :mod:`sternuke.assets`       - bulk target ingestion / classification.
* :mod:`sternuke.cli`          - argument parsing + ``run_orchestration`` loop.
* :mod:`sternuke.gui`          - desktop orchestration dashboard.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any, List, Optional, Sequence


def orchestrate(
    targets: Sequence[str],
    *,
    modes: Optional[Sequence[str]] = None,
    output_dir: str = "./sternuke-out",
    model: str = "deepseek-coder",
    base_url: str = "http://localhost:11434/v1",
    rpc_url: str = "http://127.0.0.1:8545",
    concurrency: int = 15,
    rps: float = 15.0,
    allow_remote: bool = False,
    verbose: bool = False,
) -> List[Any]:
    """Programmatic connection loop: parse raw targets, then run the modes.

    A thin synchronous wrapper stitching :mod:`sternuke.assets` (ingestion) to
    :func:`sternuke.cli.run_orchestration` (execution + advisory generation), so
    embedders can drive the whole pipeline in one call without the CLI or GUI.
    """
    from .assets import AssetParser
    from .cli import run_orchestration

    assets = AssetParser().parse_text("\n".join(targets))
    selected = list(modes) if modes else ["web_chain", "abi_fuzz", "ai_templates"]
    return asyncio.run(run_orchestration(
        assets=assets, modes=selected, output_dir=output_dir, model=model,
        base_url=base_url, rpc_url=rpc_url, concurrency=concurrency, rps=rps,
        verbose=verbose, allow_remote=allow_remote,
    ))


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # No arguments -> launch the GUI for an approachable default experience.
    if not argv:
        from .gui import launch_gui
        launch_gui()
        return 0

    # Otherwise hand off to the CLI dispatcher (click or argparse).
    from .cli import main as cli_main
    return cli_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
