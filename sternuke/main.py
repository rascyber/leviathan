# -*- coding: utf-8 -*-
"""
sternuke.main
=============

Single entry point that stitches the CLI, GUI, engine and AI components
together.

Behaviour
---------
* ``python -m sternuke.main`` with no arguments launches the GUI.
* ``python -m sternuke.main gui`` launches the GUI explicitly.
* ``python -m sternuke.main scan ...`` runs a command-line assessment.
* ``python -m sternuke.main --help`` shows CLI usage.

All heavy lifting lives in the dedicated modules:

* :mod:`sternuke.engine`   - async networking, filesystem crawler, rule parser.
* :mod:`sternuke.ai_agent` - local model orchestration + static analysis.
* :mod:`sternuke.cli`      - argument parsing and the shared ``run_assessment``.
* :mod:`sternuke.gui`      - desktop interface.
"""

from __future__ import annotations

import sys
from typing import List, Optional


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
