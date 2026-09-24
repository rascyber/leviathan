# -*- coding: utf-8 -*-
"""
sternuke.cli
============

Command-line interface for the sternuke framework.

Uses ``click`` when available (rich UX) and transparently falls back to
``argparse`` so the CLI works with only the standard library. Both front-ends
dispatch into the same :func:`run_assessment` coroutine.

Examples
--------
Web assessment with the built-in ruleset::

    python -m sternuke.main scan --target https://example.test --mode web \\
        --rules sternuke/rules --output ./sternuke-out

AI-assisted blockchain (static) assessment of a local repo::

    python -m sternuke.main scan --target ./my-contracts --mode blockchain \\
        --ai --model deepseek-coder --output ./sternuke-out
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import List, Optional

from .engine import (
    Finding, RepoCrawler, RuleEngine, ScanPolicy, WebScanner,
)
from .ai_agent import AIAgent, LocalModelClient, ModelConfig

try:
    import click
except ImportError:  # pragma: no cover
    click = None


# ----------------------------------------------------------------------------
# Shared orchestration
# ----------------------------------------------------------------------------
def _console_logger(verbose: bool):
    def log(msg: str) -> None:
        if verbose or not msg.startswith("[net]"):
            print(msg, file=sys.stderr)
    return log


async def run_assessment(
    *,
    target: str,
    mode: str,
    rules_path: Optional[str],
    output_dir: str,
    use_ai: bool,
    model: str,
    base_url: str,
    concurrency: int,
    rps: float,
    verbose: bool,
    rule_format: str = "yaml",
) -> List[Finding]:
    """Run a full assessment and return the findings list.

    This is the single seam the CLI, GUI and :mod:`sternuke.main` all call.
    """
    log = _console_logger(verbose)
    os.makedirs(output_dir, exist_ok=True)
    policy = ScanPolicy(max_concurrency=concurrency, requests_per_second=rps)
    rule_engine = RuleEngine(logger=log)
    model_client = LocalModelClient(ModelConfig(base_url=base_url, model=model), logger=log)
    agent = AIAgent(model_client, logger=log)

    findings: List[Finding] = []

    if mode == "blockchain":
        # Static, local-only assessment of a source repository.
        crawler = RepoCrawler(logger=log)
        sources = crawler.crawl(target)
        blueprints = agent.build_blueprints(sources)
        _dump_json(os.path.join(output_dir, "blueprint.json"),
                   [bp.to_dict() for bp in blueprints])
        if use_ai:
            rule_file = await agent.synthesize_from_blueprints(
                blueprints, output_dir, fmt=rule_format)
            rule_engine.load_file(rule_file)
        else:
            # Even without the model, surface the deterministic advisories.
            offline = agent._offline_blueprint_rules(blueprints)  # noqa: SLF001 - intended reuse
            path = agent._write_rules(offline, output_dir, rule_format, prefix="blockchain")
            rule_engine.load_file(path)
        # Blockchain rules are advisory findings (no network requests).
        for rule in rule_engine.rules:
            findings.append(Finding(
                rule_id=rule.id, name=rule.name, severity=rule.severity,
                target=target, matched_at=target, description=rule.description,
                remediation=rule.remediation, tags=rule.tags,
            ))

    elif mode == "web":
        if rules_path:
            _load_rules(rule_engine, rules_path, log)
        if use_ai:
            # Optionally let the agent add endpoint-specific rules first.
            rule_file = await agent.synthesize_from_web_context(
                [{"url": target}], output_dir, fmt=rule_format)
            rule_engine.load_file(rule_file)
        if not rule_engine.rules:
            # Guarantee a baseline ruleset so a scan is never empty.
            offline = agent._offline_web_rules()  # noqa: SLF001
            path = agent._write_rules(offline, output_dir, rule_format, prefix="web")
            rule_engine.load_file(path)
        scanner = WebScanner(policy, rule_engine, logger=log)
        findings = await scanner.scan([target])
    else:
        raise ValueError(f"Unknown mode: {mode!r} (expected 'web' or 'blockchain')")

    _write_report(findings, output_dir)
    return findings


# ----------------------------------------------------------------------------
# Reporting helpers
# ----------------------------------------------------------------------------
def _load_rules(engine: RuleEngine, path: str, log) -> None:
    if os.path.isdir(path):
        engine.load_dir(path)
    elif os.path.isfile(path):
        engine.load_file(path)
    else:
        log(f"[rules] path not found: {path}")


def _dump_json(path: str, obj) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2)


def _write_report(findings: List[Finding], output_dir: str) -> str:
    report = os.path.join(output_dir, "findings.json")
    _dump_json(report, [f.to_dict() for f in findings])
    return report


def print_summary(findings: List[Finding]) -> None:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = sorted(findings, key=lambda f: order.get(f.severity, 9))
    print("\n=== sternuke findings ===")
    if not findings:
        print("No findings.")
        return
    for f in findings:
        print(f"  [{f.severity.upper():8}] {f.name}")
        print(f"            @ {f.matched_at}")
        if f.evidence:
            print(f"            evidence: {f.evidence}")
    print(f"\nTotal: {len(findings)} finding(s)")


# ----------------------------------------------------------------------------
# click front-end
# ----------------------------------------------------------------------------
if click is not None:

    @click.group()
    @click.version_option("1.0.0", prog_name="sternuke")
    def cli() -> None:
        """sternuke - local, AI-assisted vulnerability assessment framework."""

    @cli.command("scan")
    @click.option("--target", required=True,
                  help="Target URL (web mode) or local directory (blockchain mode).")
    @click.option("--mode", type=click.Choice(["web", "blockchain"]), default="web",
                  show_default=True, help="Assessment domain.")
    @click.option("--model", default="deepseek-coder", show_default=True,
                  help="Local model name served by Ollama/vLLM.")
    @click.option("--base-url", default="http://localhost:11434/v1", show_default=True,
                  help="Local OpenAI-compatible inference endpoint.")
    @click.option("--rules", "rules_path", default=None,
                  help="Rule file or directory for web mode.")
    @click.option("--output", "output_dir", default="./sternuke-out", show_default=True,
                  help="Directory for reports and synthesised rules.")
    @click.option("--ai/--no-ai", default=False, show_default=True,
                  help="Use the local AI agent to synthesise rules.")
    @click.option("--concurrency", default=20, show_default=True,
                  help="Max simultaneous requests (assessment throttle).")
    @click.option("--rps", default=25.0, show_default=True,
                  help="Global requests-per-second cap.")
    @click.option("--rule-format", type=click.Choice(["yaml", "json"]), default="yaml")
    @click.option("-v", "--verbose", is_flag=True, default=False)
    def scan_cmd(target, mode, model, base_url, rules_path, output_dir, ai,
                 concurrency, rps, rule_format, verbose):
        """Run an assessment against a single target."""
        findings = asyncio.run(run_assessment(
            target=target, mode=mode, rules_path=rules_path, output_dir=output_dir,
            use_ai=ai, model=model, base_url=base_url, concurrency=concurrency,
            rps=rps, verbose=verbose, rule_format=rule_format,
        ))
        print_summary(findings)

    @cli.command("gui")
    def gui_cmd():
        """Launch the graphical interface."""
        from .gui import launch_gui
        launch_gui()

    def main(argv: Optional[List[str]] = None) -> int:
        cli.main(args=argv, standalone_mode=False)
        return 0

else:  # ------------------------------------------------------------------
    # argparse fallback (standard library only)
    import argparse

    def _build_parser() -> "argparse.ArgumentParser":
        parser = argparse.ArgumentParser(
            prog="sternuke", description="Local, AI-assisted vulnerability assessment framework.")
        sub = parser.add_subparsers(dest="command", required=True)

        scan = sub.add_parser("scan", help="Run an assessment.")
        scan.add_argument("--target", required=True)
        scan.add_argument("--mode", choices=["web", "blockchain"], default="web")
        scan.add_argument("--model", default="deepseek-coder")
        scan.add_argument("--base-url", default="http://localhost:11434/v1")
        scan.add_argument("--rules", dest="rules_path", default=None)
        scan.add_argument("--output", dest="output_dir", default="./sternuke-out")
        scan.add_argument("--ai", dest="use_ai", action="store_true")
        scan.add_argument("--concurrency", type=int, default=20)
        scan.add_argument("--rps", type=float, default=25.0)
        scan.add_argument("--rule-format", choices=["yaml", "json"], default="yaml")
        scan.add_argument("-v", "--verbose", action="store_true")

        sub.add_parser("gui", help="Launch the graphical interface.")
        return parser

    def main(argv: Optional[List[str]] = None) -> int:
        parser = _build_parser()
        args = parser.parse_args(argv)
        if args.command == "gui":
            from .gui import launch_gui
            launch_gui()
            return 0
        findings = asyncio.run(run_assessment(
            target=args.target, mode=args.mode, rules_path=args.rules_path,
            output_dir=args.output_dir, use_ai=args.use_ai, model=args.model,
            base_url=args.base_url, concurrency=args.concurrency, rps=args.rps,
            verbose=args.verbose, rule_format=args.rule_format,
        ))
        print_summary(findings)
        return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
