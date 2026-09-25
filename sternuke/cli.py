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
from typing import Any, Callable, List, Optional
from urllib.parse import urlparse

from .engine import (
    Finding, RepoCrawler, RuleEngine, ScanPolicy, WebScanner,
)
from .ai_agent import AIAgent, LocalModelClient, ModelConfig
from .cognitive import CrossContractAnalyzer
from .memory import build_default_memory
from .fuzzing.guards import ScopeError

# Errors that should surface to the user as a clean message, not a traceback.
_CLEAN_ERRORS = (ScopeError, ValueError, FileNotFoundError, NotADirectoryError)

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
    log_sink: Optional[Callable[[str], None]] = None,
) -> List[Finding]:
    """Run a full assessment and return the findings list.

    This is the single seam the CLI, GUI and :mod:`sternuke.main` all call.
    ``log_sink``, when provided, receives every log line (used by the web UI).
    """
    log = log_sink or _console_logger(verbose)
    os.makedirs(output_dir, exist_ok=True)
    policy = ScanPolicy(max_concurrency=concurrency, requests_per_second=rps)
    rule_engine = RuleEngine(logger=log)
    model_client = LocalModelClient(ModelConfig(base_url=base_url, model=model), logger=log)
    agent = AIAgent(model_client, logger=log)
    # Local case-based memory: recalled cases steer, but never dictate, testing.
    memory = build_default_memory(
        path=os.path.join(output_dir, "memory.json"), logger=log)

    findings: List[Finding] = []

    if mode == "blockchain":
        # Static, local-only assessment of a source repository.
        crawler = RepoCrawler(logger=log)
        sources = crawler.crawl(target)
        blueprints = agent.build_blueprints(sources)
        _dump_json(os.path.join(output_dir, "blueprint.json"),
                   [bp.to_dict() for bp in blueprints])

        # Cross-contract interaction & reentrancy mapping (static analysis).
        xcontract = CrossContractAnalyzer(logger=log)
        call_graph: dict = {}
        for sf in sources:
            nodes = xcontract.analyze(sf.path, sf.content, sf.language)
            call_graph.update(xcontract.call_graph_summary(nodes))
            for f in xcontract.findings(nodes):
                findings.append(f)
                memory.remember_finding(
                    title=f.name, text=f.description, domain="blockchain",
                    tech=f.tags, severity=f.severity)
        _dump_json(os.path.join(output_dir, "call_graph.json"), call_graph)
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
        # Strategic intuition: recall weakness classes relevant to the target
        # host/profile so the operator (and AI agent) knows what to prioritise.
        profile = [urlparse(target).hostname or target, "web", "api"]
        for recall in memory.strategic_intuition(profile, domain="web", top_k=3):
            log(f"[intuition] {recall.score:.2f} :: {recall.record.title}")
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

    memory.save()
    _write_report(findings, output_dir)
    return findings


async def run_business_logic_chain(
    *,
    target: str,
    path: str,
    params: dict,
    output_dir: str,
    model: str,
    base_url: str,
    concurrency: int,
    rps: float,
    verbose: bool,
) -> List[Finding]:
    """Plan and execute a stateful business-logic test chain against one endpoint.

    Exercises the cognitive planner, the dependency-ordered stateful engine and
    the bounded self-correction loop together. Intended for authorised testing
    of an endpoint you control.
    """
    from .engine import AsyncHttpClient
    from .state_engine import StatefulChainEngine
    from .cognitive import BusinessLogicMutator

    log = _console_logger(verbose)
    os.makedirs(output_dir, exist_ok=True)
    policy = ScanPolicy(max_concurrency=concurrency, requests_per_second=rps)
    model_client = LocalModelClient(ModelConfig(base_url=base_url, model=model), logger=log)
    memory = build_default_memory(os.path.join(output_dir, "memory.json"), logger=log)

    planner = BusinessLogicMutator(logger=log)
    steps = planner.plan(path, params, method="POST")
    engine = StatefulChainEngine(policy, model_client, logger=log)

    async with AsyncHttpClient(policy, log) as client:
        result = await engine.run_chain(target, steps, client,
                                        name="business-logic", memory=memory)
    memory.save()
    _dump_json(os.path.join(output_dir, "chain-steps.json"),
               [s.__dict__ for s in result.steps])
    _write_report(result.findings, output_dir)
    return result.findings


async def run_fuzz(
    *,
    mode: str,
    output_dir: str,
    verbose: bool,
    # web
    target: Optional[str] = None,
    method: str = "GET",
    body: Optional[str] = None,
    payloads_per_param: int = 40,
    concurrency: int = 20,
    rps: float = 25.0,
    allow_remote: bool = False,
    # binary
    binary: Optional[str] = None,
    input_mode: str = "stdin",
    prog_args: Optional[List[str]] = None,
    max_execs: int = 2000,
    seconds: float = 60.0,
    seed_dir: Optional[str] = None,
    # contract
    rpc: Optional[str] = None,
    address: Optional[str] = None,
    signatures: Optional[List[str]] = None,
    abi_path: Optional[str] = None,
    sender: Optional[str] = None,
    max_calls: int = 400,
) -> List[Finding]:
    """Dispatch to the requested fuzzer. Targets stay local unless allow_remote.

    Exercises the mutation subsystem for web parameters, local contracts, or
    local binaries. Intended for assessment of systems you control.
    """
    log = _console_logger(verbose)
    os.makedirs(output_dir, exist_ok=True)
    findings: List[Finding] = []

    if mode == "web":
        from .fuzzing import WebFuzzer, WebFuzzBudget
        if not target:
            raise ValueError("web fuzzing requires --target")
        fuzzer = WebFuzzer(
            ScanPolicy(max_concurrency=concurrency, requests_per_second=rps),
            budget=WebFuzzBudget(payloads_per_param=payloads_per_param),
            allow_remote=allow_remote, logger=log)
        report = await fuzzer.fuzz(target, method=method, body=body)
        findings = report.findings

    elif mode == "binary":
        from .fuzzing import BinaryFuzzer, FuzzBudget
        if not binary:
            raise ValueError("binary fuzzing requires --binary")
        fuzzer = BinaryFuzzer(
            binary, args=prog_args or [], input_mode=input_mode,
            budget=FuzzBudget(max_execs=max_execs, max_seconds=seconds), logger=log)
        report = await fuzzer.run(seed_dir=seed_dir,
                                  crash_dir=os.path.join(output_dir, "crashes"))
        findings = report.findings

    elif mode == "contract":
        from .fuzzing import ContractFuzzer
        if not (rpc and address):
            raise ValueError("contract fuzzing requires --rpc and --address")
        if abi_path:
            with open(abi_path, "r", encoding="utf-8") as fh:
                abi = json.load(fh)
            fns = ContractFuzzer.functions_from_abi(abi)
        elif signatures:
            fns = ContractFuzzer.functions_from_signatures(signatures)
        else:
            raise ValueError("contract fuzzing requires --abi or one or more --sig")
        fuzzer = ContractFuzzer(rpc, address, functions=fns, sender=sender,
                                max_calls=max_calls, allow_remote=allow_remote, logger=log)
        report = await fuzzer.run()
        findings = report.findings
    else:
        raise ValueError(f"Unknown fuzz mode: {mode!r} (web|binary|contract)")

    _write_report(findings, output_dir)
    return findings


async def run_orchestration(
    *,
    assets: List[Any],
    modes: List[str],
    output_dir: str,
    model: str,
    base_url: str,
    concurrency: int,
    rps: float,
    verbose: bool,
    allow_remote: bool = False,
    rpc_url: str = "http://localhost:11434/v1",
    log_sink: Optional[Callable[[str], None]] = None,
) -> List[Finding]:
    """Run selected modes across a list of parsed assets and write advisories.

    ``modes`` may include: ``web_chain`` (stateful business-logic chain over web
    assets), ``abi_fuzz`` (advanced ABI contract fuzzing over contract-address
    assets, local node only), and ``ai_templates`` (feed every anomaly into the
    intelligence pipeline to emit CVSS-scored Nuclei templates + HackerOne
    reports). This is the single loop the CLI and GUI both drive.
    """
    from .assets import Asset, AssetType
    from .cognitive import BusinessLogicMutator
    from .state_engine import StatefulChainEngine
    from .engine import AsyncHttpClient
    from .intelligence import IntelligenceEngine, AnomalyContext

    log = log_sink or _console_logger(verbose)
    os.makedirs(output_dir, exist_ok=True)
    policy = ScanPolicy(max_concurrency=concurrency, requests_per_second=rps)
    model_client = LocalModelClient(ModelConfig(base_url=base_url, model=model), logger=log)
    memory = build_default_memory(os.path.join(output_dir, "memory.json"), logger=log)
    intel = IntelligenceEngine(model_client if "ai_templates" in modes else None, logger=log)
    findings: List[Finding] = []

    web_assets = [a for a in assets if a.type in (
        AssetType.FQDN, AssetType.API_ENDPOINT, AssetType.IPV4, AssetType.IPV6)]
    contract_assets = [a for a in assets if a.type == AssetType.CONTRACT_ADDRESS]

    # -- Web stateful chain --------------------------------------------------
    if "web_chain" in modes and web_assets:
        planner = BusinessLogicMutator(logger=log)
        chain_engine = StatefulChainEngine(policy, model_client, logger=log)
        for asset in web_assets:
            base = asset.value if "://" in asset.value else f"http://{asset.value}"
            try:
                assert_web_scope_local(base, allow_remote)
            except ScopeError as exc:
                log(f"[orchestrate] skip {base}: {exc}")
                continue
            steps = planner.plan("/api/v1/cart/checkout", {"quantity": "1", "item_id": "9"})
            async with AsyncHttpClient(policy, log) as client:
                result = await chain_engine.run_chain(base, steps, client,
                                                      name=f"chain:{asset.value}",
                                                      memory=memory)
            findings.extend(result.findings)

    # -- Advanced ABI contract fuzzing --------------------------------------
    if "abi_fuzz" in modes and contract_assets:
        from .fuzzing.contract_fuzzer import ContractFuzzer
        for asset in contract_assets:
            try:
                fns = ContractFuzzer.functions_from_signatures(
                    ["setRate(uint256)", "prop_solvency()"])
                fuzzer = ContractFuzzer(rpc_url, asset.value, functions=fns,
                                        max_calls=50, allow_remote=allow_remote, logger=log)
                report = await fuzzer.run()
                findings.extend(report.findings)
            except ScopeError as exc:
                log(f"[orchestrate] contract fuzz skipped: {exc}")
            except Exception as exc:  # noqa: BLE001 - one asset must not kill the run
                log(f"[orchestrate] contract fuzz error on {asset.value}: {exc}")

    # -- AI template / advisory generation loop ------------------------------
    if "ai_templates" in modes and findings:
        for finding in findings:
            ctx = AnomalyContext.from_finding(finding)
            advisory = await intel.analyze(ctx)
            intel.write_advisory(advisory, output_dir)

    memory.save()
    _write_report(findings, output_dir)
    log(f"[orchestrate] complete: {len(findings)} finding(s) across "
        f"{len(assets)} asset(s)")
    return findings


def assert_web_scope_local(url: str, allow_remote: bool) -> str:
    """Thin wrapper reusing the fuzzing scope guard for orchestration."""
    from .fuzzing.guards import assert_web_scope
    return assert_web_scope(url, allow_remote=allow_remote)


def run_intel_query(query: str, output_dir: str, domain: Optional[str],
                    top_k: int) -> None:
    """Print the memory's strategic recall for a query (case-based reasoning)."""
    memory = build_default_memory(os.path.join(output_dir, "memory.json"))
    recalls = memory.query(query, top_k=top_k, domain=domain)
    print(f"\n=== strategic recall for: {query!r} ===")
    if not recalls:
        print("No relevant cases.")
        return
    for r in recalls:
        print(f"  [{r.score:.2f}] ({r.record.domain}/{r.record.severity}) "
              f"{r.record.title}")
        if r.record.strategy:
            print(f"          strategy: {r.record.strategy}")


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

    @cli.command("chain")
    @click.option("--target", required=True, help="Base URL of the endpoint under test.")
    @click.option("--path", default="/api/v1/cart/checkout", show_default=True,
                  help="Endpoint path to probe for business-logic flaws.")
    @click.option("--param", "params", multiple=True, metavar="KEY=VALUE",
                  help="Baseline business parameter (repeatable), e.g. --param quantity=1.")
    @click.option("--model", default="deepseek-coder", show_default=True)
    @click.option("--base-url", default="http://localhost:11434/v1", show_default=True)
    @click.option("--output", "output_dir", default="./sternuke-out", show_default=True)
    @click.option("--concurrency", default=10, show_default=True)
    @click.option("--rps", default=15.0, show_default=True)
    @click.option("-v", "--verbose", is_flag=True, default=False)
    def chain_cmd(target, path, params, model, base_url, output_dir,
                  concurrency, rps, verbose):
        """Run a stateful business-logic test chain against one endpoint."""
        parsed = dict(p.split("=", 1) for p in params if "=" in p) or {"quantity": "1"}
        findings = asyncio.run(run_business_logic_chain(
            target=target, path=path, params=parsed, output_dir=output_dir,
            model=model, base_url=base_url, concurrency=concurrency, rps=rps,
            verbose=verbose,
        ))
        print_summary(findings)

    @cli.command("intel")
    @click.argument("query")
    @click.option("--domain", type=click.Choice(["web", "blockchain"]), default=None)
    @click.option("--output", "output_dir", default="./sternuke-out", show_default=True)
    @click.option("--top-k", default=5, show_default=True)
    def intel_cmd(query, domain, output_dir, top_k):
        """Query local case-based memory for relevant weakness patterns."""
        run_intel_query(query, output_dir, domain, top_k)

    @cli.command("fuzz")
    @click.option("--mode", type=click.Choice(["web", "binary", "contract"]),
                  default="web", show_default=True, help="Fuzzing domain.")
    @click.option("--output", "output_dir", default="./sternuke-out", show_default=True)
    @click.option("-v", "--verbose", is_flag=True, default=False)
    # web
    @click.option("--target", default=None, help="[web] URL with parameters to mutate.")
    @click.option("--method", default="GET", show_default=True, help="[web] HTTP method.")
    @click.option("--body", default=None, help="[web] form body to mutate.")
    @click.option("--payloads-per-param", default=40, show_default=True)
    @click.option("--concurrency", default=20, show_default=True)
    @click.option("--rps", default=25.0, show_default=True)
    @click.option("--allow-remote", is_flag=True, default=False,
                  help="Explicitly permit a non-local target (you accept authz).")
    # binary
    @click.option("--binary", default=None, help="[binary] local executable to fuzz.")
    @click.option("--input-mode", type=click.Choice(["stdin", "file"]), default="stdin")
    @click.option("--arg", "prog_args", multiple=True,
                  help="[binary] target arg; use @@ for the input file (file mode).")
    @click.option("--max-execs", default=2000, show_default=True)
    @click.option("--seconds", default=60.0, show_default=True)
    @click.option("--seed-dir", default=None, help="[binary] directory of seed inputs.")
    # contract
    @click.option("--rpc", default=None, help="[contract] local JSON-RPC endpoint.")
    @click.option("--address", default=None, help="[contract] deployed contract address.")
    @click.option("--sig", "signatures", multiple=True,
                  help="[contract] function signature, e.g. 'withdraw(uint256)'.")
    @click.option("--abi", "abi_path", default=None, help="[contract] JSON ABI file.")
    @click.option("--sender", default=None, help="[contract] sender address.")
    @click.option("--max-calls", default=400, show_default=True)
    def fuzz_cmd(mode, output_dir, verbose, target, method, body, payloads_per_param,
                 concurrency, rps, allow_remote, binary, input_mode, prog_args,
                 max_execs, seconds, seed_dir, rpc, address, signatures, abi_path,
                 sender, max_calls):
        """Run the payload-mutation fuzzer (web | binary | contract)."""
        findings = asyncio.run(run_fuzz(
            mode=mode, output_dir=output_dir, verbose=verbose, target=target,
            method=method, body=body, payloads_per_param=payloads_per_param,
            concurrency=concurrency, rps=rps, allow_remote=allow_remote,
            binary=binary, input_mode=input_mode, prog_args=list(prog_args),
            max_execs=max_execs, seconds=seconds, seed_dir=seed_dir, rpc=rpc,
            address=address, signatures=list(signatures), abi_path=abi_path,
            sender=sender, max_calls=max_calls,
        ))
        print_summary(findings)

    @cli.command("orchestrate")
    @click.option("--scope-file", default=None,
                  help="Path to a .txt/.csv scope file of targets.")
    @click.option("--targets", default=None,
                  help="Inline newline/comma-separated targets (alternative to file).")
    @click.option("--mode", "modes", multiple=True,
                  type=click.Choice(["web_chain", "abi_fuzz", "ai_templates"]),
                  help="Modes to run (repeatable). Default: all.")
    @click.option("--model", default="deepseek-coder", show_default=True)
    @click.option("--base-url", default="http://localhost:11434/v1", show_default=True)
    @click.option("--rpc-url", default="http://127.0.0.1:8545", show_default=True,
                  help="Local node for ABI contract fuzzing.")
    @click.option("--output", "output_dir", default="./sternuke-out", show_default=True)
    @click.option("--concurrency", default=15, show_default=True)
    @click.option("--rps", default=15.0, show_default=True)
    @click.option("--allow-remote", is_flag=True, default=False)
    @click.option("-v", "--verbose", is_flag=True, default=False)
    def orchestrate_cmd(scope_file, targets, modes, model, base_url, rpc_url,
                        output_dir, concurrency, rps, allow_remote, verbose):
        """Ingest a scope file/targets and run selected modes across all assets."""
        from .assets import AssetParser
        parser = AssetParser()
        if scope_file:
            assets = parser.parse_file(scope_file)
        elif targets:
            assets = parser.parse_text(targets.replace(",", "\n"))
        else:
            raise ValueError("provide --scope-file or --targets")
        selected = list(modes) or ["web_chain", "abi_fuzz", "ai_templates"]
        print(f"Parsed {len(assets)} asset(s): {parser.summary(assets)}")
        findings = asyncio.run(run_orchestration(
            assets=assets, modes=selected, output_dir=output_dir, model=model,
            base_url=base_url, rpc_url=rpc_url, concurrency=concurrency, rps=rps,
            verbose=verbose, allow_remote=allow_remote,
        ))
        print_summary(findings)

    @cli.command("gui")
    def gui_cmd():
        """Launch the native desktop interface (requires Tk)."""
        from .gui import launch_gui
        launch_gui()

    @cli.command("serve")
    @click.option("--host", default="127.0.0.1", show_default=True,
                  help="Bind address (loopback by default).")
    @click.option("--port", default=8787, show_default=True)
    @click.option("--model", default="deepseek-coder", show_default=True)
    @click.option("--base-url", default="http://localhost:11434/v1", show_default=True)
    @click.option("--output", "output_dir", default="./sternuke-out", show_default=True)
    def serve_cmd(host, port, model, base_url, output_dir):
        """Run the browser dashboard on localhost (http://127.0.0.1:8787)."""
        from .webgui import serve
        serve(host=host, port=port, output_dir=output_dir, model=model, base_url=base_url)

    def main(argv: Optional[List[str]] = None) -> int:
        try:
            cli.main(args=argv, standalone_mode=False)
            return 0
        except _CLEAN_ERRORS as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

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

        chain = sub.add_parser("chain", help="Run a stateful business-logic chain.")
        chain.add_argument("--target", required=True)
        chain.add_argument("--path", default="/api/v1/cart/checkout")
        chain.add_argument("--param", dest="params", action="append", default=[],
                           metavar="KEY=VALUE")
        chain.add_argument("--model", default="deepseek-coder")
        chain.add_argument("--base-url", default="http://localhost:11434/v1")
        chain.add_argument("--output", dest="output_dir", default="./sternuke-out")
        chain.add_argument("--concurrency", type=int, default=10)
        chain.add_argument("--rps", type=float, default=15.0)
        chain.add_argument("-v", "--verbose", action="store_true")

        intel = sub.add_parser("intel", help="Query local case-based memory.")
        intel.add_argument("query")
        intel.add_argument("--domain", choices=["web", "blockchain"], default=None)
        intel.add_argument("--output", dest="output_dir", default="./sternuke-out")
        intel.add_argument("--top-k", dest="top_k", type=int, default=5)

        fz = sub.add_parser("fuzz", help="Run the payload-mutation fuzzer.")
        fz.add_argument("--mode", choices=["web", "binary", "contract"], default="web")
        fz.add_argument("--output", dest="output_dir", default="./sternuke-out")
        fz.add_argument("-v", "--verbose", action="store_true")
        fz.add_argument("--target", default=None)
        fz.add_argument("--method", default="GET")
        fz.add_argument("--body", default=None)
        fz.add_argument("--payloads-per-param", dest="payloads_per_param", type=int, default=40)
        fz.add_argument("--concurrency", type=int, default=20)
        fz.add_argument("--rps", type=float, default=25.0)
        fz.add_argument("--allow-remote", dest="allow_remote", action="store_true")
        fz.add_argument("--binary", default=None)
        fz.add_argument("--input-mode", dest="input_mode", choices=["stdin", "file"],
                        default="stdin")
        fz.add_argument("--arg", dest="prog_args", action="append", default=[])
        fz.add_argument("--max-execs", dest="max_execs", type=int, default=2000)
        fz.add_argument("--seconds", type=float, default=60.0)
        fz.add_argument("--seed-dir", dest="seed_dir", default=None)
        fz.add_argument("--rpc", default=None)
        fz.add_argument("--address", default=None)
        fz.add_argument("--sig", dest="signatures", action="append", default=[])
        fz.add_argument("--abi", dest="abi_path", default=None)
        fz.add_argument("--sender", default=None)
        fz.add_argument("--max-calls", dest="max_calls", type=int, default=400)

        orch = sub.add_parser("orchestrate", help="Run modes across a scope file.")
        orch.add_argument("--scope-file", dest="scope_file", default=None)
        orch.add_argument("--targets", default=None)
        orch.add_argument("--mode", dest="modes", action="append", default=[],
                          choices=["web_chain", "abi_fuzz", "ai_templates"])
        orch.add_argument("--model", default="deepseek-coder")
        orch.add_argument("--base-url", dest="base_url", default="http://localhost:11434/v1")
        orch.add_argument("--rpc-url", dest="rpc_url", default="http://127.0.0.1:8545")
        orch.add_argument("--output", dest="output_dir", default="./sternuke-out")
        orch.add_argument("--concurrency", type=int, default=15)
        orch.add_argument("--rps", type=float, default=15.0)
        orch.add_argument("--allow-remote", dest="allow_remote", action="store_true")
        orch.add_argument("-v", "--verbose", action="store_true")

        srv = sub.add_parser("serve", help="Run the browser dashboard on localhost.")
        srv.add_argument("--host", default="127.0.0.1")
        srv.add_argument("--port", type=int, default=8787)
        srv.add_argument("--model", default="deepseek-coder")
        srv.add_argument("--base-url", dest="base_url", default="http://localhost:11434/v1")
        srv.add_argument("--output", dest="output_dir", default="./sternuke-out")

        sub.add_parser("gui", help="Launch the native desktop interface.")
        return parser

    def main(argv: Optional[List[str]] = None) -> int:
        parser = _build_parser()
        args = parser.parse_args(argv)
        if args.command == "gui":
            from .gui import launch_gui
            launch_gui()
            return 0
        if args.command == "serve":
            from .webgui import serve
            serve(host=args.host, port=args.port, output_dir=args.output_dir,
                  model=args.model, base_url=args.base_url)
            return 0
        if args.command == "intel":
            run_intel_query(args.query, args.output_dir, args.domain, args.top_k)
            return 0
        if args.command == "orchestrate":
            from .assets import AssetParser
            parser_a = AssetParser()
            if args.scope_file:
                assets = parser_a.parse_file(args.scope_file)
            elif args.targets:
                assets = parser_a.parse_text(args.targets.replace(",", "\n"))
            else:
                raise ValueError("provide --scope-file or --targets")
            selected = args.modes or ["web_chain", "abi_fuzz", "ai_templates"]
            print(f"Parsed {len(assets)} asset(s): {parser_a.summary(assets)}")
            findings = asyncio.run(run_orchestration(
                assets=assets, modes=selected, output_dir=args.output_dir,
                model=args.model, base_url=args.base_url, rpc_url=args.rpc_url,
                concurrency=args.concurrency, rps=args.rps, verbose=args.verbose,
                allow_remote=args.allow_remote,
            ))
            print_summary(findings)
            return 0
        if args.command == "fuzz":
            findings = asyncio.run(run_fuzz(
                mode=args.mode, output_dir=args.output_dir, verbose=args.verbose,
                target=args.target, method=args.method, body=args.body,
                payloads_per_param=args.payloads_per_param, concurrency=args.concurrency,
                rps=args.rps, allow_remote=args.allow_remote, binary=args.binary,
                input_mode=args.input_mode, prog_args=args.prog_args,
                max_execs=args.max_execs, seconds=args.seconds, seed_dir=args.seed_dir,
                rpc=args.rpc, address=args.address, signatures=args.signatures,
                abi_path=args.abi_path, sender=args.sender, max_calls=args.max_calls,
            ))
            print_summary(findings)
            return 0
        if args.command == "chain":
            parsed = dict(p.split("=", 1) for p in args.params if "=" in p) \
                or {"quantity": "1"}
            findings = asyncio.run(run_business_logic_chain(
                target=args.target, path=args.path, params=parsed,
                output_dir=args.output_dir, model=args.model, base_url=args.base_url,
                concurrency=args.concurrency, rps=args.rps, verbose=args.verbose,
            ))
            print_summary(findings)
            return 0
        findings = asyncio.run(run_assessment(
            target=args.target, mode=args.mode, rules_path=args.rules_path,
            output_dir=args.output_dir, use_ai=args.use_ai, model=args.model,
            base_url=args.base_url, concurrency=args.concurrency, rps=args.rps,
            verbose=args.verbose, rule_format=args.rule_format,
        ))
        print_summary(findings)
        return 0

    _orig_main = main

    def main(argv: Optional[List[str]] = None) -> int:  # noqa: F811 - wrap for clean errors
        try:
            return _orig_main(argv)
        except _CLEAN_ERRORS as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
