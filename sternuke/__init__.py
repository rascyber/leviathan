# -*- coding: utf-8 -*-
"""
sternuke
========

A local, AI-assisted vulnerability *assessment* framework.

sternuke is a high-speed, asynchronous scanner and autonomous agent that runs
entirely on infrastructure you control:

* **Web/API assessment** - async request manager with local signature (regex /
  word / status) matching and bounded parameter fuzzing.
* **Blockchain repo assessment** - static structural modelling of Solidity and
  Rust sources (contracts, functions, visibility, access controls) before any
  model sees the code.
* **Autonomous AI agent** - orchestrates a *local* Ollama / vLLM model over the
  standard OpenAI-compatible API to synthesise localized JSON/YAML detection
  rules; degrades to deterministic heuristics when offline.

No commercial APIs, license keys or paid cloud feeds are required or contacted.

This tool is for authorised security assessment only - use it exclusively on
systems and code you own or have explicit written permission to test.
"""

from .engine import (
    AsyncHttpClient, Finding, HttpResponse, Matcher, RepoCrawler, Rule,
    RuleEngine, ScanPolicy, SourceFile, WebScanner,
)
from .ai_agent import (
    AIAgent, ContractBlueprint, FunctionInfo, LocalModelClient, ModelConfig,
    RustAnalyzer, SolidityAnalyzer, StateVariable, WebContextBuilder,
)

__version__ = "1.0.0"

__all__ = [
    "AsyncHttpClient", "Finding", "HttpResponse", "Matcher", "RepoCrawler",
    "Rule", "RuleEngine", "ScanPolicy", "SourceFile", "WebScanner",
    "AIAgent", "ContractBlueprint", "FunctionInfo", "LocalModelClient",
    "ModelConfig", "RustAnalyzer", "SolidityAnalyzer", "StateVariable",
    "WebContextBuilder", "__version__",
]
